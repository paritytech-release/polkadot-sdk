// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! This subsystem is responsible for keeping track of session changes
//! and issuing a connection request to the relevant validators
//! on every new session.
//!
//! In addition to that, it creates a gossip overlay topology
//! which limits the amount of messages sent and received
//! to be an order of sqrt of the validators. Our neighbors
//! in this graph will be forwarded to the network bridge with
//! the `NetworkBridgeRxMessage::NewGossipTopology` message.

use std::{
	collections::{HashMap, HashSet},
	fmt,
	time::{Duration, Instant},
	u32,
};

use futures::{channel::oneshot, select, FutureExt as _};
use futures_timer::Delay;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use sc_network::{config::parse_addr, Multiaddr};
use sp_application_crypto::{AppCrypto, ByteArray};
use sp_keystore::{Keystore, KeystorePtr};

use polkadot_node_network_protocol::{
	authority_discovery::AuthorityDiscovery, peer_set::PeerSet, GossipSupportNetworkMessage,
	PeerId, ValidationProtocols,
};
use polkadot_node_subsystem::{
	messages::{
		ChainApiMessage, GossipSupportMessage, NetworkBridgeEvent, NetworkBridgeRxMessage,
		NetworkBridgeTxMessage, RuntimeApiMessage, RuntimeApiRequest,
	},
	overseer, ActiveLeavesUpdate, FromOrchestra, OverseerSignal, SpawnedSubsystem, SubsystemError,
};
use polkadot_node_subsystem_util as util;
use polkadot_primitives::{AuthorityDiscoveryId, Hash, SessionIndex, SessionInfo, ValidatorIndex};

#[cfg(test)]
mod tests;

mod metrics;

use metrics::Metrics;

const LOG_TARGET: &str = "parachain::gossip-support";
// How much time should we wait to reissue a connection request
// since the last authority discovery resolution failure.
#[cfg(not(test))]
const BACKOFF_DURATION: Duration = Duration::from_secs(5);

#[cfg(test)]
const BACKOFF_DURATION: Duration = Duration::from_millis(500);

// The authorithy_discovery queries runs every ten minutes,
// so it make sense to run a bit more often than that to
// detect changes as often as we can, but not too often since
// it won't help.
#[cfg(not(test))]
const TRY_RERESOLVE_AUTHORITIES: Duration = Duration::from_secs(5 * 60);

#[cfg(test)]
const TRY_RERESOLVE_AUTHORITIES: Duration = Duration::from_secs(2);

/// Duration after which we consider low connectivity a problem.
///
/// Especially at startup low connectivity is expected (authority discovery cache needs to be
/// populated). Authority discovery on Kusama takes around 8 minutes, so warning after 10 minutes
/// should be fine:
///
/// https://github.com/paritytech/substrate/blob/fc49802f263529160635471c8a17888846035f5d/client/authority-discovery/src/lib.rs#L88
const LOW_CONNECTIVITY_WARN_DELAY: Duration = Duration::from_secs(600);

/// If connectivity is lower than this in percent, issue warning in logs.
const LOW_CONNECTIVITY_WARN_THRESHOLD: usize = 85;

/// The Gossip Support subsystem.
pub struct GossipSupport<AD> {
	keystore: KeystorePtr,

	last_session_index: Option<SessionIndex>,
	/// Whether we are currently an authority or not.
	is_authority_now: bool,
	/// The minimum known session we build the topology for.
	min_known_session: SessionIndex,
	// Some(timestamp) if we failed to resolve
	// at least a third of authorities the last time.
	// `None` otherwise.
	last_failure: Option<Instant>,

	// Validators can restart during a session, so if they change
	// their PeerID, we will connect to them in the best case after
	// a session, so we need to try more often to resolved peers and
	// reconnect to them. The authorithy_discovery queries runs every ten
	// minutes, so we can't detect changes in the address more often
	// that that.
	last_connection_request: Option<Instant>,

	/// First time we did not reach our connectivity threshold.
	///
	/// This is the time of the first failed attempt to connect to >2/3 of all validators in a
	/// potential sequence of failed attempts. It will be cleared once we reached >2/3
	/// connectivity.
	failure_start: Option<Instant>,

	/// Successfully resolved connections
	///
	/// waiting for actual connection.
	resolved_authorities: HashMap<AuthorityDiscoveryId, HashSet<Multiaddr>>,

	/// Actually connected authorities.
	connected_authorities: HashMap<AuthorityDiscoveryId, PeerId>,
	/// By `PeerId`.
	///
	/// Needed for efficient handling of disconnect events.
	connected_peers: HashMap<PeerId, HashSet<AuthorityDiscoveryId>>,
	/// Authority discovery service.
	authority_discovery: AD,

	/// The oldest session we need to build a topology for because
	/// the finalized blocks are from a session we haven't built a topology for.
	finalized_needed_session: Option<u32>,
	/// Subsystem metrics.
	metrics: Metrics,
}

#[overseer::contextbounds(GossipSupport, prefix = self::overseer)]
impl<AD> GossipSupport<AD>
where
	AD: AuthorityDiscovery,
{
	/// Create a new instance of the [`GossipSupport`] subsystem.
	pub fn new(keystore: KeystorePtr, authority_discovery: AD, metrics: Metrics) -> Self {
		// Initialize metrics to `0`.
		metrics.on_is_not_authority();
		metrics.on_is_not_parachain_validator();

		Self {
			keystore,
			last_session_index: None,
			last_failure: None,
			last_connection_request: None,
			failure_start: None,
			resolved_authorities: HashMap::new(),
			connected_authorities: HashMap::new(),
			connected_peers: HashMap::new(),
			min_known_session: u32::MAX,
			authority_discovery,
			finalized_needed_session: None,
			is_authority_now: false,
			metrics,
		}
	}

	async fn run<Context>(mut self, mut ctx: Context) -> Self {
		fn get_connectivity_check_delay() -> Delay {
			Delay::new(LOW_CONNECTIVITY_WARN_DELAY)
		}
		let mut next_connectivity_check = get_connectivity_check_delay().fuse();
		loop {
			let message = select!(
				_ = next_connectivity_check => {
					self.check_connectivity();
					next_connectivity_check = get_connectivity_check_delay().fuse();
					continue
				}
				result = ctx.recv().fuse() =>
					match result {
						Ok(message) => message,
						Err(e) => {
							gum::debug!(
								target: LOG_TARGET,
								err = ?e,
								"Failed to receive a message from Overseer, exiting",
							);
							return self
						},
					}
			);
			match message {
				FromOrchestra::Communication {
					msg: GossipSupportMessage::NetworkBridgeUpdate(ev),
				} => self.handle_connect_disconnect(ev),
				FromOrchestra::Signal(OverseerSignal::ActiveLeaves(ActiveLeavesUpdate {
					activated,
					..
				})) => {
					gum::trace!(target: LOG_TARGET, "active leaves signal");

					let leaves = activated.into_iter().map(|a| a.hash);
					if let Err(e) = self.handle_active_leaves(ctx.sender(), leaves).await {
						gum::debug!(target: LOG_TARGET, error = ?e);
					}
				},
				FromOrchestra::Signal(OverseerSignal::BlockFinalized(_hash, _number)) =>
					if let Some(session_index) = self.last_session_index {
						if let Err(e) = self
							.build_topology_for_last_finalized_if_needed(
								ctx.sender(),
								session_index,
							)
							.await
						{
							gum::warn!(
								target: LOG_TARGET,
								"Failed to build topology for last finalized session: {:?}",
								e
							);
						}
					},
				FromOrchestra::Signal(OverseerSignal::Conclude) => return self,
			}
		}
	}

	/// 1. Determine if the current session index has changed.
	/// 2. If it has, determine relevant validators and issue a connection request.
	async fn handle_active_leaves(
		&mut self,
		sender: &mut impl overseer::GossipSupportSenderTrait,
		leaves: impl Iterator<Item = Hash>,
	) -> Result<(), util::Error> {
		for leaf in leaves {
			let current_index = util::request_session_index_for_child(leaf, sender).await.await??;
			let since_failure = self.last_failure.map(|i| i.elapsed()).unwrap_or_default();
			let since_last_reconnect =
				self.last_connection_request.map(|i| i.elapsed()).unwrap_or_default();

			let force_request = since_failure >= BACKOFF_DURATION;
			let re_resolve_authorities = since_last_reconnect >= TRY_RERESOLVE_AUTHORITIES;
			let leaf_session = Some((current_index, leaf));
			let maybe_new_session = match self.last_session_index {
				Some(i) if current_index <= i => None,
				_ => leaf_session,
			};

			let maybe_issue_connection = if force_request || re_resolve_authorities {
				leaf_session
			} else {
				maybe_new_session
			};

			if let Some((session_index, relay_parent)) = maybe_issue_connection {
				let session_info =
					util::request_session_info(leaf, session_index, sender).await.await??;

				let session_info = match session_info {
					Some(s) => s,
					None => {
						gum::warn!(
							relay_parent = ?leaf,
							session_index = self.last_session_index,
							"Failed to get session info.",
						);

						continue
					},
				};

				// Note: we only update `last_session_index` once we've
				// successfully gotten the `SessionInfo`.
				let is_new_session = maybe_new_session.is_some();
				if is_new_session {
					gum::debug!(
						target: LOG_TARGET,
						%session_index,
						"New session detected",
					);
					self.last_session_index = Some(session_index);
					self.is_authority_now =
						ensure_i_am_an_authority(&self.keystore, &session_info.discovery_keys)
							.is_ok();
				}

				// Connect to authorities from the past/present/future.
				//
				// This is maybe not the right place for this logic to live,
				// but at the moment we're limited by the network bridge's ability
				// to handle connection requests (it only allows one, globally).
				//
				// Certain network protocols - mostly req/res, but some gossip,
				// will require being connected to past/future validators as well
				// as current. That is, the old authority sets are not made obsolete
				// by virtue of a new session being entered. Therefore we maintain
				// connections to a much broader set of validators.
				{
					let mut connections = authorities_past_present_future(sender, leaf).await?;
					self.last_connection_request = Some(Instant::now());
					// Remove all of our locally controlled validator indices so we don't connect to
					// ourself.
					let connections =
						if remove_all_controlled(&self.keystore, &mut connections) != 0 {
							connections
						} else {
							// If we control none of them, issue an empty connection request
							// to clean up all connections.
							Vec::new()
						};

					if force_request || is_new_session {
						self.issue_connection_request(sender, connections).await;
					} else if re_resolve_authorities {
						self.issue_connection_request_to_changed(sender, connections).await;
					}
				}

				if is_new_session {
					if let Err(err) = self
						.build_topology_for_last_finalized_if_needed(sender, session_index)
						.await
					{
						gum::warn!(
							target: LOG_TARGET,
							"Failed to build topology for last finalized session: {:?}",
							err
						);
					}

					// Gossip topology is only relevant for authorities in the current session.
					let our_index = self.get_key_index_and_update_metrics(&session_info)?;
					update_gossip_topology(
						sender,
						our_index,
						session_info.discovery_keys.clone(),
						relay_parent,
						session_index,
					)
					.await?;
				}
				// authority_discovery is just a cache so let's try every time we try to re-connect
				// if new authorities are present.
				self.update_authority_ids(sender, session_info.discovery_keys).await;
			}
		}
		Ok(())
	}

	/// Build the gossip topology for the session of the last finalized block if we haven't built
	/// one.
	///
	/// This is needed to ensure that if finality is lagging accross session boundary and a restart
	/// happens after the new session started, we built a topology from the session we haven't
	/// finalized the blocks yet.
	/// Once finalized blocks start to be from a session we've built a topology for, we can stop.
	async fn build_topology_for_last_finalized_if_needed(
		&mut self,
		sender: &mut impl overseer::GossipSupportSenderTrait,
		current_session_index: u32,
	) -> Result<(), util::Error> {
		self.min_known_session = self.min_known_session.min(current_session_index);

		if self
			.finalized_needed_session
			.map(|oldest_needed_session| oldest_needed_session < self.min_known_session)
			.unwrap_or(true)
		{
			let (tx, rx) = oneshot::channel();
			sender.send_message(ChainApiMessage::FinalizedBlockNumber(tx)).await;
			let finalized_block_number = match rx.await? {
				Ok(block_number) => block_number,
				_ => return Ok(()),
			};

			let (tx, rx) = oneshot::channel();
			sender
				.send_message(ChainApiMessage::FinalizedBlockHash(finalized_block_number, tx))
				.await;

			let finalized_block_hash = match rx.await? {
				Ok(Some(block_hash)) => block_hash,
				_ => return Ok(()),
			};

			let finalized_session_index =
				util::request_session_index_for_child(finalized_block_hash, sender)
					.await
					.await??;

			if finalized_session_index < self.min_known_session &&
				Some(finalized_session_index) != self.finalized_needed_session
			{
				gum::debug!(
					target: LOG_TARGET,
					?finalized_block_hash,
					?finalized_block_number,
					?finalized_session_index,
					"Building topology for finalized block session",
				);

				let finalized_session_info = match util::request_session_info(
					finalized_block_hash,
					finalized_session_index,
					sender,
				)
				.await
				.await??
				{
					Some(session_info) => session_info,
					_ => return Ok(()),
				};

				let our_index = self.get_key_index_and_update_metrics(&finalized_session_info)?;
				update_gossip_topology(
					sender,
					our_index,
					finalized_session_info.discovery_keys.clone(),
					finalized_block_hash,
					finalized_session_index,
				)
				.await?;
			}
			self.finalized_needed_session = Some(finalized_session_index);
		}
		Ok(())
	}

	// Checks if the node is an authority and also updates `polkadot_node_is_authority` and
	// `polkadot_node_is_parachain_validator` metrics accordingly.
	// On success, returns the index of our keys in `session_info.discovery_keys`.
	fn get_key_index_and_update_metrics(
		&mut self,
		session_info: &SessionInfo,
	) -> Result<usize, util::Error> {
		let authority_check_result =
			ensure_i_am_an_authority(&self.keystore, &session_info.discovery_keys);

		match authority_check_result.as_ref() {
			Ok(index) => {
				gum::trace!(target: LOG_TARGET, "We are now an authority",);
				self.metrics.on_is_authority();

				// The subset of authorities participating in parachain consensus.
				let parachain_validators_this_session = session_info.validators.len();

				// First `maxValidators` entries are the parachain validators. We'll check
				// if our index is in this set to avoid searching for the keys.
				// https://github.com/paritytech/polkadot/blob/a52dca2be7840b23c19c153cf7e110b1e3e475f8/runtime/parachains/src/configuration.rs#L148
				if *index < parachain_validators_this_session {
					gum::trace!(target: LOG_TARGET, "We are now a parachain validator",);
					self.metrics.on_is_parachain_validator();
				} else {
					gum::trace!(target: LOG_TARGET, "We are no longer a parachain validator",);
					self.metrics.on_is_not_parachain_validator();
				}
			},
			Err(util::Error::NotAValidator) => {
				gum::trace!(target: LOG_TARGET, "We are no longer an authority",);
				self.metrics.on_is_not_authority();
				self.metrics.on_is_not_parachain_validator();
			},
			// Don't update on runtime errors.
			Err(_) => {},
		};

		authority_check_result
	}

	async fn resolve_authorities(
		&mut self,
		authorities: Vec<AuthorityDiscoveryId>,
	) -> (Vec<HashSet<Multiaddr>>, HashMap<AuthorityDiscoveryId, HashSet<Multiaddr>>, usize) {
		let mut validator_addrs = Vec::with_capacity(authorities.len());
		let mut resolved = HashMap::with_capacity(authorities.len());
		let mut failures = 0;

		for authority in authorities {
			if let Some(addrs) =
				self.authority_discovery.get_addresses_by_authority_id(authority.clone()).await
			{
				validator_addrs.push(addrs.clone());
				resolved.insert(authority, addrs);
			} else {
				failures += 1;
				gum::debug!(
					target: LOG_TARGET,
					"Couldn't resolve addresses of authority: {:?}",
					authority
				);
			}
		}
		(validator_addrs, resolved, failures)
	}

	async fn issue_connection_request_to_changed<Sender>(
		&mut self,
		sender: &mut Sender,
		authorities: Vec<AuthorityDiscoveryId>,
	) where
		Sender: overseer::GossipSupportSenderTrait,
	{
		let (_, resolved, _) = self.resolve_authorities(authorities).await;

		let mut changed = Vec::new();

		for (authority, new_addresses) in &resolved {
			let new_peer_ids = new_addresses
				.iter()
				.flat_map(|addr| parse_addr(addr.clone()).ok().map(|(p, _)| p))
				.collect::<HashSet<_>>();
			match self.resolved_authorities.get(authority) {
				Some(old_addresses) => {
					let old_peer_ids = old_addresses
						.iter()
						.flat_map(|addr| parse_addr(addr.clone()).ok().map(|(p, _)| p))
						.collect::<HashSet<_>>();
					if !old_peer_ids.is_superset(&new_peer_ids) {
						changed.push(new_addresses.clone());
					}
				},
				None => changed.push(new_addresses.clone()),
			}
		}
		gum::debug!(
			target: LOG_TARGET,
			num_changed = ?changed.len(),
			?changed,
			"Issuing a connection request to changed validators"
		);
		if !changed.is_empty() {
			self.resolved_authorities = resolved;

			sender
				.send_message(NetworkBridgeTxMessage::AddToResolvedValidators {
					validator_addrs: changed,
					peer_set: PeerSet::Validation,
				})
				.await;
		}
	}

	async fn issue_connection_request<Sender>(
		&mut self,
		sender: &mut Sender,
		authorities: Vec<AuthorityDiscoveryId>,
	) where
		Sender: overseer::GossipSupportSenderTrait,
	{
		let num = authorities.len();

		let (validator_addrs, resolved, failures) = self.resolve_authorities(authorities).await;

		self.resolved_authorities = resolved;
		gum::debug!(target: LOG_TARGET, %num, "Issuing a connection request");

		sender
			.send_message(NetworkBridgeTxMessage::ConnectToResolvedValidators {
				validator_addrs,
				peer_set: PeerSet::Validation,
			})
			.await;

		// issue another request for the same session
		// if at least a third of the authorities were not resolved.
		if num != 0 && 3 * failures >= num {
			let timestamp = Instant::now();
			match self.failure_start {
				None => self.failure_start = Some(timestamp),
				Some(first) if first.elapsed() >= LOW_CONNECTIVITY_WARN_DELAY => {
					gum::warn!(
						target: LOG_TARGET,
						connected = ?(num - failures),
						target = ?num,
						"Low connectivity - authority lookup failed for too many validators."
					);
				},
				Some(_) => {
					gum::debug!(
						target: LOG_TARGET,
						connected = ?(num - failures),
						target = ?num,
						"Low connectivity (due to authority lookup failures) - expected on startup."
					);
				},
			}
			self.last_failure = Some(timestamp);
		} else {
			self.last_failure = None;
			self.failure_start = None;
		};
	}

	async fn update_authority_ids<Sender>(
		&mut self,
		sender: &mut Sender,
		authorities: Vec<AuthorityDiscoveryId>,
	) where
		Sender: overseer::GossipSupportSenderTrait,
	{
		let mut authority_ids: HashMap<PeerId, HashSet<AuthorityDiscoveryId>> = HashMap::new();
		for authority in authorities {
			let peer_ids = self
				.authority_discovery
				.get_addresses_by_authority_id(authority.clone())
				.await
				.into_iter()
				.flat_map(|list| list.into_iter())
				.flat_map(|addr| parse_addr(addr).ok().map(|(p, _)| p))
				.collect::<HashSet<_>>();

			gum::trace!(
				target: LOG_TARGET,
				?peer_ids,
				?authority,
				"Resolved to peer ids"
			);

			for p in peer_ids {
				authority_ids.entry(p).or_default().insert(authority.clone());
			}
		}

		// peer was authority and now isn't
		for (peer_id, current) in self.connected_peers.iter_mut() {
			// empty -> nonempty is handled in the next loop
			if !current.is_empty() && !authority_ids.contains_key(peer_id) {
				sender
					.send_message(NetworkBridgeRxMessage::UpdatedAuthorityIds {
						peer_id: *peer_id,
						authority_ids: HashSet::new(),
					})
					.await;

				for a in current.drain() {
					self.connected_authorities.remove(&a);
				}
			}
		}

		// peer has new authority set.
		for (peer_id, new) in authority_ids {
			// If the peer is connected _and_ the authority IDs have changed.
			if let Some(prev) = self.connected_peers.get(&peer_id).filter(|x| x != &&new) {
				sender
					.send_message(NetworkBridgeRxMessage::UpdatedAuthorityIds {
						peer_id,
						authority_ids: new.clone(),
					})
					.await;

				prev.iter().for_each(|a| {
					self.connected_authorities.remove(a);
				});
				new.iter().for_each(|a| {
					self.connected_authorities.insert(a.clone(), peer_id);
				});

				self.connected_peers.insert(peer_id, new);
			}
		}
	}

	fn handle_connect_disconnect(&mut self, ev: NetworkBridgeEvent<GossipSupportNetworkMessage>) {
		match ev {
			NetworkBridgeEvent::PeerConnected(peer_id, _, _, o_authority) => {
				if let Some(authority_ids) = o_authority {
					authority_ids.iter().for_each(|a| {
						self.connected_authorities.insert(a.clone(), peer_id);
					});
					self.connected_peers.insert(peer_id, authority_ids);
				} else {
					self.connected_peers.insert(peer_id, HashSet::new());
				}
			},
			NetworkBridgeEvent::PeerDisconnected(peer_id) => {
				if let Some(authority_ids) = self.connected_peers.remove(&peer_id) {
					authority_ids.into_iter().for_each(|a| {
						self.connected_authorities.remove(&a);
					});
				}
			},
			NetworkBridgeEvent::UpdatedAuthorityIds(_, _) => {
				// The `gossip-support` subsystem itself issues these messages.
			},
			NetworkBridgeEvent::OurViewChange(_) => {},
			NetworkBridgeEvent::PeerViewChange(_, _) => {},
			NetworkBridgeEvent::NewGossipTopology { .. } => {},
			NetworkBridgeEvent::PeerMessage(_, message) => {
				// match void -> LLVM unreachable
				match message {
					ValidationProtocols::V3(m) => match m {},
				}
			},
		}
	}

	/// Check connectivity and report on it in logs.
	fn check_connectivity(&mut self) {
		let absolute_connected = self.connected_authorities.len();
		let absolute_resolved = self.resolved_authorities.len();
		let connected_ratio =
			(100 * absolute_connected).checked_div(absolute_resolved).unwrap_or(100);
		let unconnected_authorities = self
			.resolved_authorities
			.iter()
			.filter(|(a, _)| !self.connected_authorities.contains_key(a));
		if connected_ratio <= LOW_CONNECTIVITY_WARN_THRESHOLD && self.is_authority_now {
			gum::error!(
				target: LOG_TARGET,
				session_index = self.last_session_index.as_ref().map(|s| *s).unwrap_or_default(),
				"Connectivity seems low, we are only connected to {connected_ratio}% of available validators (see debug logs for details), if this persists more than a session action needs to be taken"
			);
		}
		let pretty = PrettyAuthorities(unconnected_authorities);
		gum::debug!(
			target: LOG_TARGET,
			?connected_ratio,
			?absolute_connected,
			?absolute_resolved,
			unconnected_authorities = %pretty,
			"Connectivity Report"
		);
	}
}

// Get the authorities of the past, present, and future.
async fn authorities_past_present_future(
	sender: &mut impl overseer::GossipSupportSenderTrait,
	relay_parent: Hash,
) -> Result<Vec<AuthorityDiscoveryId>, util::Error> {
	let authorities = util::request_authorities(relay_parent, sender).await.await??;
	gum::debug!(
		target: LOG_TARGET,
		authority_count = ?authorities.len(),
		"Determined past/present/future authorities",
	);
	Ok(authorities)
}

/// Return an error if we're not a validator in the given set (do not have keys).
/// Otherwise, returns the index of our keys in `authorities`.
fn ensure_i_am_an_authority(
	keystore: &KeystorePtr,
	authorities: &[AuthorityDiscoveryId],
) -> Result<usize, util::Error> {
	for (i, v) in authorities.iter().enumerate() {
		if Keystore::has_keys(&**keystore, &[(v.to_raw_vec(), AuthorityDiscoveryId::ID)]) {
			return Ok(i)
		}
	}
	Err(util::Error::NotAValidator)
}

/// Filter out all controlled keys in the given set. Returns the number of keys removed.
fn remove_all_controlled(
	keystore: &KeystorePtr,
	authorities: &mut Vec<AuthorityDiscoveryId>,
) -> usize {
	let mut to_remove = Vec::new();
	for (i, v) in authorities.iter().enumerate() {
		if Keystore::has_keys(&**keystore, &[(v.to_raw_vec(), AuthorityDiscoveryId::ID)]) {
			to_remove.push(i);
		}
	}

	for i in to_remove.iter().rev().copied() {
		authorities.remove(i);
	}

	to_remove.len()
}

/// We partition the list of all sorted `authorities` into `sqrt(len)` groups of `sqrt(len)` size
/// and form a matrix where each validator is connected to all validators in its row and column.
/// This is similar to `[web3]` research proposed topology, except for the groups are not parachain
/// groups (because not all validators are parachain validators and the group size is small),
/// but formed randomly via BABE randomness from two epochs ago.
/// This limits the amount of gossip peers to 2 * `sqrt(len)` and ensures the diameter of 2.
///
/// [web3]: https://research.web3.foundation/en/latest/polkadot/networking/3-avail-valid.html#topology
async fn update_gossip_topology(
	sender: &mut impl overseer::GossipSupportSenderTrait,
	our_index: usize,
	authorities: Vec<AuthorityDiscoveryId>,
	relay_parent: Hash,
	session_index: SessionIndex,
) -> Result<(), util::Error> {
	// retrieve BABE randomness
	let random_seed = {
		let (tx, rx) = oneshot::channel();

		// TODO https://github.com/paritytech/polkadot/issues/5316:
		// get the random seed from the `SessionInfo` instead.
		sender
			.send_message(RuntimeApiMessage::Request(
				relay_parent,
				RuntimeApiRequest::CurrentBabeEpoch(tx),
			))
			.await;

		let randomness = rx.await??.randomness;
		let mut subject = [0u8; 40];
		subject[..8].copy_from_slice(b"gossipsu");
		subject[8..].copy_from_slice(&randomness);
		sp_crypto_hashing::blake2_256(&subject)
	};

	// shuffle the validators and create the index mapping
	let (shuffled_indices, canonical_shuffling) = {
		let mut rng: ChaCha20Rng = SeedableRng::from_seed(random_seed);
		let len = authorities.len();
		let mut shuffled_indices = vec![0; len];
		let mut canonical_shuffling: Vec<_> = authorities
			.iter()
			.enumerate()
			.map(|(i, a)| (a.clone(), ValidatorIndex(i as _)))
			.collect();

		fisher_yates_shuffle(&mut rng, &mut canonical_shuffling[..]);
		for (i, (_, validator_index)) in canonical_shuffling.iter().enumerate() {
			shuffled_indices[validator_index.0 as usize] = i;
		}

		(shuffled_indices, canonical_shuffling)
	};

	sender
		.send_message(NetworkBridgeRxMessage::NewGossipTopology {
			session: session_index,
			local_index: Some(ValidatorIndex(our_index as _)),
			canonical_shuffling,
			shuffled_indices,
		})
		.await;

	Ok(())
}

// Durstenfeld algorithm for the Fisher-Yates shuffle
// https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm
fn fisher_yates_shuffle<T, R: Rng + ?Sized>(rng: &mut R, items: &mut [T]) {
	for i in (1..items.len()).rev() {
		// invariant: elements with index > i have been locked in place.
		let index = rng.gen_range(0u32..(i as u32 + 1));
		items.swap(i, index as usize);
	}
}

#[overseer::subsystem(GossipSupport, error = SubsystemError, prefix = self::overseer)]
impl<Context, AD> GossipSupport<AD>
where
	AD: AuthorityDiscovery + Clone,
{
	fn start(self, ctx: Context) -> SpawnedSubsystem {
		let future = self.run(ctx).map(|_| Ok(())).boxed();

		SpawnedSubsystem { name: "gossip-support-subsystem", future }
	}
}

/// Helper struct to get a nice rendering of unreachable authorities.
struct PrettyAuthorities<I>(I);

impl<'a, I> fmt::Display for PrettyAuthorities<I>
where
	I: Iterator<Item = (&'a AuthorityDiscoveryId, &'a HashSet<Multiaddr>)> + Clone,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut authorities = self.0.clone().peekable();
		if authorities.peek().is_none() {
			write!(f, "None")?;
		} else {
			write!(f, "\n")?;
		}
		for (authority, addrs) in authorities {
			write!(f, "{}:\n", authority)?;
			for addr in addrs {
				write!(f, "  {}\n", addr)?;
			}
			write!(f, "\n")?;
		}
		Ok(())
	}
}
