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

//! The Network Bridge Subsystem - handles _outgoing_ messages, from subsystem to the network.
use super::*;

use polkadot_node_network_protocol::{
	peer_set::PeerSetProtocolNames, request_response::ReqProtocolNames, CollationProtocols,
	ValidationProtocols,
};

use polkadot_node_subsystem::{
	errors::SubsystemError,
	messages::{NetworkBridgeTxMessage, ReportPeerMessage},
	overseer, FromOrchestra, OverseerSignal, SpawnedSubsystem,
};

use polkadot_node_network_protocol::request_response::Requests;
use sc_network::{MessageSink, ReputationChange};

use crate::validator_discovery;

/// Actual interfacing to the network based on the `Network` trait.
///
/// Defines the `Network` trait with an implementation for an `Arc<NetworkService>`.
use crate::network::{
	send_collation_message_v1, send_collation_message_v2, send_validation_message_v3, Network,
};

use crate::metrics::Metrics;

#[cfg(test)]
mod tests;

// network bridge log target
const LOG_TARGET: &'static str = "parachain::network-bridge-tx";

/// The network bridge subsystem.
pub struct NetworkBridgeTx<N, AD> {
	/// `Network` trait implementing type.
	network_service: N,
	authority_discovery_service: AD,
	metrics: Metrics,
	req_protocol_names: ReqProtocolNames,
	peerset_protocol_names: PeerSetProtocolNames,
	notification_sinks: Arc<Mutex<HashMap<(PeerSet, PeerId), Box<dyn MessageSink>>>>,
}

impl<N, AD> NetworkBridgeTx<N, AD> {
	/// Create a new network bridge subsystem with underlying network service and authority
	/// discovery service.
	///
	/// This assumes that the network service has had the notifications protocol for the network
	/// bridge already registered. See [`peer_sets_info`].
	pub fn new(
		network_service: N,
		authority_discovery_service: AD,
		metrics: Metrics,
		req_protocol_names: ReqProtocolNames,
		peerset_protocol_names: PeerSetProtocolNames,
		notification_sinks: Arc<Mutex<HashMap<(PeerSet, PeerId), Box<dyn MessageSink>>>>,
	) -> Self {
		Self {
			network_service,
			authority_discovery_service,
			metrics,
			req_protocol_names,
			peerset_protocol_names,
			notification_sinks,
		}
	}
}

#[overseer::subsystem(NetworkBridgeTx, error = SubsystemError, prefix = self::overseer)]
impl<Net, AD, Context> NetworkBridgeTx<Net, AD>
where
	Net: Network + Sync,
	AD: validator_discovery::AuthorityDiscovery + Clone + Sync,
{
	fn start(self, ctx: Context) -> SpawnedSubsystem {
		let future = run_network_out(self, ctx)
			.map_err(|e| SubsystemError::with_origin("network-bridge", e))
			.boxed();
		SpawnedSubsystem { name: "network-bridge-tx-subsystem", future }
	}
}

#[overseer::contextbounds(NetworkBridgeTx, prefix = self::overseer)]
async fn handle_subsystem_messages<Context, N, AD>(
	mut ctx: Context,
	mut network_service: N,
	mut authority_discovery_service: AD,
	metrics: Metrics,
	req_protocol_names: ReqProtocolNames,
	peerset_protocol_names: PeerSetProtocolNames,
	notification_sinks: Arc<Mutex<HashMap<(PeerSet, PeerId), Box<dyn MessageSink>>>>,
) -> Result<(), Error>
where
	N: Network,
	AD: validator_discovery::AuthorityDiscovery + Clone,
{
	let mut validator_discovery =
		validator_discovery::Service::<N, AD>::new(peerset_protocol_names.clone());

	loop {
		match ctx.recv().fuse().await? {
			FromOrchestra::Signal(OverseerSignal::Conclude) => return Ok(()),
			FromOrchestra::Signal(_) => { /* handled by incoming */ },
			FromOrchestra::Communication { msg } => {
				(network_service, authority_discovery_service) =
					handle_incoming_subsystem_communication(
						&mut ctx,
						network_service,
						&mut validator_discovery,
						authority_discovery_service.clone(),
						msg,
						&metrics,
						&req_protocol_names,
						&peerset_protocol_names,
						&notification_sinks,
					)
					.await;
			},
		}
	}
}

#[overseer::contextbounds(NetworkBridgeTx, prefix = self::overseer)]
async fn handle_incoming_subsystem_communication<Context, N, AD>(
	_ctx: &mut Context,
	network_service: N,
	validator_discovery: &mut validator_discovery::Service<N, AD>,
	mut authority_discovery_service: AD,
	msg: NetworkBridgeTxMessage,
	metrics: &Metrics,
	req_protocol_names: &ReqProtocolNames,
	peerset_protocol_names: &PeerSetProtocolNames,
	notification_sinks: &Arc<Mutex<HashMap<(PeerSet, PeerId), Box<dyn MessageSink>>>>,
) -> (N, AD)
where
	N: Network,
	AD: validator_discovery::AuthorityDiscovery + Clone,
{
	match msg {
		NetworkBridgeTxMessage::ReportPeer(ReportPeerMessage::Single(peer, rep)) => {
			if !rep.value.is_positive() {
				gum::debug!(target: LOG_TARGET, ?peer, ?rep, action = "ReportPeer");
			}

			metrics.on_report_event();
			network_service.report_peer(peer, rep);
		},
		NetworkBridgeTxMessage::ReportPeer(ReportPeerMessage::Batch(batch)) => {
			for (peer, score) in batch {
				let rep = ReputationChange::new(score, "Aggregated reputation change");
				if !rep.value.is_positive() {
					gum::debug!(target: LOG_TARGET, ?peer, ?rep, action = "ReportPeer");
				}

				metrics.on_report_event();
				network_service.report_peer(peer, rep);
			}
		},
		NetworkBridgeTxMessage::DisconnectPeers(peers, peer_set) => {
			gum::trace!(
				target: LOG_TARGET,
				action = "DisconnectPeers",
				?peers,
				peer_set = ?peer_set,
			);

			// [`NetworkService`] keeps track of the protocols by their main name.
			let protocol = peerset_protocol_names.get_main_name(peer_set);
			for peer in peers {
				network_service.disconnect_peer(peer, protocol.clone());
			}
		},
		NetworkBridgeTxMessage::SendValidationMessage(peers, msg) => {
			gum::trace!(
				target: LOG_TARGET,
				action = "SendValidationMessages",
				?msg,
				num_messages = 1usize,
			);

			match msg {
				ValidationProtocols::V3(msg) => send_validation_message_v3(
					peers,
					WireMessage::ProtocolMessage(msg),
					&metrics,
					notification_sinks,
				),
			}
		},
		NetworkBridgeTxMessage::SendValidationMessages(msgs) => {
			gum::trace!(
				target: LOG_TARGET,
				action = "SendValidationMessages",
				num_messages = %msgs.len(),
				?msgs,
			);

			for (peers, msg) in msgs {
				match msg {
					ValidationProtocols::V3(msg) => send_validation_message_v3(
						peers,
						WireMessage::ProtocolMessage(msg),
						&metrics,
						notification_sinks,
					),
				}
			}
		},
		NetworkBridgeTxMessage::SendCollationMessage(peers, msg) => {
			gum::trace!(
				target: LOG_TARGET,
				action = "SendCollationMessages",
				num_messages = 1usize,
			);

			match msg {
				CollationProtocols::V1(msg) => send_collation_message_v1(
					peers,
					WireMessage::ProtocolMessage(msg),
					&metrics,
					notification_sinks,
				),
				CollationProtocols::V2(msg) => send_collation_message_v2(
					peers,
					WireMessage::ProtocolMessage(msg),
					&metrics,
					notification_sinks,
				),
			}
		},
		NetworkBridgeTxMessage::SendCollationMessages(msgs) => {
			gum::trace!(
				target: LOG_TARGET,
				action = "SendCollationMessages",
				num_messages = %msgs.len(),
			);

			for (peers, msg) in msgs {
				match msg {
					CollationProtocols::V1(msg) => send_collation_message_v1(
						peers,
						WireMessage::ProtocolMessage(msg),
						&metrics,
						notification_sinks,
					),
					CollationProtocols::V2(msg) => send_collation_message_v2(
						peers,
						WireMessage::ProtocolMessage(msg),
						&metrics,
						notification_sinks,
					),
				}
			}
		},
		NetworkBridgeTxMessage::SendRequests(reqs, if_disconnected) => {
			gum::trace!(
				target: LOG_TARGET,
				action = "SendRequests",
				num_requests = %reqs.len(),
			);

			for req in reqs {
				match req {
					Requests::ChunkFetching(ref req) => {
						// This is not the actual request that will succeed, as we don't know yet
						// what that will be. It's only the primary request we tried.
						if req.fallback_request.is_some() {
							metrics.on_message("chunk_fetching_v2")
						} else {
							metrics.on_message("chunk_fetching_v1")
						}
					},
					Requests::AvailableDataFetchingV1(_) =>
						metrics.on_message("available_data_fetching_v1"),
					Requests::CollationFetchingV1(_) => metrics.on_message("collation_fetching_v1"),
					Requests::CollationFetchingV2(_) => metrics.on_message("collation_fetching_v2"),
					Requests::PoVFetchingV1(_) => metrics.on_message("pov_fetching_v1"),
					Requests::DisputeSendingV1(_) => metrics.on_message("dispute_sending_v1"),
					Requests::AttestedCandidateV2(_) => metrics.on_message("attested_candidate_v2"),
				}

				network_service
					.start_request(
						&mut authority_discovery_service,
						req,
						req_protocol_names,
						if_disconnected,
					)
					.await;
			}
		},
		NetworkBridgeTxMessage::ConnectToValidators { validator_ids, peer_set, failed } => {
			gum::trace!(
				target: LOG_TARGET,
				action = "ConnectToValidators",
				peer_set = ?peer_set,
				ids = ?validator_ids,
				"Received a validator connection request",
			);

			metrics.note_desired_peer_count(peer_set, validator_ids.len());

			let (network_service, ads) = validator_discovery
				.on_request(
					validator_ids,
					peer_set,
					failed,
					network_service,
					authority_discovery_service,
				)
				.await;

			return (network_service, ads)
		},
		NetworkBridgeTxMessage::ConnectToResolvedValidators { validator_addrs, peer_set } => {
			gum::trace!(
				target: LOG_TARGET,
				action = "ConnectToPeers",
				peer_set = ?peer_set,
				?validator_addrs,
				"Received a resolved validator connection request",
			);

			metrics.note_desired_peer_count(peer_set, validator_addrs.len());

			let all_addrs = validator_addrs.into_iter().flatten().collect();
			let network_service = validator_discovery
				.on_resolved_request(all_addrs, peer_set, network_service)
				.await;
			return (network_service, authority_discovery_service)
		},

		NetworkBridgeTxMessage::AddToResolvedValidators { validator_addrs, peer_set } => {
			gum::trace!(
				target: LOG_TARGET,
				action = "AddToResolvedValidators",
				peer_set = ?peer_set,
				?validator_addrs,
				"Received a resolved validator connection request",
			);

			let all_addrs = validator_addrs.into_iter().flatten().collect();
			let network_service = validator_discovery
				.on_add_to_resolved_request(all_addrs, peer_set, network_service)
				.await;
			return (network_service, authority_discovery_service)
		},
	}
	(network_service, authority_discovery_service)
}

#[overseer::contextbounds(NetworkBridgeTx, prefix = self::overseer)]
async fn run_network_out<N, AD, Context>(
	bridge: NetworkBridgeTx<N, AD>,
	ctx: Context,
) -> Result<(), Error>
where
	N: Network,
	AD: validator_discovery::AuthorityDiscovery + Clone + Sync,
{
	let NetworkBridgeTx {
		network_service,
		authority_discovery_service,
		metrics,
		req_protocol_names,
		peerset_protocol_names,
		notification_sinks,
	} = bridge;

	handle_subsystem_messages(
		ctx,
		network_service,
		authority_discovery_service,
		metrics,
		req_protocol_names,
		peerset_protocol_names,
		notification_sinks,
	)
	.await?;

	Ok(())
}
