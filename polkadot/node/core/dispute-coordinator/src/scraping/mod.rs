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

use std::collections::{btree_map::Entry, BTreeMap, HashSet};

use futures::channel::oneshot;
use schnellru::{ByLength, LruMap};

use polkadot_node_primitives::{DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION, MAX_FINALITY_LAG};
use polkadot_node_subsystem::{
	messages::ChainApiMessage, overseer, ActivatedLeaf, ActiveLeavesUpdate, ChainApiError,
	RuntimeApiError, SubsystemSender,
};
use polkadot_node_subsystem_util::runtime::{
	self, get_candidate_events, get_on_chain_votes, get_unapplied_slashes,
};
use polkadot_primitives::{
	slashing::PendingSlashes,
	vstaging::{CandidateEvent, CandidateReceiptV2 as CandidateReceipt, ScrapedOnChainVotes},
	BlockNumber, CandidateHash, Hash, SessionIndex,
};

use crate::{
	error::{FatalError, FatalResult, Result},
	LOG_TARGET,
};

#[cfg(test)]
mod tests;

mod candidates;

/// Number of hashes to keep in the LRU.
///
///
/// When traversing the ancestry of a block we will stop once we hit a hash that we find in the
/// `last_observed_blocks` LRU. This means, this value should the very least be as large as the
/// number of expected forks for keeping chain scraping efficient. Making the LRU much larger than
/// that has very limited use.
/// In cases of high load when finality lags, forks could appear anywhere from the last finalized
/// block to best, hence this number needs to be large enough to hold all the hashes from best to
/// finalized.
const LRU_OBSERVED_BLOCKS_CAPACITY: u32 = 2 * MAX_FINALITY_LAG;

/// `ScrapedUpdates`
///
/// Updates to `on_chain_votes` and included receipts for new active leaf and its unprocessed
/// ancestors.
///
/// `on_chain_votes`: New votes as seen on chain
/// `included_receipts`: Newly included parachain block candidate receipts as seen on chain
pub struct ScrapedUpdates {
	pub on_chain_votes: Vec<ScrapedOnChainVotes>,
	pub included_receipts: Vec<CandidateReceipt>,
	pub unapplied_slashes: Vec<(SessionIndex, CandidateHash, PendingSlashes)>,
}

impl ScrapedUpdates {
	pub fn new() -> Self {
		Self {
			on_chain_votes: Vec::new(),
			included_receipts: Vec::new(),
			unapplied_slashes: Vec::new(),
		}
	}
}

/// A structure meant to facilitate chain reversions in the event of a dispute
/// concluding against a candidate. Each candidate hash maps to a number of
/// block heights, which in turn map to vectors of blocks at those heights.
pub struct Inclusions {
	inclusions_inner: BTreeMap<CandidateHash, BTreeMap<BlockNumber, HashSet<Hash>>>,
	/// Keeps track at which block number a candidate was inserted. Used in `remove_up_to_height`.
	/// Without this tracking we won't be able to remove all candidates before block X.
	candidates_by_block_number: BTreeMap<BlockNumber, HashSet<CandidateHash>>,
}

impl Inclusions {
	pub fn new() -> Self {
		Self { inclusions_inner: BTreeMap::new(), candidates_by_block_number: BTreeMap::new() }
	}

	pub fn insert(
		&mut self,
		candidate_hash: CandidateHash,
		block_number: BlockNumber,
		block_hash: Hash,
	) {
		self.inclusions_inner
			.entry(candidate_hash)
			.or_default()
			.entry(block_number)
			.or_default()
			.insert(block_hash);

		self.candidates_by_block_number
			.entry(block_number)
			.or_default()
			.insert(candidate_hash);
	}

	/// Removes all candidates up to a given height.
	///
	/// The candidates at the block height are NOT removed.
	pub fn remove_up_to_height(&mut self, height: &BlockNumber) {
		let not_stale = self.candidates_by_block_number.split_off(&height);
		let stale = std::mem::take(&mut self.candidates_by_block_number);
		self.candidates_by_block_number = not_stale;

		for candidate in stale.into_values().flatten() {
			match self.inclusions_inner.entry(candidate) {
				Entry::Vacant(_) => {
					// Rare case where same candidate was present on multiple heights, but all are
					// pruned at the same time. This candidate was already pruned in the previous
					// occurrence so it is skipped now.
				},
				Entry::Occupied(mut e) => {
					let mut blocks_including = std::mem::take(e.get_mut());
					// Returns everything after the given key, including the key. This works because
					// the blocks are sorted in ascending order.
					blocks_including = blocks_including.split_off(&height);
					if blocks_including.is_empty() {
						e.remove_entry();
					} else {
						*e.get_mut() = blocks_including;
					}
				},
			}
		}
	}

	pub fn get(&self, candidate: &CandidateHash) -> Vec<(BlockNumber, Hash)> {
		let mut inclusions_as_vec: Vec<(BlockNumber, Hash)> = Vec::new();
		if let Some(blocks_including) = self.inclusions_inner.get(candidate) {
			for (height, blocks_at_height) in blocks_including.iter() {
				for block in blocks_at_height {
					inclusions_as_vec.push((*height, *block));
				}
			}
		}
		inclusions_as_vec
	}

	pub fn contains(&self, candidate: &CandidateHash) -> bool {
		self.inclusions_inner.get(candidate).is_some()
	}
}

/// Chain scraper
///
/// Scrapes unfinalized chain in order to collect information from blocks. Chain scraping
/// during disputes enables critical spam prevention. It does so by updating two important
/// criteria determining whether a vote sent during dispute distribution is potential
/// spam. Namely, whether the candidate being voted on is backed or included.
///
/// Concretely:
///
/// - Monitors for `CandidateIncluded` events to keep track of candidates that have been included on
///   chains.
/// - Monitors for `CandidateBacked` events to keep track of all backed candidates.
/// - Calls `FetchOnChainVotes` for each block to gather potentially missed votes from chain.
///
/// With this information it provides a `CandidateComparator` and as a return value of
/// `process_active_leaves_update` any scraped votes.
///
/// Scraped candidates are available `DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION` more blocks
/// after finalization as a precaution not to prune them prematurely. Besides the newly scraped
/// candidates `DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION` finalized blocks are parsed as
/// another precaution to have their `CandidateReceipts` available in case a dispute is raised on
/// them,
pub struct ChainScraper {
	/// All candidates we have seen backed.
	backed_candidates: candidates::ScrapedCandidates,

	/// Maps included candidate hashes to one or more relay block heights and hashes.
	/// These correspond to all the relay blocks which marked a candidate as included,
	/// and are needed to apply reversions in case a dispute is concluded against the
	/// candidate.
	inclusions: Inclusions,

	/// Latest relay blocks observed by the provider.
	///
	/// This is used to avoid redundant scraping of ancestry. We assume that ancestors of cached
	/// blocks are already processed, i.e. we have saved corresponding included candidates.
	last_observed_blocks: LruMap<Hash, ()>,
}

impl ChainScraper {
	/// Limits the number of ancestors received for a single request.
	pub(crate) const ANCESTRY_CHUNK_SIZE: u32 = 10;
	/// Limits the overall number of ancestors walked through for a given head.
	///
	/// As long as we have `MAX_FINALITY_LAG` this makes sense as a value.
	pub(crate) const ANCESTRY_SIZE_LIMIT: u32 = MAX_FINALITY_LAG;

	/// Create a properly initialized `OrderingProvider`.
	///
	/// Returns: `Self` and any scraped votes.
	pub async fn new<Sender>(
		sender: &mut Sender,
		initial_head: ActivatedLeaf,
	) -> Result<(Self, Vec<ScrapedOnChainVotes>)>
	where
		Sender: overseer::DisputeCoordinatorSenderTrait,
	{
		let mut s = Self {
			backed_candidates: candidates::ScrapedCandidates::new(),
			inclusions: Inclusions::new(),
			last_observed_blocks: LruMap::new(ByLength::new(LRU_OBSERVED_BLOCKS_CAPACITY)),
		};
		let update =
			ActiveLeavesUpdate { activated: Some(initial_head), deactivated: Default::default() };
		let updates = s.process_active_leaves_update(sender, &update).await?;
		Ok((s, updates.on_chain_votes))
	}

	/// Check whether we have seen a candidate included on any chain.
	pub fn is_candidate_included(&self, candidate_hash: &CandidateHash) -> bool {
		self.inclusions.contains(candidate_hash)
	}

	/// Check whether the candidate is backed
	pub fn is_candidate_backed(&self, candidate_hash: &CandidateHash) -> bool {
		self.backed_candidates.contains(candidate_hash)
	}

	/// Query active leaves for any candidate `CandidateEvent::CandidateIncluded` events.
	///
	/// and updates current heads, so we can query candidates for all non finalized blocks.
	///
	/// Returns: On chain votes and included candidate receipts for the leaf and any
	/// ancestors we might not yet have seen.
	pub async fn process_active_leaves_update<Sender>(
		&mut self,
		sender: &mut Sender,
		update: &ActiveLeavesUpdate,
	) -> Result<ScrapedUpdates>
	where
		Sender: overseer::DisputeCoordinatorSenderTrait,
	{
		let activated = match update.activated.as_ref() {
			Some(activated) => activated,
			None => return Ok(ScrapedUpdates::new()),
		};

		// Fetch ancestry up to `SCRAPED_FINALIZED_BLOCKS_COUNT` blocks beyond
		// the last finalized one
		let ancestors = self
			.get_relevant_block_ancestors(sender, activated.hash, activated.number)
			.await?;

		// Ancestors block numbers are consecutive in the descending order.
		let earliest_block_number = activated.number - ancestors.len() as u32;
		let block_numbers = (earliest_block_number..=activated.number).rev();

		let block_hashes = std::iter::once(activated.hash).chain(ancestors);

		let mut scraped_updates = ScrapedUpdates::new();
		for (block_number, block_hash) in block_numbers.zip(block_hashes) {
			gum::trace!(target: LOG_TARGET, ?block_number, ?block_hash, "In ancestor processing.");

			let receipts_for_block =
				self.process_candidate_events(sender, block_number, block_hash).await?;
			scraped_updates.included_receipts.extend(receipts_for_block);

			if let Some(votes) = get_on_chain_votes(sender, block_hash).await? {
				scraped_updates.on_chain_votes.push(votes);
			}
		}

		// for unapplied slashes, we only look at the latest activated hash,
		// it should accumulate them all
		match get_unapplied_slashes(sender, activated.hash).await {
			Ok(unapplied_slashes) => {
				scraped_updates.unapplied_slashes = unapplied_slashes;
			},
			Err(runtime::Error::RuntimeRequest(RuntimeApiError::NotSupported { .. })) => {
				gum::debug!(
					target: LOG_TARGET,
					block_hash = ?activated.hash,
					"Fetching unapplied slashes not yet supported.",
				);
			},
			Err(error) => {
				gum::warn!(
					target: LOG_TARGET,
					block_hash = ?activated.hash,
					?error,
					"Error fetching unapplied slashes.",
				);
			},
		}

		self.last_observed_blocks.insert(activated.hash, ());

		Ok(scraped_updates)
	}

	/// Prune finalized candidates.
	///
	/// We keep each candidate for `DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION` blocks after
	/// finalization. After that we treat it as low priority.
	pub fn process_finalized_block(&mut self, finalized_block_number: &BlockNumber) {
		// `DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION - 1` because
		// `finalized_block_number`counts to the candidate lifetime.
		match finalized_block_number.checked_sub(DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION - 1)
		{
			Some(key_to_prune) => {
				self.backed_candidates.remove_up_to_height(&key_to_prune);
				self.inclusions.remove_up_to_height(&key_to_prune);
			},
			None => {
				// Nothing to prune. We are still in the beginning of the chain and there are not
				// enough finalized blocks yet.
			},
		}
		{}
	}

	/// Process candidate events of a block.
	///
	/// Keep track of all included and backed candidates.
	///
	/// Returns freshly included candidate receipts
	async fn process_candidate_events<Sender>(
		&mut self,
		sender: &mut Sender,
		block_number: BlockNumber,
		block_hash: Hash,
	) -> Result<Vec<CandidateReceipt>>
	where
		Sender: overseer::DisputeCoordinatorSenderTrait,
	{
		let events = get_candidate_events(sender, block_hash).await?;
		let mut included_receipts: Vec<CandidateReceipt> = Vec::new();
		// Get included and backed events:
		for ev in events {
			match ev {
				CandidateEvent::CandidateIncluded(receipt, _, _, _) => {
					let candidate_hash = receipt.hash();
					gum::trace!(
						target: LOG_TARGET,
						?candidate_hash,
						?block_number,
						"Processing included event"
					);
					self.inclusions.insert(candidate_hash, block_number, block_hash);
					included_receipts.push(receipt);
				},
				CandidateEvent::CandidateBacked(receipt, _, _, _) => {
					let candidate_hash = receipt.hash();
					gum::trace!(
						target: LOG_TARGET,
						?candidate_hash,
						?block_number,
						"Processing backed event"
					);
					self.backed_candidates.insert(block_number, candidate_hash);
				},
				_ => {
					// skip the rest
				},
			}
		}
		Ok(included_receipts)
	}

	/// Returns ancestors of `head` in the descending order, stopping
	/// either at the block present in cache or at `SCRAPED_FINALIZED_BLOCKS_COUNT -1` blocks after
	/// the last finalized one (called `target_ancestor`).
	///
	/// Both `head` and the `target_ancestor` blocks are **not** included in the result.
	async fn get_relevant_block_ancestors<Sender>(
		&mut self,
		sender: &mut Sender,
		mut head: Hash,
		mut head_number: BlockNumber,
	) -> Result<Vec<Hash>>
	where
		Sender: overseer::DisputeCoordinatorSenderTrait,
	{
		let target_ancestor = get_finalized_block_number(sender)
			.await?
			.saturating_sub(DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION);

		let mut ancestors = Vec::new();

		// If head_number <= target_ancestor + 1 the ancestry will be empty.
		if self.last_observed_blocks.get(&head).is_some() || head_number <= target_ancestor + 1 {
			return Ok(ancestors)
		}

		loop {
			let hashes = get_block_ancestors(sender, head, Self::ANCESTRY_CHUNK_SIZE).await?;

			let earliest_block_number = match head_number.checked_sub(hashes.len() as u32) {
				Some(number) => number,
				None => {
					// It's assumed that it's impossible to retrieve
					// more than N ancestors for block number N.
					gum::error!(
						target: LOG_TARGET,
						"Received {} ancestors for block number {} from Chain API",
						hashes.len(),
						head_number,
					);
					return Ok(ancestors)
				},
			};
			// The reversed order is parent, grandparent, etc. excluding the head.
			let block_numbers = (earliest_block_number..head_number).rev();

			for (block_number, hash) in block_numbers.zip(&hashes) {
				// Return if we either met target/cached block or
				// hit the size limit for the returned ancestry of head.
				if self.last_observed_blocks.get(hash).is_some() ||
					block_number <= target_ancestor ||
					ancestors.len() >= Self::ANCESTRY_SIZE_LIMIT as usize
				{
					return Ok(ancestors)
				}

				ancestors.push(*hash);
			}

			match hashes.last() {
				Some(last_hash) => {
					head = *last_hash;
					head_number = earliest_block_number;
				},
				None => break,
			}
		}
		return Ok(ancestors)
	}

	pub fn get_blocks_including_candidate(
		&self,
		candidate: &CandidateHash,
	) -> Vec<(BlockNumber, Hash)> {
		self.inclusions.get(candidate)
	}
}

async fn get_finalized_block_number<Sender>(sender: &mut Sender) -> FatalResult<BlockNumber>
where
	Sender: overseer::DisputeCoordinatorSenderTrait,
{
	let (number_tx, number_rx) = oneshot::channel();
	send_message_fatal(sender, ChainApiMessage::FinalizedBlockNumber(number_tx), number_rx).await
}

async fn get_block_ancestors<Sender>(
	sender: &mut Sender,
	head: Hash,
	num_ancestors: BlockNumber,
) -> FatalResult<Vec<Hash>>
where
	Sender: overseer::DisputeCoordinatorSenderTrait,
{
	let (tx, rx) = oneshot::channel();
	sender
		.send_message(ChainApiMessage::Ancestors {
			hash: head,
			k: num_ancestors as usize,
			response_channel: tx,
		})
		.await;

	rx.await
		.or(Err(FatalError::ChainApiSenderDropped))?
		.map_err(FatalError::ChainApiAncestors)
}

async fn send_message_fatal<Sender, Response>(
	sender: &mut Sender,
	message: ChainApiMessage,
	receiver: oneshot::Receiver<std::result::Result<Response, ChainApiError>>,
) -> FatalResult<Response>
where
	Sender: SubsystemSender<ChainApiMessage>,
{
	sender.send_message(message).await;

	receiver
		.await
		.map_err(|_| FatalError::ChainApiSenderDropped)?
		.map_err(FatalError::ChainApiAncestors)
}
