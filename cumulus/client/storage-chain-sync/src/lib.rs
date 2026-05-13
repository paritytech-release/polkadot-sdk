// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! BlockImport wrapper that bitswap-fetches missing TRANSACTION-column entries before
//! delegating to the inner block import. Tip-sync only; gap-sync and warp-sync pass through.
//!
//! See `StorageChainBlockImport::classify_renew_hashes` for the Case A / B / C discovery
//! dispatch.

mod fetcher;

pub(crate) use fetcher::FetchError;
pub use fetcher::{BitswapPeerSource, IndexedTransactionFetcher, NetworkHandle, SyncingHandle};

use sc_client_api::{backend::PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY, BlockBackend};
use sc_client_db::{classify_indexed_extrinsics, ClassifiedExtrinsic, IndexedTransactionMeta};
use sc_consensus::{
	BlockCheckParams, BlockImport, BlockImportParams, ImportResult, StateAction,
	StorageChanges as ConsensusStorageChanges,
};
use sc_network::bitswap::RAW_CODEC;
use sp_api::{ApiExt, CallApiAt, CallContext, Core, ProofRecorder, ProvideRuntimeApi};
use sp_consensus::{BlockOrigin, Error as ConsensusError};
use sp_runtime::traits::{Block as BlockT, HashingFor, Header as HeaderT};
use sp_state_machine::{IndexOperation, StorageChanges};
use sp_transaction_storage_proof::{
	runtime_api::TransactionStorageApi, ContentHash, HashingAlgorithm, IndexedTransactionInfo,
};
use sp_trie::proof_size_extension::ProofSizeExt;
use std::{collections::HashSet, marker::PhantomData, sync::Arc};

const LOG_TARGET: &str = "storage-chain-block-import";

/// Block-import wrapper that bitswap-fetches missing TRANSACTION-column entries
/// for tip-sync blocks before delegating to the inner block import.
pub struct StorageChainBlockImport<Block: BlockT, Inner, Client> {
	inner: Inner,
	client: Arc<Client>,
	fetcher: IndexedTransactionFetcher<Block>,
	_phantom: PhantomData<Block>,
}

impl<Block: BlockT, Inner: Clone, Client> Clone for StorageChainBlockImport<Block, Inner, Client> {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
			client: self.client.clone(),
			fetcher: self.fetcher.clone(),
			_phantom: PhantomData,
		}
	}
}

impl<Block: BlockT, Inner, Client> StorageChainBlockImport<Block, Inner, Client> {
	pub fn new(
		inner: Inner,
		client: Arc<Client>,
		fetcher: IndexedTransactionFetcher<Block>,
	) -> Self {
		Self { inner, client, fetcher, _phantom: PhantomData }
	}
}

#[async_trait::async_trait]
impl<Block, Inner, Client> BlockImport<Block> for StorageChainBlockImport<Block, Inner, Client>
where
	Block: BlockT<Hash = sc_client_db::DbHash>,
	Inner: BlockImport<Block, Error = ConsensusError> + Send + Sync,
	Client: ProvideRuntimeApi<Block> + CallApiAt<Block> + BlockBackend<Block> + Send + Sync,
	Client::Api: TransactionStorageApi<Block> + Core<Block>,
{
	type Error = ConsensusError;

	async fn check_block(
		&self,
		block: BlockCheckParams<Block>,
	) -> Result<ImportResult, Self::Error> {
		self.inner.check_block(block).await
	}

	async fn import_block(
		&self,
		mut params: BlockImportParams<Block>,
	) -> Result<ImportResult, Self::Error> {
		if !self.should_intercept(&params) {
			return self.inner.import_block(params).await;
		}

		let renews = self.classify_renew_hashes(&mut params)?;
		let missing = self.filter_missing(renews);
		let FetchedRenews { payload } = self.fetch_all(missing).await?;
		Self::attach_prefetched(&mut params, payload);

		let result = self.inner.import_block(params).await?;

		Ok(result)
	}
}

impl<Block, Inner, Client> StorageChainBlockImport<Block, Inner, Client>
where
	Block: BlockT<Hash = sc_client_db::DbHash>,
	Client: ProvideRuntimeApi<Block> + CallApiAt<Block> + BlockBackend<Block> + Send + Sync,
	Client::Api: TransactionStorageApi<Block> + Core<Block>,
{
	/// True iff the block needs bitswap prefetch (tip-only, body present, runtime API v2+).
	fn should_intercept(&self, params: &BlockImportParams<Block>) -> bool {
		if params.body.is_none() {
			return false;
		}
		match params.origin {
			BlockOrigin::NetworkInitialSync |
			BlockOrigin::NetworkBroadcast |
			BlockOrigin::ConsensusBroadcast |
			BlockOrigin::Own => {},
			BlockOrigin::Genesis |
			BlockOrigin::File |
			BlockOrigin::WarpSync |
			BlockOrigin::GapSync => return false,
		}
		let parent_hash = *params.header.parent_hash();
		self.client
			.runtime_api()
			.has_api_with::<dyn TransactionStorageApi<Block>, _>(parent_hash, |v| v >= 2)
			.unwrap_or(false)
	}

	/// Discovers renew hashes via Case A (peek), B (re-execute), or C (runtime API).
	///
	/// `&mut params` because Case B reassigns `params.state_action` to the executed
	/// `StorageChanges` so the inner block-import skips re-execution.
	fn classify_renew_hashes(
		&self,
		params: &mut BlockImportParams<Block>,
	) -> Result<RenewHashes, ConsensusError> {
		let parent_hash = *params.header.parent_hash();
		let block_number = *params.header.number();

		if let Some(changes) = params.state_action.as_storage_changes() {
			let renews = extract_renews_from_index_ops(&changes.transaction_index_changes);
			if !renews.is_empty() {
				log::debug!(
					target: LOG_TARGET,
					"block #{block_number:?} ({parent_hash:?}): case A peek, {} renew hashes",
					renews.len(),
				);
			}
			return Ok(RenewHashes::Unverified(renews));
		}

		if matches!(params.origin, BlockOrigin::GapSync) {
			let infos = self
				.client
				.runtime_api()
				.indexed_transactions(parent_hash, block_number)
				.map_err(|e| {
				ConsensusError::Other(
					format!("indexed_transactions runtime API failed: {e}").into(),
				)
			})?;
			if infos.iter().any(|info| info.extrinsic_index == u32::MAX) {
				log::debug!(
					target: LOG_TARGET,
					"block #{block_number:?} ({parent_hash:?}): case C runtime-API returned \
					 metadata without concrete extrinsic indexes; skipping wrapper bitswap",
				);
				return Ok(RenewHashes::Verified(HashSet::new()));
			}
			let body = params.body.as_ref().ok_or_else(|| {
				ConsensusError::Other("StorageChainBlockImport: body absent after gate".into())
			})?;
			let renews = body_classify_renews::<Block>(&infos, body);
			if !renews.is_empty() {
				log::debug!(
					target: LOG_TARGET,
					"block #{block_number:?} ({parent_hash:?}): case C runtime-API, \
					 {} indexed entries, {} renew hashes",
					infos.len(),
					renews.len(),
				);
			}
			return Ok(RenewHashes::Verified(renews));
		}

		let gen_storage_changes = self.execute_block(params)?;
		let renews = extract_renews_from_index_ops(&gen_storage_changes.transaction_index_changes);
		if !renews.is_empty() {
			log::debug!(
				target: LOG_TARGET,
				"block #{block_number:?} ({parent_hash:?}): case B re-executed, \
				 {} renew hashes",
				renews.len(),
			);
		}

		params.state_action =
			StateAction::ApplyChanges(ConsensusStorageChanges::Changes(gen_storage_changes));

		Ok(RenewHashes::Unverified(renews))
	}

	/// Drops every entry whose data is already in the local TRANSACTION column.
	fn filter_missing(&self, renews: RenewHashes) -> RenewHashes {
		let already_present = |hash: &ContentHash| {
			self.client.has_indexed_transaction((*hash).into()).unwrap_or(false)
		};
		match renews {
			RenewHashes::Verified(set) => RenewHashes::Verified(
				set.into_iter().filter(|(hash, _)| !already_present(hash)).collect(),
			),
			RenewHashes::Unverified(set) => RenewHashes::Unverified(
				set.into_iter().filter(|hash| !already_present(hash)).collect(),
			),
		}
	}

	/// Bitswap-fetch every missing entry; dispatches to verified or unverified path
	/// per [`RenewHashes`] variant. Errors if any entry was not served.
	async fn fetch_all(&self, missing: RenewHashes) -> Result<FetchedRenews, ConsensusError> {
		if missing.is_empty() {
			return Ok(FetchedRenews::default());
		}

		let (wanted_hashes, acquired) = match missing {
			RenewHashes::Verified(set) => {
				let wants: Vec<(ContentHash, HashingAlgorithm)> = set.into_iter().collect();
				let acquired = self.fetcher.fetch_many(&wants).await?;
				let hashes: Vec<ContentHash> = wants.into_iter().map(|(h, _)| h).collect();
				(hashes, acquired)
			},
			RenewHashes::Unverified(set) => {
				let wants: Vec<ContentHash> = set.into_iter().collect();
				let acquired = self.fetcher.fetch_many_unverified(&wants).await?;
				(wants, acquired)
			},
		};

		if acquired.len() != wanted_hashes.len() {
			let missing_count = wanted_hashes.len() - acquired.len();
			return Err(ConsensusError::Other(
				format!(
					"bitswap fetch: {missing_count} of {} entries not served",
					wanted_hashes.len(),
				)
				.into(),
			));
		}

		let payload: Vec<(ContentHash, Vec<u8>)> = wanted_hashes
			.iter()
			.map(|hash| {
				let data = acquired
					.get(hash)
					.expect("all hashes present; len equality verified above; qed")
					.clone();
				(*hash, data)
			})
			.collect();

		Ok(FetchedRenews { payload })
	}

	/// Stash prefetched bytes in `params.intermediates` under
	/// [`PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY`] for the backend writer.
	fn attach_prefetched(
		params: &mut BlockImportParams<Block>,
		fetched: Vec<(ContentHash, Vec<u8>)>,
	) {
		if fetched.is_empty() {
			return;
		}
		for (hash, _) in &fetched {
			log::info!(
				target: LOG_TARGET,
				"attaching bitswap-fetched indexed transaction {hash:?} to BlockImportParams",
			);
		}
		params.insert_intermediate(PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY, fetched);
	}

	/// Execute via runtime API to obtain `StorageChanges` (Case B). Caller must reassign
	/// `params.state_action` to `ApplyChanges(Changes(_))` before forwarding to the inner
	/// block import, otherwise the inner client re-executes.
	fn execute_block(
		&self,
		params: &BlockImportParams<Block>,
	) -> Result<StorageChanges<HashingFor<Block>>, ConsensusError> {
		let parent_hash = *params.header.parent_hash();
		let body = params.body.clone().unwrap_or_default();
		let block = Block::new(params.header.clone(), body);

		let recorder = ProofRecorder::<Block>::default();

		let mut runtime_api = self.client.runtime_api();
		runtime_api.set_call_context(CallContext::Onchain { import: true });
		runtime_api.record_proof_with_recorder(recorder.clone());
		runtime_api.register_extension(ProofSizeExt::new(recorder));

		runtime_api.execute_block(parent_hash, block.into()).map_err(|e| {
			ConsensusError::Other(format!("execute_block: runtime_api.execute_block: {e}").into())
		})?;

		let state = self.client.state_at(parent_hash).map_err(|e| {
			ConsensusError::Other(format!("execute_block: state_at({parent_hash:?}): {e}").into())
		})?;

		let gen_storage_changes =
			runtime_api.into_storage_changes(&state, parent_hash).map_err(|e| {
				ConsensusError::Other(format!("execute_block: into_storage_changes: {e}").into())
			})?;

		if params.header.state_root() != &gen_storage_changes.transaction_storage_root {
			return Err(ConsensusError::Other(
				format!(
					"execute_block: state root mismatch: header={:?}, executed={:?}",
					params.header.state_root(),
					gen_storage_changes.transaction_storage_root,
				)
				.into(),
			));
		}

		Ok(gen_storage_changes)
	}
}

/// Renew hashes tagged by their discovery path.
///
/// `Verified` pairs include the hashing algorithm (sourced from the runtime API); bitswap
/// can verify integrity. `Unverified` are bare hashes from host calls; each blob is verified
/// at fetch time by hashing with every supported [`HashingAlgorithm`].
enum RenewHashes {
	Verified(HashSet<(ContentHash, HashingAlgorithm)>),
	Unverified(HashSet<ContentHash>),
}

impl RenewHashes {
	fn is_empty(&self) -> bool {
		match self {
			Self::Verified(s) => s.is_empty(),
			Self::Unverified(s) => s.is_empty(),
		}
	}
}

/// Result of [`StorageChainBlockImport::fetch_all`]: the fetched payload bytes.
#[derive(Default)]
struct FetchedRenews {
	payload: Vec<(ContentHash, Vec<u8>)>,
}

/// Pull `Renew` content-hashes from a host-call index-ops log. `Insert` ops are ignored:
/// their bytes are in the block body.
fn extract_renews_from_index_ops(ops: &[IndexOperation]) -> HashSet<ContentHash> {
	ops.iter()
		.filter_map(|op| match op {
			IndexOperation::Renew { hash, .. } => hash.as_slice().try_into().ok(),
			IndexOperation::Insert { .. } => None,
		})
		.collect()
}

#[cfg(test)]
fn is_supported(info: &&IndexedTransactionInfo) -> bool {
	info.cid_codec == RAW_CODEC
}

#[cfg(test)]
fn to_db_meta(info: &IndexedTransactionInfo) -> IndexedTransactionMeta {
	IndexedTransactionMeta {
		content_hash: info.content_hash,
		size: info.size,
		extrinsic_index: info.extrinsic_index,
		hashing: info.hashing,
	}
}

/// Returns runtime-declared renew (hash, hashing) pairs whose bytes are NOT in the body —
/// i.e. the entries that must be fetched from elsewhere.
///
/// Filters out non-RAW codec entries (not bitswap-fetchable). Pure; no side effects.
fn body_classify_renews<Block: BlockT>(
	infos: &[IndexedTransactionInfo],
	body: &[Block::Extrinsic],
) -> HashSet<(ContentHash, HashingAlgorithm)> {
	let db_meta: Vec<IndexedTransactionMeta> = infos
		.iter()
		.filter(|info| info.cid_codec == RAW_CODEC)
		.map(|info| IndexedTransactionMeta {
			content_hash: info.content_hash,
			size: info.size,
			extrinsic_index: info.extrinsic_index,
			hashing: info.hashing,
		})
		.collect();

	if db_meta.is_empty() {
		return HashSet::new();
	}

	classify_indexed_extrinsics::<Block>(body, &db_meta)
		.into_iter()
		.filter_map(|entry| match entry {
			ClassifiedExtrinsic::Renew { hashes } => Some(hashes),
			_ => None,
		})
		.flatten()
		.collect()
}

impl From<FetchError> for ConsensusError {
	fn from(e: FetchError) -> Self {
		ConsensusError::Other(format!("bitswap: {e}").into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use sp_runtime::{generic, traits::BlakeTwo256, OpaqueExtrinsic};
	use std::collections::HashSet;

	type Block = generic::Block<generic::Header<u32, BlakeTwo256>, OpaqueExtrinsic>;

	fn info(
		content_hash: ContentHash,
		size: u32,
		alg: HashingAlgorithm,
		codec: u64,
		extrinsic_index: u32,
	) -> IndexedTransactionInfo {
		IndexedTransactionInfo {
			content_hash,
			size,
			hashing: alg,
			cid_codec: codec,
			extrinsic_index,
		}
	}

	fn extrinsic(bytes: &[u8]) -> OpaqueExtrinsic {
		OpaqueExtrinsic::from_blob(bytes.to_vec())
	}

	fn body_info(
		ext: &OpaqueExtrinsic,
		extrinsic_index: u32,
		hashing: HashingAlgorithm,
		codec: u64,
	) -> IndexedTransactionInfo {
		let encoded = ext.encode();
		info(hashing.hash(&encoded), encoded.len() as u32, hashing, codec, extrinsic_index)
	}

	#[test]
	fn is_supported_accepts_all_hashings_with_raw_codec() {
		for algo in
			[HashingAlgorithm::Blake2b256, HashingAlgorithm::Sha2_256, HashingAlgorithm::Keccak256]
		{
			let i = info([0u8; 32], 100, algo, RAW_CODEC, 0);
			assert!(is_supported(&&i), "{algo:?} should be supported with RAW codec");
		}
	}

	#[test]
	fn is_supported_rejects_non_raw_codec() {
		for algo in
			[HashingAlgorithm::Blake2b256, HashingAlgorithm::Sha2_256, HashingAlgorithm::Keccak256]
		{
			let i = info([0u8; 32], 100, algo, 0x70, 0);
			assert!(!is_supported(&&i), "{algo:?} with non-RAW codec should be rejected");
		}
	}

	#[test]
	fn to_db_meta_preserves_all_fields() {
		let h = [7u8; 32];
		let i = IndexedTransactionInfo {
			content_hash: h,
			size: 4096,
			hashing: HashingAlgorithm::Sha2_256,
			cid_codec: RAW_CODEC,
			extrinsic_index: 17,
		};
		let meta = to_db_meta(&i);
		assert_eq!(meta.content_hash, h);
		assert_eq!(meta.size, 4096);
		assert_eq!(meta.extrinsic_index, 17);
		assert_eq!(meta.hashing, HashingAlgorithm::Sha2_256);
	}

	#[test]
	fn body_classify_renews_returns_empty_for_supported_insert() {
		let body = vec![extrinsic(&[1, 2, 3])];
		let infos = vec![body_info(&body[0], 0, HashingAlgorithm::Blake2b256, RAW_CODEC)];

		assert!(body_classify_renews::<Block>(&infos, &body).is_empty());
	}

	#[test]
	fn body_classify_renews_filters_unsupported_non_raw_codec() {
		let body = vec![extrinsic(&[4, 5, 6])];
		let infos = vec![info(
			[9; 32],
			body[0].encode().len() as u32,
			HashingAlgorithm::Blake2b256,
			0x70,
			0,
		)];

		assert!(body_classify_renews::<Block>(&infos, &body).is_empty());
	}

	#[test]
	fn body_classify_renews_returns_single_supported_renew() {
		let body = vec![extrinsic(&[7, 8, 9])];
		let infos = vec![info(
			[1; 32],
			body[0].encode().len() as u32,
			HashingAlgorithm::Sha2_256,
			RAW_CODEC,
			0,
		)];

		let renews = body_classify_renews::<Block>(&infos, &body);
		assert_eq!(renews, HashSet::from([([1; 32], HashingAlgorithm::Sha2_256)]));
	}

	#[test]
	fn body_classify_renews_flattens_multi_renews_at_same_index() {
		let body = vec![extrinsic(&[10, 11, 12])];
		let encoded_len = body[0].encode().len() as u32;
		let infos = vec![
			info([2; 32], encoded_len, HashingAlgorithm::Blake2b256, RAW_CODEC, 0),
			info([3; 32], encoded_len, HashingAlgorithm::Keccak256, RAW_CODEC, 0),
		];

		let renews = body_classify_renews::<Block>(&infos, &body);
		assert_eq!(
			renews,
			HashSet::from([
				([2; 32], HashingAlgorithm::Blake2b256),
				([3; 32], HashingAlgorithm::Keccak256),
			]),
		);
	}

	#[test]
	fn extract_renews_from_index_ops_returns_only_renew_hashes() {
		let ops = vec![
			IndexOperation::Insert { extrinsic: 0, hash: vec![0xaa; 32], size: 100 },
			IndexOperation::Renew { extrinsic: 1, hash: vec![0xbb; 32] },
			IndexOperation::Insert { extrinsic: 2, hash: vec![0xcc; 32], size: 200 },
			IndexOperation::Renew { extrinsic: 3, hash: vec![0xdd; 32] },
		];
		let renews = extract_renews_from_index_ops(&ops);
		assert_eq!(renews, HashSet::from([[0xbb; 32], [0xdd; 32]]));
	}

	#[test]
	fn extract_renews_from_index_ops_dedupes_duplicate_hashes() {
		let h = [0x42; 32];
		let ops = vec![
			IndexOperation::Renew { extrinsic: 0, hash: h.to_vec() },
			IndexOperation::Renew { extrinsic: 1, hash: h.to_vec() },
			IndexOperation::Renew { extrinsic: 2, hash: h.to_vec() },
		];
		let renews = extract_renews_from_index_ops(&ops);
		assert_eq!(renews, HashSet::from([h]));
	}

	#[test]
	fn extract_renews_from_index_ops_handles_empty_input() {
		let renews = extract_renews_from_index_ops(&[]);
		assert!(renews.is_empty());
	}

	#[test]
	fn extract_renews_from_index_ops_drops_malformed_hash_length() {
		let ops = vec![
			IndexOperation::Renew { extrinsic: 0, hash: vec![0xee; 31] },
			IndexOperation::Renew { extrinsic: 1, hash: vec![0xff; 32] },
			IndexOperation::Renew { extrinsic: 2, hash: vec![0x11; 33] },
		];
		let renews = extract_renews_from_index_ops(&ops);
		assert_eq!(renews, HashSet::from([[0xff; 32]]));
	}
}
