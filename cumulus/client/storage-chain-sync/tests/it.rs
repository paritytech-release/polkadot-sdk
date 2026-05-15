// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for [`cumulus_client_storage_chain_sync::StorageChainBlockImport`].
//!
//! These tests drive the wrapper through its public [`BlockImport::import_block`] surface
//! against a hand-rolled mock client/runtime API and a recording inner `BlockImport` that
//! captures the `BlockImportParams` it receives.
//!
//! Scope: cases A (already-executed peek) and the `should_intercept` short-circuits. Case B
//! (re-execute) and case C (gap-sync verified path) are intentionally out of scope; they
//! require either a real WASM runtime or upstream gate changes outside this branch.

use mock::{
	case_a_params, install_log_capture, intermediate_attached, make_harness, params_with_origin,
	renew_op,
};
use rstest::rstest;
use sc_consensus::{BlockImport, ImportResult};
use sp_consensus::BlockOrigin;
use sp_runtime::OpaqueExtrinsic;
use sp_transaction_storage_proof::ContentHash;

#[rstest]
#[case::warp_sync(BlockOrigin::WarpSync, None)]
#[case::gap_sync(BlockOrigin::GapSync, Some(Vec::new()))]
#[case::body_none(BlockOrigin::NetworkBroadcast, None)]
#[tokio::test]
async fn import_passes_through(
	#[case] origin: BlockOrigin,
	#[case] body: Option<Vec<OpaqueExtrinsic>>,
) {
	let h = make_harness();
	let params = params_with_origin(origin, 1, body);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));
	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_case_a_no_renews_attaches_nothing() {
	let h = make_harness();
	let params = case_a_params(1, Vec::new());
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));
	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[rstest]
#[case::blake2b(
	b"renew-blob-payload".as_slice(),
	sp_transaction_storage_proof::HashingAlgorithm::Blake2b256,
)]
#[case::sha2(
	b"sha2-renew-blob-payload".as_slice(),
	sp_transaction_storage_proof::HashingAlgorithm::Sha2_256,
)]
#[case::keccak(
	b"keccak-renew-blob-payload".as_slice(),
	sp_transaction_storage_proof::HashingAlgorithm::Keccak256,
)]
#[tokio::test]
async fn import_case_a_attaches_prefetched(
	#[case] bytes: &[u8],
	#[case] algorithm: sp_transaction_storage_proof::HashingAlgorithm,
) {
	let h = make_harness();
	let content_hash: ContentHash = algorithm.hash(bytes);
	h.network.insert(content_hash, bytes.to_vec());

	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));

	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	let payload: &Vec<(ContentHash, Vec<u8>)> = captured[0]
		.get_intermediate(sc_client_api::backend::PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY)
		.expect("intermediate must be present");
	assert_eq!(payload.len(), 1);
	assert_eq!(payload[0].0, content_hash);
	assert_eq!(payload[0].1, bytes);
}

#[tokio::test]
async fn import_case_a_skips_already_present_hash() {
	let h = make_harness();
	let content_hash: ContentHash = [0x22u8; 32];
	let bytes = b"already-on-disk".to_vec();
	h.api.insert_indexed_transaction(content_hash, bytes);

	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));

	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_case_a_errors_when_fetcher_partial() {
	let h = make_harness();
	let content_hash: ContentHash = [0x33u8; 32];
	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let err = h
		.wrapper
		.import_block(params)
		.await
		.expect_err("fetcher should yield zero bytes and the wrapper should error");
	let msg = format!("{err}");
	assert!(msg.contains("bitswap fetch"), "unexpected error message: {msg}",);
	assert!(h.captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn import_rejects_blob_failing_multihash_verify() {
	let (capture, _guard) = install_log_capture();
	let h = make_harness();
	let content_hash: ContentHash = [0x55u8; 32];
	let bad_bytes = b"these-bytes-do-not-hash-to-content_hash".to_vec();
	h.network.insert(content_hash, bad_bytes.clone());
	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let err = h
		.wrapper
		.import_block(params)
		.await
		.expect_err("fetch should fail when blob fails multi-hash verify");
	let msg = format!("{err}");
	assert!(msg.contains("bitswap fetch"), "unexpected error message: {msg}",);
	assert!(
		capture.contains("did not match any supported hashing algorithm"),
		"missing warn line, logs:\n{}",
		capture.get_logs(),
	);
	assert!(
		!capture.contains("post-commit verify FAILED"),
		"should not contain post-commit verify message",
	);
}

mod mock {
	use async_trait::async_trait;
	use cid::{Cid, Version as CidVersion};
	use cumulus_client_storage_chain_sync::{
		BitswapPeerSource, IndexedTransactionFetcher, NetworkHandle, StorageChainBlockImport,
		SyncingHandle,
	};
	use futures::channel::oneshot;

	use sc_consensus::{
		BlockCheckParams, BlockImport, BlockImportParams, ImportResult, ImportedAux, StateAction,
		StorageChanges as ConsensusStorageChanges,
	};
	use sc_network::{
		bitswap::{test_helpers::schema as bitswap_schema, BLAKE2B_256_MULTIHASH_CODE, RAW_CODEC},
		request_responses::{IfDisconnected, RequestFailure},
		types::ProtocolName,
		NetworkRequest, PeerId,
	};
	use sp_api::{mock_impl_runtime_apis, ApiError};
	use sp_consensus::{BlockOrigin, Error as ConsensusError};
	use sp_core::H256;
	use sp_runtime::{
		generic,
		traits::{BlakeTwo256, Block as BlockT, Header as _},
		Digest, Justifications, OpaqueExtrinsic,
	};
	use sp_state_machine::{IndexOperation, StorageChanges};
	use sp_transaction_storage_proof::{
		runtime_api::TransactionStorageApi, ContentHash, IndexedTransactionInfo,
	};
	use std::{
		collections::HashMap,
		sync::{Arc, Mutex, OnceLock},
	};

	pub(super) type TestBlock = generic::Block<generic::Header<u32, BlakeTwo256>, OpaqueExtrinsic>;
	type TestHeader = generic::Header<u32, BlakeTwo256>;
	type Block = TestBlock;

	#[derive(Default, Clone)]
	struct MockApiInner {
		indexed_at_block_number: HashMap<u32, Vec<IndexedTransactionInfo>>,
		indexed_transactions: HashMap<H256, Vec<u8>>,
	}

	#[derive(Clone)]
	pub(super) struct MockApiClient {
		inner: Arc<Mutex<MockApiInner>>,
	}

	impl Default for MockApiClient {
		fn default() -> Self {
			Self { inner: Arc::new(Mutex::new(MockApiInner::default())) }
		}
	}

	impl MockApiClient {
		#[allow(dead_code)] // Used by upcoming gap-sync tests (v13 plan PR-2).
		pub(super) fn set_indexed(&self, block_number: u32, infos: Vec<IndexedTransactionInfo>) {
			self.inner.lock().unwrap().indexed_at_block_number.insert(block_number, infos);
		}

		pub(super) fn insert_indexed_transaction(&self, hash: ContentHash, data: Vec<u8>) {
			self.inner.lock().unwrap().indexed_transactions.insert(H256::from(hash), data);
		}
	}

	mock_impl_runtime_apis! {
		impl TransactionStorageApi<Block> for MockApiClient {
			fn retention_period(&self) -> u32 {
				0
			}

			fn indexed_transactions(&self, block: u32) -> Vec<IndexedTransactionInfo> {
				self.inner
					.lock()
					.unwrap()
					.indexed_at_block_number
					.get(&block)
					.cloned()
					.unwrap_or_default()
			}
		}
	}

	impl sp_api::ProvideRuntimeApi<TestBlock> for MockApiClient {
		type Api = MockApiClient;
		fn runtime_api(&self) -> sp_api::ApiRef<'_, Self::Api> {
			self.clone().into()
		}
	}

	impl sp_api::CallApiAt<TestBlock> for MockApiClient {
		type StateBackend =
			sp_state_machine::InMemoryBackend<sp_runtime::traits::HashingFor<TestBlock>>;

		fn call_api_at(&self, _: sp_api::CallApiAtParams<TestBlock>) -> Result<Vec<u8>, ApiError> {
			unreachable!("Cases A and the gate short-circuits do not call call_api_at")
		}

		fn runtime_version_at(
			&self,
			_at: <TestBlock as sp_runtime::traits::Block>::Hash,
			_call_context: sp_core::traits::CallContext,
		) -> Result<sp_version::RuntimeVersion, ApiError> {
			unreachable!("not used by the wrapper in these tests")
		}

		fn state_at(
			&self,
			_at: <TestBlock as sp_runtime::traits::Block>::Hash,
		) -> Result<Self::StateBackend, ApiError> {
			unreachable!("only the case B re-execute path queries this; case B is out of scope")
		}

		fn initialize_extensions(
			&self,
			_at: <TestBlock as sp_runtime::traits::Block>::Hash,
			_extensions: &mut sp_externalities::Extensions,
		) -> Result<(), ApiError> {
			Ok(())
		}
	}

	impl sc_client_api::BlockBackend<TestBlock> for MockApiClient {
		fn block_body(
			&self,
			_hash: <TestBlock as BlockT>::Hash,
		) -> sp_blockchain::Result<Option<Vec<<TestBlock as BlockT>::Extrinsic>>> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn block_indexed_body(
			&self,
			_hash: <TestBlock as BlockT>::Hash,
		) -> sp_blockchain::Result<Option<Vec<Vec<u8>>>> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn block_indexed_hashes(
			&self,
			_hash: <TestBlock as BlockT>::Hash,
		) -> sp_blockchain::Result<Option<Vec<H256>>> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn block(
			&self,
			_hash: <TestBlock as BlockT>::Hash,
		) -> sp_blockchain::Result<Option<generic::SignedBlock<TestBlock>>> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn block_status(
			&self,
			_hash: <TestBlock as BlockT>::Hash,
		) -> sp_blockchain::Result<sp_consensus::BlockStatus> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn justifications(
			&self,
			_hash: <TestBlock as BlockT>::Hash,
		) -> sp_blockchain::Result<Option<Justifications>> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn block_hash(
			&self,
			_number: sp_runtime::traits::NumberFor<TestBlock>,
		) -> sp_blockchain::Result<Option<<TestBlock as BlockT>::Hash>> {
			unreachable!("StorageChainBlockImport tests only query indexed transaction presence")
		}

		fn indexed_transaction(&self, hash: H256) -> sp_blockchain::Result<Option<Vec<u8>>> {
			Ok(self.inner.lock().unwrap().indexed_transactions.get(&hash).cloned())
		}

		fn has_indexed_transaction(&self, hash: H256) -> sp_blockchain::Result<bool> {
			Ok(self.inner.lock().unwrap().indexed_transactions.contains_key(&hash))
		}

		fn requires_full_sync(&self) -> bool {
			false
		}
	}

	pub(super) struct TestInner {
		captured: Arc<Mutex<Vec<BlockImportParams<TestBlock>>>>,
	}

	impl TestInner {
		fn recording() -> Self {
			Self { captured: Arc::new(Mutex::new(Vec::new())) }
		}
	}

	#[async_trait]
	impl BlockImport<TestBlock> for TestInner {
		type Error = ConsensusError;

		async fn check_block(
			&self,
			_block: BlockCheckParams<TestBlock>,
		) -> Result<ImportResult, Self::Error> {
			Ok(ImportResult::imported(true))
		}

		async fn import_block(
			&self,
			block: BlockImportParams<TestBlock>,
		) -> Result<ImportResult, Self::Error> {
			self.captured.lock().unwrap().push(block);
			Ok(ImportResult::Imported(ImportedAux::default()))
		}
	}

	#[derive(Default)]
	pub(super) struct MockNetworkRequest {
		responses: Mutex<HashMap<ContentHash, Vec<u8>>>,
	}

	impl MockNetworkRequest {
		pub(super) fn insert(&self, hash: ContentHash, data: Vec<u8>) {
			self.responses.lock().unwrap().insert(hash, data);
		}
	}

	#[async_trait]
	impl NetworkRequest for MockNetworkRequest {
		async fn request(
			&self,
			_target: PeerId,
			_protocol: ProtocolName,
			request: Vec<u8>,
			_fallback_request: Option<(Vec<u8>, ProtocolName)>,
			_connect: IfDisconnected,
		) -> Result<(Vec<u8>, ProtocolName), RequestFailure> {
			use prost::Message as _;
			let message = bitswap_schema::Message::decode(&*request)
				.expect("MockNetworkRequest received malformed bitswap request");
			let responses = self.responses.lock().unwrap();
			let mut payload = Vec::new();
			let mut block_presences = Vec::new();
			for entry in message.wantlist.unwrap_or_default().entries {
				let Ok(cid) = Cid::read_bytes(entry.block.as_slice()) else { continue };
				let digest: Option<ContentHash> = cid.hash().digest().try_into().ok();
				match digest.and_then(|d| responses.get(&d).cloned()) {
					Some(data) => payload
						.push(bitswap_schema::message::Block { prefix: blake2b_raw_prefix(), data }),
					None => block_presences.push(bitswap_schema::message::BlockPresence {
						cid: entry.block,
						r#type: bitswap_schema::message::BlockPresenceType::DontHave as i32,
					}),
				}
			}
			let response =
				bitswap_schema::Message { payload, block_presences, ..Default::default() };
			Ok((response.encode_to_vec(), ProtocolName::from("/ipfs/bitswap/1.2.0")))
		}

		fn start_request(
			&self,
			_target: PeerId,
			_protocol: ProtocolName,
			_request: Vec<u8>,
			_fallback_request: Option<(Vec<u8>, ProtocolName)>,
			_tx: oneshot::Sender<Result<(Vec<u8>, ProtocolName), RequestFailure>>,
			_connect: IfDisconnected,
		) {
			unreachable!("the bitswap client uses async request(), never start_request()")
		}
	}

	fn blake2b_raw_prefix() -> Vec<u8> {
		sc_network::bitswap::test_helpers::Prefix {
			version: CidVersion::V1,
			codec: RAW_CODEC,
			mh_type: BLAKE2B_256_MULTIHASH_CODE,
			mh_len: 32,
		}
		.to_bytes()
	}

	struct MockBitswapPeerSource {
		peers: Vec<PeerId>,
	}

	#[async_trait]
	impl BitswapPeerSource for MockBitswapPeerSource {
		async fn current_peers(&self) -> Result<Vec<PeerId>, oneshot::Canceled> {
			Ok(self.peers.clone())
		}
	}

	pub(super) struct Harness {
		pub(super) wrapper: StorageChainBlockImport<TestBlock, TestInner, MockApiClient>,
		pub(super) api: Arc<MockApiClient>,
		pub(super) captured: Arc<Mutex<Vec<BlockImportParams<TestBlock>>>>,
		pub(super) network: Arc<MockNetworkRequest>,
	}

	pub(super) fn make_harness() -> Harness {
		let api = Arc::new(MockApiClient::default());
		let network: Arc<MockNetworkRequest> = Arc::new(MockNetworkRequest::default());
		let inner = TestInner::recording();
		let captured = inner.captured.clone();

		let network_handle: NetworkHandle = Arc::new(OnceLock::new());
		let syncing_handle: SyncingHandle = Arc::new(OnceLock::new());
		let _ = network_handle.set(network.clone() as Arc<dyn NetworkRequest + Send + Sync>);
		let _ = syncing_handle.set(Arc::new(MockBitswapPeerSource { peers: vec![PeerId::random()] })
			as Arc<dyn BitswapPeerSource + Send + Sync>);

		let fetcher = IndexedTransactionFetcher::<TestBlock>::new(network_handle, syncing_handle);
		let wrapper = StorageChainBlockImport::new(inner, api.clone(), fetcher);

		Harness { wrapper, api, captured, network }
	}

	fn test_header(number: u32, parent: H256) -> TestHeader {
		TestHeader::new(number, H256::zero(), H256::zero(), parent, Digest::default())
	}

	pub(super) fn params_with_origin(
		origin: BlockOrigin,
		number: u32,
		body: Option<Vec<OpaqueExtrinsic>>,
	) -> BlockImportParams<TestBlock> {
		let header = test_header(number, H256::zero());
		let mut params = BlockImportParams::new(origin, header);
		params.body = body;
		params.fork_choice = Some(sc_consensus::ForkChoiceStrategy::Custom(true));
		params
	}

	fn empty_storage_changes() -> StorageChanges<sp_runtime::traits::HashingFor<TestBlock>> {
		StorageChanges::default()
	}

	pub(super) fn renew_op(hash: ContentHash, extrinsic_index: u32) -> IndexOperation {
		IndexOperation::Renew { extrinsic: extrinsic_index, hash: hash.to_vec() }
	}

	pub(super) fn case_a_params(
		number: u32,
		renews: Vec<IndexOperation>,
	) -> BlockImportParams<TestBlock> {
		let mut params =
			params_with_origin(BlockOrigin::NetworkBroadcast, number, Some(Vec::new()));
		let mut changes = empty_storage_changes();
		changes.transaction_index_changes = renews;
		params.state_action = StateAction::ApplyChanges(ConsensusStorageChanges::Changes(changes));
		params
	}

	pub(super) fn intermediate_attached(params: &BlockImportParams<TestBlock>) -> bool {
		params
			.intermediates
			.contains_key(sc_client_api::backend::PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY)
	}

	static LOG_TRACER_INIT: std::sync::Once = std::sync::Once::new();

	pub(super) fn install_log_capture(
	) -> (sp_tracing::test_log_capture::LogCapture, tracing::subscriber::DefaultGuard) {
		LOG_TRACER_INIT.call_once(|| {
			let _ = tracing_log::LogTracer::init();
		});
		let (capture, subscriber) =
			sp_tracing::test_log_capture::init_log_capture(tracing::Level::TRACE, false);
		let guard = tracing::subscriber::set_default(subscriber);
		(capture, guard)
	}
}
