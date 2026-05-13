// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for [`cumulus_client_storage_chain_sync::StorageChainBlockImport`].
//!
//! These tests drive the wrapper through its public [`BlockImport::import_block`] surface
//! against a hand-rolled mock runtime API (only `TransactionStorageApi` is mocked), a real
//! [`sc_client_db::Backend::new_test_with_tx_storage`] backend, and a recording inner
//! `BlockImport` that captures the `BlockImportParams` it receives.
//!
//! Scope: cases A (already-executed peek) and the `should_intercept` short-circuits. Case B
//! (re-execute) and case C (gap-sync verified path) are intentionally out of scope; they
//! require either a real WASM runtime or upstream gate changes outside this branch.

use async_trait::async_trait;
use cid::{Cid, Version as CidVersion};
use cumulus_client_storage_chain_sync::{
	BitswapPeerSource, IndexedTransactionFetcher, NetworkHandle, StorageChainBlockImport,
	SyncingHandle,
};
use futures::channel::oneshot;

use sc_client_api::backend::{Backend as _, BlockImportOperation as _};
use sc_client_db::{Backend, BlocksPruning};
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
use sp_runtime::{generic, traits::BlakeTwo256, traits::Header as _, Digest, OpaqueExtrinsic};
use sp_state_machine::{IndexOperation, StorageChanges};
use sp_transaction_storage_proof::{
	runtime_api::TransactionStorageApi, ContentHash, IndexedTransactionInfo,
};
use std::{
	collections::HashMap,
	sync::{Arc, Mutex, OnceLock},
};

type TestBlock = generic::Block<generic::Header<u32, BlakeTwo256>, OpaqueExtrinsic>;
type TestHeader = generic::Header<u32, BlakeTwo256>;
type Block = TestBlock;

#[derive(Default, Clone)]
struct MockApiInner {
	indexed_at_block_number: HashMap<u32, Vec<IndexedTransactionInfo>>,
}

#[derive(Clone)]
struct MockApiClient {
	inner: Arc<Mutex<MockApiInner>>,
}

impl Default for MockApiClient {
	fn default() -> Self {
		Self { inner: Arc::new(Mutex::new(MockApiInner::default())) }
	}
}

impl MockApiClient {
	#[allow(dead_code)] // Used by upcoming gap-sync tests (v13 plan PR-2).
	fn set_indexed(&self, block_number: u32, infos: Vec<IndexedTransactionInfo>) {
		self.inner.lock().unwrap().indexed_at_block_number.insert(block_number, infos);
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

enum TestInnerMode {
	Record,
	Commit { backend: Arc<Backend<TestBlock>>, next_number: Mutex<u32> },
}

struct TestInner {
	mode: TestInnerMode,
	captured: Arc<Mutex<Vec<BlockImportParams<TestBlock>>>>,
}

impl TestInner {
	fn recording() -> Self {
		Self { mode: TestInnerMode::Record, captured: Arc::new(Mutex::new(Vec::new())) }
	}

	fn committing(backend: Arc<Backend<TestBlock>>) -> Self {
		Self {
			mode: TestInnerMode::Commit { backend, next_number: Mutex::new(0) },
			captured: Arc::new(Mutex::new(Vec::new())),
		}
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
		mut block: BlockImportParams<TestBlock>,
	) -> Result<ImportResult, Self::Error> {
		if let TestInnerMode::Commit { backend, next_number } = &self.mode {
			let prefetched: Vec<(ContentHash, Vec<u8>)> = block
				.intermediates
				.remove(sc_client_api::backend::PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY)
				.and_then(|boxed| boxed.downcast::<Vec<(ContentHash, Vec<u8>)>>().ok())
				.map(|b| *b)
				.unwrap_or_default();
			let renews: Vec<IndexOperation> = match &block.state_action {
				StateAction::ApplyChanges(ConsensusStorageChanges::Changes(c)) =>
					c.transaction_index_changes.clone(),
				_ => Vec::new(),
			};
			let number = {
				let mut guard = next_number.lock().unwrap();
				let n = *guard;
				*guard += 1;
				n
			};
			commit_synthetic_block(backend, number, renews, prefetched)
				.map_err(|e| ConsensusError::Other(e.into()))?;
		}
		self.captured.lock().unwrap().push(block);
		Ok(ImportResult::Imported(ImportedAux::default()))
	}
}

#[derive(Default)]
struct MockNetworkRequest {
	responses: Mutex<HashMap<ContentHash, Vec<u8>>>,
}

impl MockNetworkRequest {
	fn insert(&self, hash: ContentHash, data: Vec<u8>) {
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
				Some(data) => payload.push(bitswap_schema::message::Block {
					prefix: blake2b_raw_prefix(),
					data,
				}),
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

struct Harness {
	wrapper: StorageChainBlockImport<TestBlock, TestInner, MockApiClient>,
	backend: Arc<Backend<TestBlock>>,
	captured: Arc<Mutex<Vec<BlockImportParams<TestBlock>>>>,
	network: Arc<MockNetworkRequest>,
}

enum HarnessMode {
	Record,
	Commit,
}

fn make_harness(mode: HarnessMode) -> Harness {
	let backend: Arc<Backend<TestBlock>> =
		Arc::new(Backend::new_test_with_tx_storage(BlocksPruning::KeepAll, 0));
	let api = Arc::new(MockApiClient::default());
	let network: Arc<MockNetworkRequest> = Arc::new(MockNetworkRequest::default());
	let inner = match mode {
		HarnessMode::Record => TestInner::recording(),
		HarnessMode::Commit => TestInner::committing(backend.clone()),
	};
	let captured = inner.captured.clone();

	let network_handle: NetworkHandle = Arc::new(OnceLock::new());
	let syncing_handle: SyncingHandle = Arc::new(OnceLock::new());
	let _ = network_handle.set(network.clone() as Arc<dyn NetworkRequest + Send + Sync>);
	let _ = syncing_handle.set(Arc::new(MockBitswapPeerSource { peers: vec![PeerId::random()] })
		as Arc<dyn BitswapPeerSource + Send + Sync>);

	let fetcher = IndexedTransactionFetcher::<TestBlock>::new(network_handle, syncing_handle);
	let wrapper = StorageChainBlockImport::new(inner, api.clone(), backend.clone(), fetcher);

	Harness { wrapper, backend, captured, network }
}

fn test_header(number: u32, parent: H256) -> TestHeader {
	TestHeader::new(number, H256::zero(), H256::zero(), parent, Digest::default())
}

fn params_with_origin(
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

fn renew_op(hash: ContentHash, extrinsic_index: u32) -> IndexOperation {
	IndexOperation::Renew { extrinsic: extrinsic_index, hash: hash.to_vec() }
}

fn case_a_params(number: u32, renews: Vec<IndexOperation>) -> BlockImportParams<TestBlock> {
	let mut params =
		params_with_origin(BlockOrigin::NetworkBroadcast, number, Some(Vec::new()));
	let mut changes = empty_storage_changes();
	changes.transaction_index_changes = renews;
	params.state_action = StateAction::ApplyChanges(ConsensusStorageChanges::Changes(changes));
	params
}


fn preseed_indexed_transaction(backend: &Backend<TestBlock>, hash: ContentHash, bytes: Vec<u8>) {
	commit_synthetic_block(
		backend,
		0,
		vec![IndexOperation::Renew { extrinsic: 0, hash: hash.to_vec() }],
		vec![(hash, bytes)],
	)
	.expect("commit_synthetic_block");
}

fn commit_synthetic_block(
	backend: &Backend<TestBlock>,
	number: u32,
	renews: Vec<IndexOperation>,
	prefetched: Vec<(ContentHash, Vec<u8>)>,
) -> Result<(), String> {
	use codec::Encode;
	use sc_client_api::backend::NewBlockState;
	let mut op = backend
		.begin_operation()
		.map_err(|e| format!("begin_operation: {e}"))?;
	backend
		.begin_state_operation(&mut op, H256::zero())
		.map_err(|e| format!("begin_state_operation: {e}"))?;
	if !renews.is_empty() {
		op.update_transaction_index(renews)
			.map_err(|e| format!("update_transaction_index: {e}"))?;
	}
	if !prefetched.is_empty() {
		op.set_prefetched_indexed_transactions(prefetched)
			.map_err(|e| format!("set_prefetched_indexed_transactions: {e}"))?;
	}
	let body: Vec<OpaqueExtrinsic> = vec![OpaqueExtrinsic::try_from_encoded_extrinsic(
		&Vec::<u8>::new().encode(),
	)
	.expect("OpaqueExtrinsic from empty bytes")];
	let header = test_header(number, H256::zero());
	op.set_block_data(header, Some(body), None, None, NewBlockState::Best, true)
		.map_err(|e| format!("set_block_data: {e}"))?;
	backend
		.commit_operation(op)
		.map_err(|e| format!("commit_operation: {e}"))?;
	Ok(())
}

fn intermediate_attached(params: &BlockImportParams<TestBlock>) -> bool {
	params
		.intermediates
		.contains_key(sc_client_api::backend::PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY)
}

#[tokio::test]
async fn import_passes_through_for_warp_sync() {
	let h = make_harness(HarnessMode::Record);
	let params = params_with_origin(BlockOrigin::WarpSync, 1, None);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));
	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_passes_through_for_gap_sync() {
	let h = make_harness(HarnessMode::Record);
	let params = params_with_origin(BlockOrigin::GapSync, 1, Some(Vec::new()));
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));
	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_passes_through_when_body_none() {
	let h = make_harness(HarnessMode::Record);
	let params = params_with_origin(BlockOrigin::NetworkBroadcast, 1, None);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));
	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_case_a_no_renews_attaches_nothing() {
	let h = make_harness(HarnessMode::Record);
	let params = case_a_params(1, Vec::new());
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));
	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_case_a_attaches_prefetched() {
	let h = make_harness(HarnessMode::Record);
	let bytes = b"renew-blob-payload".to_vec();
	let content_hash: ContentHash = sp_crypto_hashing::blake2_256(&bytes);
	h.network.insert(content_hash, bytes.clone());

	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));

	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	let payload: &Vec<(ContentHash, Vec<u8>)> = captured[0]
		.get_intermediate(
			sc_client_api::backend::PREFETCHED_INDEXED_TRANSACTIONS_INTERMEDIATE_KEY,
		)
		.expect("intermediate must be present");
	assert_eq!(payload.len(), 1);
	assert_eq!(payload[0].0, content_hash);
	assert_eq!(payload[0].1, bytes);
}

#[tokio::test]
async fn import_case_a_skips_already_present_hash() {
	let h = make_harness(HarnessMode::Record);
	let content_hash: ContentHash = [0x22u8; 32];
	let bytes = b"already-on-disk".to_vec();
	preseed_indexed_transaction(&h.backend, content_hash, bytes.clone());

	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let result = h.wrapper.import_block(params).await.expect("import_block");
	assert!(matches!(result, ImportResult::Imported(_)));

	let captured = h.captured.lock().unwrap();
	assert_eq!(captured.len(), 1);
	assert!(!intermediate_attached(&captured[0]));
}

#[tokio::test]
async fn import_case_a_errors_when_fetcher_partial() {
	let h = make_harness(HarnessMode::Record);
	let content_hash: ContentHash = [0x33u8; 32];
	let params = case_a_params(1, vec![renew_op(content_hash, 0)]);
	let err = h
		.wrapper
		.import_block(params)
		.await
		.expect_err("fetcher should yield zero bytes and the wrapper should error");
	let msg = format!("{err}");
	assert!(
		msg.contains("bitswap fetch"),
		"unexpected error message: {msg}",
	);
	assert!(h.captured.lock().unwrap().is_empty());
}

static LOG_TRACER_INIT: std::sync::Once = std::sync::Once::new();

fn install_log_capture() -> (sp_tracing::test_log_capture::LogCapture, tracing::subscriber::DefaultGuard) {
	LOG_TRACER_INIT.call_once(|| {
		let _ = tracing_log::LogTracer::init();
	});
	let (capture, subscriber) =
		sp_tracing::test_log_capture::init_log_capture(tracing::Level::TRACE, false);
	let guard = tracing::subscriber::set_default(subscriber);
	(capture, guard)
}


#[tokio::test]
async fn import_rejects_blob_failing_multihash_verify() {
	let (capture, _guard) = install_log_capture();
	let h = make_harness(HarnessMode::Commit);
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
	assert!(
		msg.contains("bitswap fetch"),
		"unexpected error message: {msg}",
	);
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
