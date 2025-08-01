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

use std::{
	collections::{BTreeMap, HashMap},
	sync::{
		atomic::{AtomicU64, Ordering as AtomicOrdering},
		Arc,
	},
	time::Duration,
};

use assert_matches::assert_matches;
use futures::{
	channel::oneshot,
	future::{self, BoxFuture},
};

use polkadot_node_subsystem_util::database::Database;

use polkadot_node_primitives::{
	DisputeMessage, DisputeStatus, SignedDisputeStatement, SignedFullStatement, Statement,
	DISPUTE_WINDOW,
};
use polkadot_node_subsystem::{
	messages::{
		ApprovalVotingParallelMessage, ChainApiMessage, ChainSelectionMessage,
		DisputeCoordinatorMessage, DisputeDistributionMessage, ImportStatementsResult,
	},
	overseer::FromOrchestra,
	OverseerSignal,
};

use polkadot_node_subsystem_util::TimeoutExt;
use sc_keystore::LocalKeystore;
use sp_application_crypto::AppCrypto;
use sp_core::{sr25519::Pair, testing::TaskExecutor, Pair as PairT};
use sp_keyring::Sr25519Keyring;
use sp_keystore::{Keystore, KeystorePtr};

use polkadot_node_primitives::{Timestamp, ACTIVE_DURATION_SECS};
use polkadot_node_subsystem::{
	messages::{AllMessages, BlockDescription, RuntimeApiMessage, RuntimeApiRequest},
	ActiveLeavesUpdate,
};
use polkadot_node_subsystem_test_helpers::{
	make_buffered_subsystem_context, mock::new_leaf, TestSubsystemContextHandle,
};
use polkadot_primitives::{
	vstaging::{
		CandidateEvent, CandidateReceiptV2 as CandidateReceipt, MutateDescriptorV2,
		ScrapedOnChainVotes,
	},
	ApprovalVote, BlockNumber, CandidateCommitments, CandidateHash, CoreIndex, DisputeStatement,
	ExecutorParams, GroupIndex, Hash, HeadData, Header, IndexedVec, MultiDisputeStatementSet,
	NodeFeatures, SessionIndex, SessionInfo, SigningContext, ValidDisputeStatementKind,
	ValidatorId, ValidatorIndex, ValidatorSignature,
};
use polkadot_primitives_test_helpers::{
	dummy_candidate_receipt_v2_bad_sig, dummy_digest, dummy_hash,
};

use crate::{
	backend::Backend,
	metrics::Metrics,
	participation::{participation_full_happy_path, participation_missing_availability},
	status::Clock,
	Config, DisputeCoordinatorSubsystem,
};

use super::db::v1::DbBackend;

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

// sets up a keystore with the given keyring accounts.
fn make_keystore(seeds: impl Iterator<Item = String>) -> LocalKeystore {
	let store = LocalKeystore::in_memory();

	for s in seeds {
		store
			.sr25519_generate_new(polkadot_primitives::PARACHAIN_KEY_TYPE_ID, Some(&s))
			.unwrap();
	}

	store
}

type VirtualOverseer = TestSubsystemContextHandle<DisputeCoordinatorMessage>;

const OVERSEER_RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);

async fn overseer_recv(virtual_overseer: &mut VirtualOverseer) -> AllMessages {
	virtual_overseer
		.recv()
		.timeout(OVERSEER_RECEIVE_TIMEOUT)
		.await
		.expect("overseer `recv` timed out")
}

enum VoteType {
	Backing,
	Explicit,
}

/// Helper to condense repeated code that creates vote pairs, one valid and one
/// invalid. Optionally the valid vote of the pair can be made a backing vote.
async fn generate_opposing_votes_pair(
	test_state: &TestState,
	valid_voter_idx: ValidatorIndex,
	invalid_voter_idx: ValidatorIndex,
	candidate_hash: CandidateHash,
	session: SessionIndex,
	valid_vote_type: VoteType,
) -> (SignedDisputeStatement, SignedDisputeStatement) {
	let valid_vote = match valid_vote_type {
		VoteType::Backing =>
			test_state.issue_backing_statement_with_index(valid_voter_idx, candidate_hash, session),
		VoteType::Explicit => test_state.issue_explicit_statement_with_index(
			valid_voter_idx,
			candidate_hash,
			session,
			true,
		),
	};
	let invalid_vote = test_state.issue_explicit_statement_with_index(
		invalid_voter_idx,
		candidate_hash,
		session,
		false,
	);

	(valid_vote, invalid_vote)
}

#[derive(Clone)]
struct MockClock {
	time: Arc<AtomicU64>,
}

impl Default for MockClock {
	fn default() -> Self {
		MockClock { time: Arc::new(AtomicU64::default()) }
	}
}

impl Clock for MockClock {
	fn now(&self) -> Timestamp {
		self.time.load(AtomicOrdering::SeqCst)
	}
}

impl MockClock {
	fn set(&self, to: Timestamp) {
		self.time.store(to, AtomicOrdering::SeqCst)
	}
}

struct TestState {
	validators: Vec<Pair>,
	validator_public: IndexedVec<ValidatorIndex, ValidatorId>,
	validator_groups: IndexedVec<GroupIndex, Vec<ValidatorIndex>>,
	master_keystore: Arc<sc_keystore::LocalKeystore>,
	subsystem_keystore: Arc<sc_keystore::LocalKeystore>,
	db: Arc<dyn Database>,
	config: Config,
	clock: MockClock,
	headers: HashMap<Hash, Header>,
	block_num_to_header: HashMap<BlockNumber, Hash>,
	last_block: Hash,
	// last session the subsystem knows about.
	known_session: Option<SessionIndex>,
}

impl Default for TestState {
	fn default() -> TestState {
		let p1 = Pair::from_string("//Polka", None).unwrap();
		let p2 = Pair::from_string("//Dot", None).unwrap();
		let p3 = Pair::from_string("//Kusama", None).unwrap();
		let validators = vec![
			(Sr25519Keyring::Alice.pair(), Sr25519Keyring::Alice.to_seed()),
			(Sr25519Keyring::Bob.pair(), Sr25519Keyring::Bob.to_seed()),
			(Sr25519Keyring::Charlie.pair(), Sr25519Keyring::Charlie.to_seed()),
			(Sr25519Keyring::Dave.pair(), Sr25519Keyring::Dave.to_seed()),
			(Sr25519Keyring::Eve.pair(), Sr25519Keyring::Eve.to_seed()),
			(Sr25519Keyring::One.pair(), Sr25519Keyring::One.to_seed()),
			(Sr25519Keyring::Ferdie.pair(), Sr25519Keyring::Ferdie.to_seed()),
			// Two more keys needed so disputes are not confirmed already with only 3 statements.
			(p1, "//Polka".into()),
			(p2, "//Dot".into()),
			(p3, "//Kusama".into()),
		];

		let validator_public = validators
			.clone()
			.into_iter()
			.map(|k| ValidatorId::from(k.0.public()))
			.collect();

		let validator_groups = IndexedVec::<GroupIndex, Vec<ValidatorIndex>>::from(vec![
			vec![ValidatorIndex(0), ValidatorIndex(1)],
			vec![ValidatorIndex(2), ValidatorIndex(3)],
			vec![ValidatorIndex(4), ValidatorIndex(5), ValidatorIndex(6)],
		]);

		let master_keystore = make_keystore(validators.iter().map(|v| v.1.clone())).into();
		let subsystem_keystore =
			make_keystore(vec![Sr25519Keyring::Alice.to_seed()].into_iter()).into();

		let db = kvdb_memorydb::create(1);
		let db = polkadot_node_subsystem_util::database::kvdb_impl::DbAdapter::new(db, &[0]);
		let db = Arc::new(db);
		let config = Config { col_dispute_data: 0 };

		let genesis_header = Header {
			parent_hash: Hash::zero(),
			number: 0,
			digest: dummy_digest(),
			state_root: dummy_hash(),
			extrinsics_root: dummy_hash(),
		};
		let last_block = genesis_header.hash();

		let mut headers = HashMap::new();
		let _ = headers.insert(last_block, genesis_header.clone());
		let mut block_num_to_header = HashMap::new();
		let _ = block_num_to_header.insert(genesis_header.number, last_block);

		TestState {
			validators: validators.into_iter().map(|(pair, _)| pair).collect(),
			validator_public,
			validator_groups,
			master_keystore,
			subsystem_keystore,
			db,
			config,
			clock: MockClock::default(),
			headers,
			block_num_to_header,
			last_block,
			known_session: None,
		}
	}
}

impl TestState {
	async fn activate_leaf_at_session(
		&mut self,
		virtual_overseer: &mut VirtualOverseer,
		session: SessionIndex,
		block_number: BlockNumber,
		candidate_events: Vec<CandidateEvent>,
	) -> Hash {
		assert!(block_number > 0);

		let block_header = Header {
			parent_hash: self.last_block,
			number: block_number,
			digest: dummy_digest(),
			state_root: dummy_hash(),
			extrinsics_root: dummy_hash(),
		};
		let block_hash = block_header.hash();

		let _ = self.headers.insert(block_hash, block_header.clone());
		let _ = self.block_num_to_header.insert(block_header.number, block_hash);
		self.last_block = block_hash;

		gum::debug!(?block_number, "Activating block in activate_leaf_at_session.");
		virtual_overseer
			.send(FromOrchestra::Signal(OverseerSignal::ActiveLeaves(
				ActiveLeavesUpdate::start_work(new_leaf(block_hash, block_number)),
			)))
			.await;

		self.handle_sync_queries(virtual_overseer, block_hash, session, candidate_events)
			.await;

		block_hash
	}

	/// Returns any sent `DisputeMessage`s.
	async fn handle_sync_queries(
		&mut self,
		virtual_overseer: &mut VirtualOverseer,
		block_hash: Hash,
		session: SessionIndex,
		candidate_events: Vec<CandidateEvent>,
	) -> Vec<DisputeMessage> {
		// Order of messages is not fixed (different on initializing):
		#[derive(Debug)]
		struct FinishedSteps {
			got_session_information: bool,
			got_scraping_information: bool,
		}

		impl FinishedSteps {
			fn new() -> Self {
				Self { got_session_information: false, got_scraping_information: false }
			}
			fn is_done(&self) -> bool {
				self.got_session_information && self.got_scraping_information
			}
		}

		let mut finished_steps = FinishedSteps::new();
		let mut sent_disputes = Vec::new();

		while !finished_steps.is_done() {
			let recv = overseer_recv(virtual_overseer).await;
			match recv {
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					h,
					RuntimeApiRequest::SessionIndexForChild(tx),
				)) => {
					assert!(
						!finished_steps.got_session_information,
						"session infos already retrieved"
					);
					finished_steps.got_session_information = true;
					assert_eq!(h, block_hash);
					let _ = tx.send(Ok(session));

					let first_expected_session = session.saturating_sub(DISPUTE_WINDOW.get() - 1);

					// Queries for session caching - see `handle_startup`
					if self.known_session.is_none() {
						for i in first_expected_session..=session {
							assert_matches!(
								overseer_recv(virtual_overseer).await,
								AllMessages::RuntimeApi(RuntimeApiMessage::Request(
									h,
									RuntimeApiRequest::SessionInfo(session_index, tx),
								)) => {
									assert_eq!(h, block_hash);
									assert_eq!(session_index, i);
									let _ = tx.send(Ok(Some(self.session_info())));
								}
							);
							assert_matches!(
								overseer_recv(virtual_overseer).await,
								AllMessages::RuntimeApi(RuntimeApiMessage::Request(
									h,
									RuntimeApiRequest::SessionExecutorParams(session_index, tx),
								)) => {
									assert_eq!(h, block_hash);
									assert_eq!(session_index, i);
									let _ = tx.send(Ok(Some(ExecutorParams::default())));
								}
							);

							assert_matches!(
								overseer_recv(virtual_overseer).await,
								AllMessages::RuntimeApi(
									RuntimeApiMessage::Request(_, RuntimeApiRequest::NodeFeatures(_, si_tx), )
								) => {
									si_tx.send(Ok(NodeFeatures::EMPTY)).unwrap();
								}
							);
						}
					}

					self.known_session = Some(session);
				},
				AllMessages::ChainApi(ChainApiMessage::FinalizedBlockNumber(tx)) => {
					assert!(
						!finished_steps.got_scraping_information,
						"Scraping info was already retrieved!"
					);
					finished_steps.got_scraping_information = true;
					tx.send(Ok(0)).unwrap();
				},
				AllMessages::ChainApi(ChainApiMessage::BlockNumber(hash, tx)) => {
					let block_num = self.headers.get(&hash).map(|header| header.number);
					tx.send(Ok(block_num)).unwrap();
				},
				AllMessages::DisputeDistribution(DisputeDistributionMessage::SendDispute(msg)) => {
					sent_disputes.push(msg);
				},
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					_new_leaf,
					RuntimeApiRequest::CandidateEvents(tx),
				)) => {
					tx.send(Ok(candidate_events.clone())).unwrap();
				},
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					_new_leaf,
					RuntimeApiRequest::FetchOnChainVotes(tx),
				)) => {
					//add some `BackedCandidates` or resolved disputes here as needed
					tx.send(Ok(Some(ScrapedOnChainVotes {
						session,
						backing_validators_per_candidate: Vec::default(),
						disputes: MultiDisputeStatementSet::default(),
					})))
					.unwrap();
				},
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					_new_leaf,
					RuntimeApiRequest::UnappliedSlashes(tx),
				)) => {
					tx.send(Ok(Vec::new())).unwrap();
				},
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					_new_leaf,
					RuntimeApiRequest::DisabledValidators(tx),
				)) => {
					tx.send(Ok(Vec::new())).unwrap();
				},
				AllMessages::ChainApi(ChainApiMessage::Ancestors { hash, k, response_channel }) => {
					let target_header = self
						.headers
						.get(&hash)
						.expect("The function is called for this block so it should exist");
					let mut response = Vec::new();
					for i in target_header.number.saturating_sub(k as u32)..target_header.number {
						response.push(
							*self
								.block_num_to_header
								.get(&i)
								.expect("headers and block_num_to_header should always be in sync"),
						);
					}
					let _ = response_channel.send(Ok(response));
				},
				msg => {
					panic!("Received unexpected message in `handle_sync_queries`: {:?}", msg);
				},
			}
		}
		return sent_disputes
	}

	async fn handle_resume_sync(
		&mut self,
		virtual_overseer: &mut VirtualOverseer,
		session: SessionIndex,
	) -> Vec<DisputeMessage> {
		self.handle_resume_sync_with_events(virtual_overseer, session, Vec::new()).await
	}

	async fn handle_resume_sync_with_events(
		&mut self,
		virtual_overseer: &mut VirtualOverseer,
		session: SessionIndex,
		mut initial_events: Vec<CandidateEvent>,
	) -> Vec<DisputeMessage> {
		let leaves: Vec<Hash> = self.headers.keys().cloned().collect();
		let mut messages = Vec::new();
		for (n, leaf) in leaves.iter().enumerate() {
			gum::debug!(
				block_number= ?n,
				"Activating block in handle resume sync."
			);
			virtual_overseer
				.send(FromOrchestra::Signal(OverseerSignal::ActiveLeaves(
					ActiveLeavesUpdate::start_work(new_leaf(*leaf, n as u32)),
				)))
				.await;

			let events = if n == 1 { std::mem::take(&mut initial_events) } else { Vec::new() };

			let mut new_messages =
				self.handle_sync_queries(virtual_overseer, *leaf, session, events).await;
			messages.append(&mut new_messages);
		}
		messages
	}

	fn session_info(&self) -> SessionInfo {
		let discovery_keys = self.validators.iter().map(|k| <_>::from(k.public())).collect();

		let assignment_keys = self.validators.iter().map(|k| <_>::from(k.public())).collect();

		SessionInfo {
			validators: self.validator_public.clone(),
			discovery_keys,
			assignment_keys,
			validator_groups: self.validator_groups.clone(),
			n_cores: self.validator_groups.len() as _,
			zeroth_delay_tranche_width: 0,
			relay_vrf_modulo_samples: 1,
			n_delay_tranches: 100,
			no_show_slots: 1,
			needed_approvals: 10,
			active_validator_indices: Vec::new(),
			dispute_period: 6,
			random_seed: [0u8; 32],
		}
	}

	fn issue_explicit_statement_with_index(
		&self,
		index: ValidatorIndex,
		candidate_hash: CandidateHash,
		session: SessionIndex,
		valid: bool,
	) -> SignedDisputeStatement {
		let public = self.validator_public.get(index).unwrap().clone();

		let keystore = self.master_keystore.clone() as KeystorePtr;

		SignedDisputeStatement::sign_explicit(&keystore, valid, candidate_hash, session, public)
			.unwrap()
			.unwrap()
	}

	fn issue_backing_statement_with_index(
		&self,
		index: ValidatorIndex,
		candidate_hash: CandidateHash,
		session: SessionIndex,
	) -> SignedDisputeStatement {
		let keystore = self.master_keystore.clone() as KeystorePtr;
		let validator_id = self.validators[index.0 as usize].public().into();
		let context =
			SigningContext { session_index: session, parent_hash: Hash::repeat_byte(0xac) };

		let statement = SignedFullStatement::sign(
			&keystore,
			Statement::Valid(candidate_hash),
			&context,
			index,
			&validator_id,
		)
		.unwrap()
		.unwrap()
		.into_unchecked();

		SignedDisputeStatement::from_backing_statement(&statement, context, validator_id).unwrap()
	}

	fn issue_approval_vote_with_index(
		&self,
		index: ValidatorIndex,
		candidate_hash: CandidateHash,
		session: SessionIndex,
	) -> SignedDisputeStatement {
		let keystore = self.master_keystore.clone() as KeystorePtr;
		let validator_id = self.validators[index.0 as usize].public();

		let payload = ApprovalVote(candidate_hash).signing_payload(session);
		let signature = keystore
			.sr25519_sign(ValidatorId::ID, &validator_id, &payload)
			.ok()
			.flatten()
			.unwrap();

		SignedDisputeStatement::new_unchecked_from_trusted_source(
			DisputeStatement::Valid(ValidDisputeStatementKind::ApprovalChecking),
			candidate_hash,
			session,
			validator_id.into(),
			signature.into(),
		)
	}

	fn resume<F>(mut self, test: F) -> Self
	where
		F: FnOnce(TestState, VirtualOverseer) -> BoxFuture<'static, TestState>,
	{
		self.known_session = None;
		let (ctx, ctx_handle) = make_buffered_subsystem_context(TaskExecutor::new(), 1);
		let subsystem = DisputeCoordinatorSubsystem::new(
			self.db.clone(),
			self.config,
			self.subsystem_keystore.clone(),
			Metrics::default(),
		);
		let backend =
			DbBackend::new(self.db.clone(), self.config.column_config(), Metrics::default());
		let subsystem_task = subsystem.run(ctx, backend, Box::new(self.clock.clone()));
		let test_task = test(self, ctx_handle);

		let (_, state) = futures::executor::block_on(future::join(subsystem_task, test_task));
		state
	}
}

fn test_harness<F>(test: F) -> TestState
where
	F: FnOnce(TestState, VirtualOverseer) -> BoxFuture<'static, TestState>,
{
	let mut test_state = TestState::default();

	// Add two more blocks after the genesis (which is created in `default()`)
	let h1 = Header {
		parent_hash: test_state.last_block,
		number: 1,
		digest: dummy_digest(),
		state_root: dummy_hash(),
		extrinsics_root: dummy_hash(),
	};
	let h1_hash = h1.hash();
	test_state.headers.insert(h1_hash, h1);
	test_state.block_num_to_header.insert(1, h1_hash);
	test_state.last_block = h1_hash;

	let h2 = Header {
		parent_hash: test_state.last_block,
		number: 2,
		digest: dummy_digest(),
		state_root: dummy_hash(),
		extrinsics_root: dummy_hash(),
	};
	let h2_hash = h2.hash();
	test_state.headers.insert(h2_hash, h2);
	test_state.block_num_to_header.insert(2, h2_hash);
	test_state.last_block = h2_hash;

	test_state.resume(test)
}

/// Handle participation messages.
async fn participation_with_distribution(
	virtual_overseer: &mut VirtualOverseer,
	candidate_hash: &CandidateHash,
	expected_commitments_hash: Hash,
) {
	participation_full_happy_path(virtual_overseer, expected_commitments_hash).await;
	assert_matches!(
		overseer_recv(virtual_overseer).await,
		AllMessages::DisputeDistribution(
			DisputeDistributionMessage::SendDispute(msg)
		) => {
			assert_eq!(&msg.candidate_receipt().hash(), candidate_hash);
		}
	);
}

fn make_valid_candidate_receipt() -> CandidateReceipt {
	make_another_valid_candidate_receipt(dummy_hash())
}

fn make_invalid_candidate_receipt() -> CandidateReceipt {
	dummy_candidate_receipt_v2_bad_sig(Default::default(), Some(Default::default()))
}

fn make_another_valid_candidate_receipt(relay_parent: Hash) -> CandidateReceipt {
	let mut candidate_receipt = dummy_candidate_receipt_v2_bad_sig(relay_parent, dummy_hash());
	candidate_receipt.commitments_hash = CandidateCommitments::default().hash();
	candidate_receipt
}

// Generate a `CandidateBacked` event from a `CandidateReceipt`. The rest is dummy data.
fn make_candidate_backed_event(candidate_receipt: CandidateReceipt) -> CandidateEvent {
	CandidateEvent::CandidateBacked(
		candidate_receipt,
		HeadData(Vec::new()),
		CoreIndex(0),
		GroupIndex(0),
	)
}

// Generate a `CandidateIncluded` event from a `CandidateReceipt`. The rest is dummy data.
fn make_candidate_included_event(candidate_receipt: CandidateReceipt) -> CandidateEvent {
	CandidateEvent::CandidateIncluded(
		candidate_receipt,
		HeadData(Vec::new()),
		CoreIndex(0),
		GroupIndex(0),
	)
}

/// Handle request for approval votes:
pub async fn handle_approval_vote_request(
	ctx_handle: &mut VirtualOverseer,
	expected_hash: &CandidateHash,
	votes_to_send: HashMap<ValidatorIndex, (Vec<CandidateHash>, ValidatorSignature)>,
) {
	assert_matches!(
		ctx_handle.recv().await,
		AllMessages::ApprovalVotingParallel(
			ApprovalVotingParallelMessage::GetApprovalSignaturesForCandidate(hash, tx)
		) => {
			assert_eq!(&hash, expected_hash);
			tx.send(votes_to_send).unwrap();
		},
		"overseer did not receive `GetApprovalSignaturesForCandidate` message.",
	);
}

/// Handle block number request. In the context of these tests this message is required for
/// handling comparator creation for enqueuing participations.
async fn handle_get_block_number(ctx_handle: &mut VirtualOverseer, test_state: &TestState) {
	assert_matches!(
		ctx_handle.recv().await,
		AllMessages::ChainApi(
		ChainApiMessage::BlockNumber(hash, tx)) => {
			tx.send(Ok(test_state.headers.get(&hash).map(|r| r.number))).unwrap();
		}
	)
}

#[test]
fn too_many_unconfirmed_statements_are_considered_spam() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt1 = make_valid_candidate_receipt();
			let candidate_hash1 = candidate_receipt1.hash();
			let candidate_receipt2 = make_invalid_candidate_receipt();
			let candidate_hash2 = candidate_receipt2.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let (valid_vote1, invalid_vote1) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash1,
				session,
				VoteType::Backing,
			)
			.await;

			let (valid_vote2, invalid_vote2) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash2,
				session,
				VoteType::Backing,
			)
			.await;

			gum::trace!("Before sending `ImportStatements`");
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt1.clone(),
						session,
						statements: vec![
							(valid_vote1, ValidatorIndex(3)),
							(invalid_vote1, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			gum::trace!("After sending `ImportStatements`");

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash1, HashMap::new())
				.await;

			// Participation has to fail here, otherwise the dispute will be confirmed. However
			// participation won't happen at all because the dispute is neither backed, not
			// confirmed nor the candidate is included. Or in other words - we'll refrain from
			// participation.

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;
				assert_eq!(
					rx.await.unwrap(),
					BTreeMap::from([((session, candidate_hash1), DisputeStatus::Active)])
				);

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash1)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 1);
				assert_eq!(votes.invalid.len(), 1);
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt2.clone(),
						session,
						statements: vec![
							(valid_vote2, ValidatorIndex(3)),
							(invalid_vote2, ValidatorIndex(1)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;

			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash2, HashMap::new())
				.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash2)],
							tx,
						),
					})
					.await;

				assert_matches!(rx.await.unwrap().get(0), None);
			}

			// Result should be invalid, because it should be considered spam.
			assert_matches!(confirmation_rx.await, Ok(ImportStatementsResult::InvalidImport));

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// No more messages expected:
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn approval_vote_import_works() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt1 = make_valid_candidate_receipt();
			let candidate_hash1 = candidate_receipt1.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let (valid_vote1, invalid_vote1) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash1,
				session,
				VoteType::Backing,
			)
			.await;

			let approval_vote = test_state.issue_approval_vote_with_index(
				ValidatorIndex(4),
				candidate_hash1,
				session,
			);

			gum::trace!("Before sending `ImportStatements`");
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt1.clone(),
						session,
						statements: vec![
							(valid_vote1, ValidatorIndex(3)),
							(invalid_vote1, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			gum::trace!("After sending `ImportStatements`");

			let approval_votes = [(
				ValidatorIndex(4),
				(vec![candidate_receipt1.hash()], approval_vote.into_validator_signature()),
			)]
			.into_iter()
			.collect();

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash1, approval_votes)
				.await;

			// Participation won't happen here because the dispute is neither backed, not confirmed
			// nor the candidate is included. Or in other words - we'll refrain from participation.

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(
					rx.await.unwrap(),
					BTreeMap::from([((session, candidate_hash1), DisputeStatus::Active)])
				);

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash1)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert!(
					votes.valid.raw().get(&ValidatorIndex(4)).is_some(),
					"Approval vote is missing!"
				);
				assert_eq!(votes.invalid.len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// No more messages expected:
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn dispute_gets_confirmed_via_participation() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt1 = make_valid_candidate_receipt();
			let candidate_hash1 = candidate_receipt1.hash();
			let candidate_receipt2 = make_invalid_candidate_receipt();
			let candidate_hash2 = candidate_receipt2.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![
						make_candidate_backed_event(candidate_receipt1.clone()),
						make_candidate_backed_event(candidate_receipt2.clone()),
					],
				)
				.await;

			let (valid_vote1, invalid_vote1) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash1,
				session,
				VoteType::Explicit,
			)
			.await;

			let (valid_vote2, invalid_vote2) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash2,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt1.clone(),
						session,
						statements: vec![
							(valid_vote1, ValidatorIndex(3)),
							(invalid_vote1, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			gum::debug!("After First import!");
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash1, HashMap::new())
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash1,
				candidate_receipt1.commitments_hash,
			)
			.await;
			gum::debug!("After Participation!");

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(
					rx.await.unwrap(),
					BTreeMap::from([((session, candidate_hash1), DisputeStatus::Active)])
				);

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash1)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert_eq!(votes.invalid.len(), 1);
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt2.clone(),
						session,
						statements: vec![
							(valid_vote2, ValidatorIndex(3)),
							(invalid_vote2, ValidatorIndex(1)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash2, HashMap::new())
				.await;

			participation_missing_availability(&mut virtual_overseer).await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash2)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 1);
				assert_eq!(votes.invalid.len(), 1);
			}

			// Result should be valid, because our node participated, so spam slots are cleared:
			assert_matches!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// No more messages expected:
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn dispute_gets_confirmed_at_byzantine_threshold() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt1 = make_valid_candidate_receipt();
			let candidate_hash1 = candidate_receipt1.hash();
			let candidate_receipt2 = make_invalid_candidate_receipt();
			let candidate_hash2 = candidate_receipt2.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let (valid_vote1, invalid_vote1) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash1,
				session,
				VoteType::Explicit,
			)
			.await;

			let (valid_vote1a, invalid_vote1a) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(4),
				ValidatorIndex(5),
				candidate_hash1,
				session,
				VoteType::Explicit,
			)
			.await;

			let (valid_vote2, invalid_vote2) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash2,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt1.clone(),
						session,
						statements: vec![
							(valid_vote1, ValidatorIndex(3)),
							(invalid_vote1, ValidatorIndex(1)),
							(valid_vote1a, ValidatorIndex(4)),
							(invalid_vote1a, ValidatorIndex(5)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash1, HashMap::new())
				.await;

			// Participation won't happen here because the dispute is neither backed, not confirmed
			// nor the candidate is included. Or in other words - we'll refrain from participation.

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(
					rx.await.unwrap(),
					BTreeMap::from([((session, candidate_hash1), DisputeStatus::Confirmed)])
				);

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash1)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert_eq!(votes.invalid.len(), 2);
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt2.clone(),
						session,
						statements: vec![
							(valid_vote2, ValidatorIndex(3)),
							(invalid_vote2, ValidatorIndex(1)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash2, HashMap::new())
				.await;

			participation_missing_availability(&mut virtual_overseer).await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash2)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 1);
				assert_eq!(votes.invalid.len(), 1);
			}

			// Result should be valid, because byzantine threshold has been reached in first
			// import, so spam slots are cleared:
			assert_matches!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// No more messages expected:
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn backing_statements_import_works_and_no_spam() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let valid_vote1 = test_state.issue_backing_statement_with_index(
				ValidatorIndex(3),
				candidate_hash,
				session,
			);

			let valid_vote2 = test_state.issue_backing_statement_with_index(
				ValidatorIndex(4),
				candidate_hash,
				session,
			);

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote1, ValidatorIndex(3)),
							(valid_vote2, ValidatorIndex(4)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			assert_matches!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			{
				// Just backing votes - we should not have any active disputes now.
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert_eq!(votes.invalid.len(), 0);
			}

			let candidate_receipt = make_invalid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			let valid_vote1 = test_state.issue_backing_statement_with_index(
				ValidatorIndex(3),
				candidate_hash,
				session,
			);

			let valid_vote2 = test_state.issue_backing_statement_with_index(
				ValidatorIndex(4),
				candidate_hash,
				session,
			);

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			// Backing vote import should not have accounted to spam slots, so this should succeed
			// as well:
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote1, ValidatorIndex(3)),
							(valid_vote2, ValidatorIndex(4)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;

			// Import should be valid, as spam slots were not filled
			assert_matches!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// No more messages expected:
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn conflicting_votes_lead_to_dispute_participation() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			let invalid_vote_2 = test_state.issue_explicit_statement_with_index(
				ValidatorIndex(2),
				candidate_hash,
				session,
				false,
			);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(3)),
							(invalid_vote, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(
					rx.await.unwrap(),
					BTreeMap::from([((session, candidate_hash), DisputeStatus::Active)])
				);

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert_eq!(votes.invalid.len(), 1);
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(invalid_vote_2, ValidatorIndex(2))],
						pending_confirmation: None,
					},
				})
				.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert_eq!(votes.invalid.len(), 2);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// This confirms that the second vote doesn't lead to participation again.
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn positive_votes_dont_trigger_participation() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let valid_vote = test_state.issue_explicit_statement_with_index(
				ValidatorIndex(2),
				candidate_hash,
				session,
				true,
			);

			let valid_vote_2 = test_state.issue_explicit_statement_with_index(
				ValidatorIndex(1),
				candidate_hash,
				session,
				true,
			);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(valid_vote, ValidatorIndex(2))],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 1);
				assert!(votes.invalid.is_empty());
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(valid_vote_2, ValidatorIndex(1))],
						pending_confirmation: None,
					},
				})
				.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2);
				assert!(votes.invalid.is_empty());
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// This confirms that no participation request is made.
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn wrong_validator_index_is_ignored() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				assert_matches!(rx.await.unwrap().get(0), None);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// This confirms that no participation request is made.
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn finality_votes_ignore_disputed_candidates() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(2)),
							(invalid_vote, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();

				let base_block = Hash::repeat_byte(0x0f);
				let block_hash_a = Hash::repeat_byte(0x0a);
				let block_hash_b = Hash::repeat_byte(0x0b);

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::DetermineUndisputedChain {
							base: (10, base_block),
							block_descriptions: vec![BlockDescription {
								block_hash: block_hash_a,
								session,
								candidates: vec![candidate_hash],
							}],
							tx,
						},
					})
					.await;

				assert_eq!(rx.await.unwrap(), (10, base_block));

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::DetermineUndisputedChain {
							base: (10, base_block),
							block_descriptions: vec![
								BlockDescription {
									block_hash: block_hash_a,
									session,
									candidates: vec![],
								},
								BlockDescription {
									block_hash: block_hash_b,
									session,
									candidates: vec![candidate_hash],
								},
							],
							tx,
						},
					})
					.await;

				assert_eq!(rx.await.unwrap(), (11, block_hash_a));
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn supermajority_valid_dispute_may_be_finalized() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();
			let candidate_events = vec![make_candidate_backed_event(candidate_receipt.clone())];

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, candidate_events)
				.await;

			let supermajority_threshold =
				polkadot_primitives::supermajority_threshold(test_state.validators.len());

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(2)),
							(invalid_vote, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			let mut statements = Vec::new();
			for i in (0_u32..supermajority_threshold as u32 - 1).map(|i| i + 3) {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation: None,
					},
				})
				.await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			{
				let (tx, rx) = oneshot::channel();

				let base_hash = Hash::repeat_byte(0x0f);
				let block_hash_a = Hash::repeat_byte(0x0a);
				let block_hash_b = Hash::repeat_byte(0x0b);

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::DetermineUndisputedChain {
							base: (10, base_hash),
							block_descriptions: vec![BlockDescription {
								block_hash: block_hash_a,
								session,
								candidates: vec![candidate_hash],
							}],
							tx,
						},
					})
					.await;

				assert_eq!(rx.await.unwrap(), (11, block_hash_a));

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::DetermineUndisputedChain {
							base: (10, base_hash),
							block_descriptions: vec![
								BlockDescription {
									block_hash: block_hash_a,
									session,
									candidates: vec![],
								},
								BlockDescription {
									block_hash: block_hash_b,
									session,
									candidates: vec![candidate_hash],
								},
							],
							tx,
						},
					})
					.await;

				assert_eq!(rx.await.unwrap(), (12, block_hash_b));
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn concluded_supermajority_for_non_active_after_time() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let supermajority_threshold =
				polkadot_primitives::supermajority_threshold(test_state.validators.len());

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(2)),
							(invalid_vote, ValidatorIndex(1)),
						],
						pending_confirmation: None,
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			let mut statements = Vec::new();
			// -2: 1 for already imported vote and one for local vote (which is valid).
			for i in (0_u32..supermajority_threshold as u32 - 2).map(|i| i + 3) {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation: None,
					},
				})
				.await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			test_state.clock.set(ACTIVE_DURATION_SECS + 1);

			{
				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());

				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::RecentDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn concluded_supermajority_against_non_active_after_time() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_invalid_candidate_receipt();

			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let supermajority_threshold =
				polkadot_primitives::supermajority_threshold(test_state.validators.len());

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(2)),
							(invalid_vote, ValidatorIndex(1)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;
			assert_matches!(confirmation_rx.await.unwrap(),
				ImportStatementsResult::ValidImport => {}
			);

			// Use a different expected commitments hash to ensure the candidate validation returns
			// invalid.
			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				CandidateCommitments::default().hash(),
			)
			.await;

			let mut statements = Vec::new();
			// minus 2, because of local vote and one previously imported invalid vote.
			for i in (0_u32..supermajority_threshold as u32 - 2).map(|i| i + 3) {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					false,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation: None,
					},
				})
				.await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			test_state.clock.set(ACTIVE_DURATION_SECS + 1);

			{
				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());
				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::RecentDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert_matches!(
				virtual_overseer.try_recv().await,
				None => {}
			);

			test_state
		})
	});
}

#[test]
fn resume_dispute_without_local_statement() {
	sp_tracing::init_for_tests();
	let session = 1;

	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			// Participation won't happen here because the dispute is neither backed, not confirmed
			// nor the candidate is included. Or in other words - we'll refrain from participation.
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			{
				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	})
	// Alice should send a DisputeParticipationMessage::Participate on restart since she has no
	// local statement for the active dispute.
	.resume(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let candidate_receipt = make_valid_candidate_receipt();
			// Candidate is now backed:
			let dispute_messages = test_state
				.handle_resume_sync_with_events(
					&mut virtual_overseer,
					session,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			assert_eq!(dispute_messages.len(), 0, "We don't expect any messages sent here.");

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			participation_full_happy_path(
				&mut virtual_overseer,
				candidate_receipt.commitments_hash,
			)
			.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;

			assert_matches!(
				virtual_overseer.recv().await,
				AllMessages::DisputeDistribution(
					DisputeDistributionMessage::SendDispute(msg)
				) => {
					assert_eq!(msg.candidate_receipt().hash(), candidate_hash);
				}
			);

			let mut statements = Vec::new();
			// Getting votes for supermajority. Should already have two valid votes.
			for i in vec![3, 4, 5, 6, 7] {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation: None,
					},
				})
				.await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			// Advance the clock far enough so that the concluded dispute will be omitted from an
			// ActiveDisputes query.
			test_state.clock.set(test_state.clock.now() + ACTIVE_DURATION_SECS + 1);

			{
				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert!(rx.await.unwrap().is_empty());
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn resume_dispute_with_local_statement() {
	sp_tracing::init_for_tests();
	let session = 1;

	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let local_valid_vote = test_state.issue_explicit_statement_with_index(
				ValidatorIndex(0),
				candidate_hash,
				session,
				true,
			);

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(local_valid_vote, ValidatorIndex(0)),
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			{
				let (tx, rx) = oneshot::channel();

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	})
	// Alice should not send a DisputeParticipationMessage::Participate on restart since she has a
	// local statement for the active dispute, instead she should try to (re-)send her vote.
	.resume(|mut test_state, mut virtual_overseer| {
		let candidate_receipt = make_valid_candidate_receipt();
		Box::pin(async move {
			let messages = test_state
				.handle_resume_sync_with_events(
					&mut virtual_overseer,
					session,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			assert_eq!(messages.len(), 1, "A message should have gone out.");

			// Assert that subsystem is not sending Participation messages because we issued a local
			// statement
			assert!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await.is_none());

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn resume_dispute_without_local_statement_or_local_key() {
	let session = 1;
	let mut test_state = TestState::default();
	test_state.subsystem_keystore =
		make_keystore(vec![Sr25519Keyring::Two.to_seed()].into_iter()).into();
	test_state
		.resume(|mut test_state, mut virtual_overseer| {
			Box::pin(async move {
				test_state.handle_resume_sync(&mut virtual_overseer, session).await;

				let candidate_receipt = make_valid_candidate_receipt();
				let candidate_hash = candidate_receipt.hash();

				test_state
					.activate_leaf_at_session(
						&mut virtual_overseer,
						session,
						1,
						vec![make_candidate_included_event(candidate_receipt.clone())],
					)
					.await;

				let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
					&test_state,
					ValidatorIndex(1),
					ValidatorIndex(2),
					candidate_hash,
					session,
					VoteType::Explicit,
				)
				.await;

				let (pending_confirmation, confirmation_rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ImportStatements {
							candidate_receipt: candidate_receipt.clone(),
							session,
							statements: vec![
								(valid_vote, ValidatorIndex(1)),
								(invalid_vote, ValidatorIndex(2)),
							],
							pending_confirmation: Some(pending_confirmation),
						},
					})
					.await;
				handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
				handle_approval_vote_request(
					&mut virtual_overseer,
					&candidate_hash,
					HashMap::new(),
				)
				.await;

				assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

				{
					let (tx, rx) = oneshot::channel();

					virtual_overseer
						.send(FromOrchestra::Communication {
							msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
						})
						.await;

					assert_eq!(rx.await.unwrap().len(), 1);
				}

				virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
				assert_matches!(
					virtual_overseer.try_recv().await,
					None => {}
				);

				test_state
			})
		})
		// Two should not send a DisputeParticipationMessage::Participate on restart since she is no
		// validator in that dispute.
		.resume(|mut test_state, mut virtual_overseer| {
			Box::pin(async move {
				test_state.handle_resume_sync(&mut virtual_overseer, session).await;

				// Assert that subsystem is not sending Participation messages because we issued a
				// local statement
				assert!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await.is_none());

				virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
				assert!(virtual_overseer.try_recv().await.is_none());

				test_state
			})
		});
}

#[test]
fn issue_valid_local_statement_does_cause_distribution_but_not_duplicate_participation() {
	issue_local_statement_does_cause_distribution_but_not_duplicate_participation(true);
}

#[test]
fn issue_invalid_local_statement_does_cause_distribution_but_not_duplicate_participation() {
	issue_local_statement_does_cause_distribution_but_not_duplicate_participation(false);
}

fn issue_local_statement_does_cause_distribution_but_not_duplicate_participation(validity: bool) {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let other_vote = test_state.issue_explicit_statement_with_index(
				ValidatorIndex(1),
				candidate_hash,
				session,
				!validity,
			);

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(other_vote, ValidatorIndex(1))],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// Initiate dispute locally:
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::IssueLocalStatement(
						session,
						candidate_hash,
						candidate_receipt.clone(),
						validity,
					),
				})
				.await;

			// Dispute distribution should get notified now:
			assert_matches!(
				overseer_recv(&mut virtual_overseer).await,
				AllMessages::DisputeDistribution(
					DisputeDistributionMessage::SendDispute(msg)
				) => {
					assert_eq!(msg.session_index(), session);
					assert_eq!(msg.candidate_receipt(), &candidate_receipt);
				}
			);

			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			// Make sure we won't participate:
			assert!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await.is_none());

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn participation_with_onchain_disabling_unconfirmed() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();
			let events = vec![make_candidate_included_event(candidate_receipt.clone())];

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, events)
				.await;

			let backer_index = ValidatorIndex(1);
			let disabled_index = ValidatorIndex(2);

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				backer_index,
				disabled_index,
				candidate_hash,
				session,
				VoteType::Backing,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			// Scenario 1: unconfirmed dispute with onchain disabled validator against.
			// Expectation: we import the vote, but do not participate.
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, backer_index),
							(invalid_vote, disabled_index),
						],
						pending_confirmation,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, vec![disabled_index]).await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// we should not participate due to disabled indices on chain
			assert!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await.is_none());

			{
				// make sure the dispute is not active
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 0);
			}

			// Scenario 2: unconfirmed dispute with non-disabled validator against.
			// Expectation: even if the dispute is unconfirmed, we should participate
			// once we receive an invalid vote from a non-disabled validator.
			let non_disabled_index = ValidatorIndex(3);
			let vote = test_state.issue_explicit_statement_with_index(
				non_disabled_index,
				candidate_hash,
				session,
				false,
			);
			let statements = vec![(vote, non_disabled_index)];

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2); // 1+1 => we have participated
				assert_eq!(votes.invalid.len(), 2);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn participation_with_onchain_disabling_confirmed() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();
			let events = vec![make_candidate_included_event(candidate_receipt.clone())];

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, events)
				.await;

			let backer_index = ValidatorIndex(1);
			let disabled_index = ValidatorIndex(2);

			// Scenario 1: confirmed dispute with disabled validator
			// Expectation: we import the vote and participate.
			let mut statements = Vec::new();

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				backer_index,
				disabled_index,
				candidate_hash,
				session,
				VoteType::Backing,
			)
			.await;

			statements.push((valid_vote, backer_index));
			statements.push((invalid_vote, disabled_index));

			// now import enough votes for dispute confirmation
			for i in vec![3, 4] {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, vec![disabled_index]).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 4); // 3+1 => we have participated
				assert_eq!(votes.invalid.len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn participation_with_offchain_disabling() {
	sp_tracing::init_for_tests();
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();
			let events = vec![make_candidate_included_event(candidate_receipt.clone())];

			let block_hash = test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 3, events)
				.await;

			let another_candidate_receipt = make_another_valid_candidate_receipt(block_hash);
			let another_candidate_hash = another_candidate_receipt.hash();
			let another_events =
				vec![make_candidate_included_event(another_candidate_receipt.clone())];

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 4, another_events)
				.await;

			// import enough votes for supermajority to conclude the dispute
			let mut statements = Vec::new();
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Backing,
			)
			.await;

			statements.push((valid_vote, ValidatorIndex(1)));
			statements.push((invalid_vote, ValidatorIndex(2)));

			for i in vec![3, 4, 5, 6, 7, 8] {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, vec![]).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 8); // 8 => we have participated
				assert_eq!(votes.invalid.len(), 1);
			}

			// now create another dispute
			// Validator 2 should be disabled offchain now

			let mut statements = Vec::new();
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				another_candidate_hash,
				session,
				VoteType::Backing,
			)
			.await;

			statements.push((valid_vote, ValidatorIndex(1)));
			statements.push((invalid_vote, ValidatorIndex(2)));

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: another_candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			// let's disable validators 3, 4 on chain, but this should not affect this import
			let disabled_validators = vec![ValidatorIndex(3), ValidatorIndex(4)];
			handle_disabled_validators_queries(&mut virtual_overseer, disabled_validators).await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// we should not participate since due to offchain disabling
			assert!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await.is_none());

			{
				// make sure the new dispute is not active
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);
			}

			// now import enough votes for dispute confirmation
			// even though all of these votes are from (on chain) disabled validators
			let mut statements = Vec::new();
			for i in vec![3, 4] {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					another_candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: another_candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			handle_approval_vote_request(
				&mut virtual_overseer,
				&another_candidate_hash,
				HashMap::new(),
			)
			.await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&another_candidate_hash,
				another_candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 2);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, another_candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 4); // 3+1 => we have participated
				assert_eq!(votes.invalid.len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

// Once the onchain disabling reaches the byzantine threshold,
// offchain disabling will no longer take any effect.
#[test]
fn participation_with_disabling_limits() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();
			let events = vec![make_candidate_included_event(candidate_receipt.clone())];

			let block_hash = test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 3, events)
				.await;

			let another_candidate_receipt = make_another_valid_candidate_receipt(block_hash);
			let another_candidate_hash = another_candidate_receipt.hash();
			let another_events =
				vec![make_candidate_included_event(another_candidate_receipt.clone())];

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 4, another_events)
				.await;

			// import enough votes for supermajority to conclude the dispute
			let mut statements = Vec::new();
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Backing,
			)
			.await;

			statements.push((valid_vote, ValidatorIndex(1)));
			statements.push((invalid_vote, ValidatorIndex(2)));

			for i in vec![3, 4, 5, 6, 7, 8] {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					true,
				);

				statements.push((vote, ValidatorIndex(i as _)));
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, vec![]).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 8); // 8 => we have participated
				assert_eq!(votes.invalid.len(), 1);
			}

			// now create another dispute
			// validator 2 should be disabled offchain now
			// but due to the byzantine threshold of onchain disabling
			// this validator will be considered enabled

			let mut statements = Vec::new();
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				another_candidate_hash,
				session,
				VoteType::Backing,
			)
			.await;

			statements.push((valid_vote, ValidatorIndex(1)));
			statements.push((invalid_vote, ValidatorIndex(2)));

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: another_candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation,
					},
				})
				.await;

			// let's disable validators 3, 4, 5 on chain, reaching the byzantine threshold
			let disabled_validators = vec![ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)];
			handle_disabled_validators_queries(&mut virtual_overseer, disabled_validators).await;
			handle_approval_vote_request(
				&mut virtual_overseer,
				&another_candidate_hash,
				HashMap::new(),
			)
			.await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&another_candidate_hash,
				another_candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 2);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, another_candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2); // 2 => we have participated
				assert_eq!(votes.invalid.len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn own_approval_vote_gets_distributed_on_dispute() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let statement = test_state.issue_approval_vote_with_index(
				ValidatorIndex(0),
				candidate_hash,
				session,
			);

			// Import our approval vote:
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(statement, ValidatorIndex(0))],
						pending_confirmation: None,
					},
				})
				.await;

			// Trigger dispute:
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(invalid_vote, ValidatorIndex(1)),
							(valid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// Dispute distribution should get notified now (without participation, as we already
			// have an approval vote):
			assert_matches!(
				overseer_recv(&mut virtual_overseer).await,
				AllMessages::DisputeDistribution(
					DisputeDistributionMessage::SendDispute(msg)
				) => {
					assert_eq!(msg.session_index(), session);
					assert_eq!(msg.candidate_receipt(), &candidate_receipt);
				}
			);

			// No participation should occur:
			assert_matches!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await, None);

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn negative_issue_local_statement_only_triggers_import() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_invalid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::IssueLocalStatement(
						session,
						candidate_hash,
						candidate_receipt.clone(),
						false,
					),
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			// Assert that subsystem is not participating.
			assert!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await.is_none());

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			let backend = DbBackend::new(
				test_state.db.clone(),
				test_state.config.column_config(),
				Metrics::default(),
			);

			let votes = backend.load_candidate_votes(session, &candidate_hash).unwrap().unwrap();
			assert_eq!(votes.invalid.len(), 1);
			assert_eq!(votes.valid.len(), 0);

			let disputes = backend.load_recent_disputes().unwrap();
			assert_eq!(disputes, None);

			test_state
		})
	});
}

#[test]
fn redundant_votes_ignored() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let valid_vote = test_state.issue_backing_statement_with_index(
				ValidatorIndex(1),
				candidate_hash,
				session,
			);

			let valid_vote_2 = test_state.issue_backing_statement_with_index(
				ValidatorIndex(1),
				candidate_hash,
				session,
			);

			assert!(valid_vote.validator_signature() != valid_vote_2.validator_signature());

			let (tx, rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(valid_vote.clone(), ValidatorIndex(1))],
						pending_confirmation: Some(tx),
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			rx.await.unwrap();

			let (tx, rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(valid_vote_2, ValidatorIndex(1))],
						pending_confirmation: Some(tx),
					},
				})
				.await;

			rx.await.unwrap();

			let backend = DbBackend::new(
				test_state.db.clone(),
				test_state.config.column_config(),
				Metrics::default(),
			);

			let votes = backend.load_candidate_votes(session, &candidate_hash).unwrap().unwrap();
			assert_eq!(votes.invalid.len(), 0);
			assert_eq!(votes.valid.len(), 1);
			assert_eq!(&votes.valid[0].2, valid_vote.validator_signature());

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
/// Make sure no disputes are recorded when there are no opposing votes, even if we reached
/// supermajority.
fn no_onesided_disputes() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();
			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			let mut statements = Vec::new();
			for index in 1..10 {
				statements.push((
					test_state.issue_backing_statement_with_index(
						ValidatorIndex(index),
						candidate_hash,
						session,
					),
					ValidatorIndex(index),
				));
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			assert_matches!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// We should not have any active disputes now.
			let (tx, rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
				})
				.await;

			assert!(rx.await.unwrap().is_empty());

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// No more messages expected:
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

#[test]
fn refrain_from_participation() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			// activate leaf - no backing/included event
			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			// generate two votes
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: None,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);

				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 1);
				assert_eq!(votes.invalid.len(), 1);
			}

			// activate leaf - no backing event
			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, Vec::new())
				.await;

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			// confirm that no participation request is made.
			assert!(virtual_overseer.try_recv().await.is_none());

			test_state
		})
	});
}

/// We have got no `participation_for_backed_candidates` test because most of the other tests (e.g.
/// `dispute_gets_confirmed_via_participation`, `backing_statements_import_works_and_no_spam`) use
/// candidate backing event to trigger participation. If they pass - that case works.
#[test]
fn participation_for_included_candidates() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			// activate leaf - with candidate included event
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_included_event(candidate_receipt.clone())],
				)
				.await;

			// generate two votes
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: None,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
					})
					.await;

				assert_eq!(rx.await.unwrap().len(), 1);

				// check if we have participated (cast a vote)
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::QueryCandidateVotes(
							vec![(session, candidate_hash)],
							tx,
						),
					})
					.await;

				let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
				assert_eq!(votes.valid.raw().len(), 2); // 2 => we have participated
				assert_eq!(votes.invalid.len(), 1);
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			test_state
		})
	});
}

/// Shows that importing backing votes when a backing event is being processed
/// results in participation.
#[test]
fn local_participation_in_dispute_for_backed_candidate() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_valid_candidate_receipt();
			let candidate_hash = candidate_receipt.hash();

			// Step 1: Show that we don't participate when not backed, confirmed, or included

			// activate leaf - without candidate backed event
			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, vec![])
				.await;

			// generate two votes
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation: None,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;

			assert_matches!(virtual_overseer.recv().timeout(TEST_TIMEOUT).await, None);

			// Step 2: Show that once backing votes are processed we participate

			// Activate leaf: With candidate backed event
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_backed_event(candidate_receipt.clone())],
				)
				.await;

			let backing_valid = test_state.issue_backing_statement_with_index(
				ValidatorIndex(3),
				candidate_hash,
				session,
			);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(backing_valid, ValidatorIndex(3))],
						pending_confirmation: None,
					},
				})
				.await;

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				candidate_receipt.commitments_hash,
			)
			.await;

			// Check for our 1 active dispute
			let (tx, rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ActiveDisputes(tx),
				})
				.await;

			assert_eq!(rx.await.unwrap().len(), 1);

			// check if we have participated (casted a vote)
			let (tx, rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::QueryCandidateVotes(
						vec![(session, candidate_hash)],
						tx,
					),
				})
				.await;

			let (_, _, votes) = rx.await.unwrap().get(0).unwrap().clone();
			assert_eq!(votes.valid.raw().len(), 3); // 3 => 1 initial vote, 1 backing vote, and our vote
			assert_eq!(votes.invalid.len(), 1);

			// Wrap up
			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			test_state
		})
	});
}

/// Shows that when a candidate_included event is scraped from the chain we
/// reprioritize any participation requests pertaining to that candidate.
/// This involves moving the request for this candidate from the best effort
/// queue to the priority queue.
#[test]
fn participation_requests_reprioritized_for_newly_included() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;
			test_state.handle_resume_sync(&mut virtual_overseer, session).await;
			let mut receipts: Vec<CandidateReceipt> = Vec::new();

			// Generate all receipts
			for repetition in 1..=3u8 {
				// Building candidate receipts
				let mut candidate_receipt = make_valid_candidate_receipt();
				candidate_receipt.descriptor.set_pov_hash(Hash::from(
					[repetition; 32], // Altering this receipt so its hash will be changed
				));
				// Set consecutive parents (starting from zero). They will order the candidates for
				// participation.
				let parent_block_num: BlockNumber = repetition as BlockNumber - 1;
				candidate_receipt.descriptor.set_relay_parent(
					*test_state.block_num_to_header.get(&parent_block_num).unwrap(),
				);
				receipts.push(candidate_receipt.clone());
			}

			// Mark all candidates as backed, so their participation requests make it to best
			// effort. These calls must all occur before including the candidates due to test
			// overseer oddities.
			let mut candidate_events = Vec::new();
			for r in receipts.iter() {
				candidate_events.push(make_candidate_backed_event(r.clone()))
			}
			test_state
				.activate_leaf_at_session(&mut virtual_overseer, session, 1, candidate_events)
				.await;

			for (idx, candidate_receipt) in receipts.iter().enumerate() {
				let candidate_hash = candidate_receipt.hash();

				// Create votes for candidates
				let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
					&test_state,
					ValidatorIndex(1),
					ValidatorIndex(2),
					candidate_hash,
					session,
					VoteType::Explicit,
				)
				.await;

				// Import votes for candidates
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::ImportStatements {
							candidate_receipt: candidate_receipt.clone(),
							session,
							statements: vec![
								(valid_vote, ValidatorIndex(1)),
								(invalid_vote, ValidatorIndex(2)),
							],
							pending_confirmation: None,
						},
					})
					.await;

				handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
				// Handle corresponding messages to unblock import
				// we need to handle
				// `ApprovalVotingParallelMessage::GetApprovalSignaturesForCandidate` for import
				handle_approval_vote_request(
					&mut virtual_overseer,
					&candidate_hash,
					HashMap::new(),
				)
				.await;

				//  We'll trigger participation for the first `MAX_PARALLEL_PARTICIPATIONS`
				// candidates. The rest will be queued => we need to handle
				// `ChainApiMessage::BlockNumber` for them.
				if idx >= crate::participation::MAX_PARALLEL_PARTICIPATIONS {
					// We send the `idx` as parent block number, because it is used for ordering.
					// This way we get predictable ordering and participation.
					handle_get_block_number(&mut virtual_overseer, &test_state).await;
				}
			}

			// Generate included event for one of the candidates here
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					2,
					vec![make_candidate_included_event(
						receipts.last().expect("There is more than one candidate").clone(),
					)],
				)
				.await;

			// NB: The checks below are a bit racy. In theory candidate 2 can be processed even
			// before candidate 0 and this is okay. If any of the asserts in the two functions after
			// this comment fail -> rework `participation_with_distribution` to expect a set of
			// commitment hashes instead of just one.

			// This is the candidate for which participation was started initially
			// (`MAX_PARALLEL_PARTICIPATIONS` threshold was not yet hit)
			participation_with_distribution(
				&mut virtual_overseer,
				&receipts.get(0).expect("There is more than one candidate").hash(),
				receipts.first().expect("There is more than one candidate").commitments_hash,
			)
			.await;

			// This one should have been prioritized
			participation_with_distribution(
				&mut virtual_overseer,
				&receipts.get(2).expect("There is more than one candidate").hash(),
				receipts.last().expect("There is more than one candidate").commitments_hash,
			)
			.await;

			// And this is the last one
			participation_with_distribution(
				&mut virtual_overseer,
				&receipts.get(1).expect("There is more than one candidate").hash(),
				receipts.first().expect("There is more than one candidate").commitments_hash,
			)
			.await;

			// Wrap up
			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			test_state
		})
	});
}

// When a dispute has concluded against a parachain block candidate we want to notify
// the chain selection subsystem. Then chain selection can revert the relay parents of
// the disputed candidate and mark all descendants as non-viable. This direct
// notification saves time compared to letting chain selection learn about a dispute
// conclusion from an on chain revert log.
#[test]
fn informs_chain_selection_when_dispute_concluded_against() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt = make_invalid_candidate_receipt();
			let parent_1_number = 1;
			let parent_2_number = 2;

			let candidate_hash = candidate_receipt.hash();

			// Including test candidate in 2 different parent blocks
			let block_1_header = Header {
				parent_hash: test_state.last_block,
				number: parent_1_number,
				digest: dummy_digest(),
				state_root: dummy_hash(),
				extrinsics_root: dummy_hash(),
			};
			let parent_1_hash = block_1_header.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					parent_1_number,
					vec![make_candidate_included_event(candidate_receipt.clone())],
				)
				.await;

			let block_2_header = Header {
				parent_hash: test_state.last_block,
				number: parent_2_number,
				digest: dummy_digest(),
				state_root: dummy_hash(),
				extrinsics_root: dummy_hash(),
			};
			let parent_2_hash = block_2_header.hash();

			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					parent_2_number,
					vec![make_candidate_included_event(candidate_receipt.clone())],
				)
				.await;

			let byzantine_threshold =
				polkadot_primitives::byzantine_threshold(test_state.validators.len());

			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(2),
				ValidatorIndex(1),
				candidate_hash,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(2)),
							(invalid_vote, ValidatorIndex(1)),
						],
						pending_confirmation: Some(pending_confirmation),
					},
				})
				.await;
			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash, HashMap::new())
				.await;
			assert_matches!(confirmation_rx.await.unwrap(),
				ImportStatementsResult::ValidImport => {}
			);

			// Use a different expected commitments hash to ensure the candidate validation returns
			// invalid.
			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash,
				CandidateCommitments::default().hash(),
			)
			.await;

			let mut statements = Vec::new();
			// own vote + `byzantine_threshold` more votes should be enough to issue `RevertBlocks`
			for i in 3_u32..byzantine_threshold as u32 + 3 {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash,
					session,
					false,
				);

				statements.push((vote, ValidatorIndex(i)));
			}

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements,
						pending_confirmation: None,
					},
				})
				.await;

			// Checking that concluded dispute has signaled the reversion of all parent blocks.
			assert_matches!(
				virtual_overseer.recv().await,
				AllMessages::ChainSelection(
					ChainSelectionMessage::RevertBlocks(revert_set)
				) => {
					assert!(revert_set.contains(&(parent_1_number, parent_1_hash)));
					assert!(revert_set.contains(&(parent_2_number, parent_2_hash)));
				},
				"Overseer did not receive `ChainSelectionMessage::RevertBlocks` message"
			);

			// One more import which should not trigger reversion
			// Validator index is `byzantine_threshold + 4`
			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt.clone(),
						session,
						statements: vec![(
							test_state.issue_explicit_statement_with_index(
								ValidatorIndex(byzantine_threshold as u32 + 4),
								candidate_hash,
								session,
								false,
							),
							ValidatorIndex(byzantine_threshold as u32 + 4),
						)],
						pending_confirmation: None,
					},
				})
				.await;

			// Wrap up
			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;
			assert_matches!(
				virtual_overseer.try_recv().await,
				None => {}
			);

			test_state
		})
	});
}

// On startup `SessionInfo` cache should be populated
#[test]
fn session_info_caching_on_startup_works() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			test_state
		})
	});
}

// Underflow means that no more than `DISPUTE_WINDOW` sessions should be fetched on startup
#[test]
fn session_info_caching_doesnt_underflow() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = DISPUTE_WINDOW.get() + 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			test_state
		})
	});
}

// Cached `SessionInfo` shouldn't be re-requested from the runtime
#[test]
fn session_info_is_requested_only_once() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			// This leaf activation shouldn't fetch `SessionInfo` because the session is already
			// cached
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					3,
					vec![make_candidate_included_event(make_valid_candidate_receipt())],
				)
				.await;

			// This leaf activation should fetch `SessionInfo` because the session is new
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session + 1,
					4,
					vec![make_candidate_included_event(make_valid_candidate_receipt())],
				)
				.await;

			assert_matches!(
				virtual_overseer.recv().await,
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					_,
					RuntimeApiRequest::SessionInfo(session_index, tx),
				)) => {
					assert_eq!(session_index, 2);
					let _ = tx.send(Ok(Some(test_state.session_info())));
				}
			);
			assert_matches!(
				virtual_overseer.recv().await,
				AllMessages::RuntimeApi(RuntimeApiMessage::Request(
					_,
					RuntimeApiRequest::SessionExecutorParams(session_index, tx),
				)) => {
					assert_eq!(session_index, 2);
					let _ = tx.send(Ok(Some(ExecutorParams::default())));
				}
			);
			assert_matches!(
				virtual_overseer.recv().await,
				AllMessages::RuntimeApi(
					RuntimeApiMessage::Request(_, RuntimeApiRequest::NodeFeatures(_, si_tx), )
				) => {
					si_tx.send(Ok(NodeFeatures::EMPTY)).unwrap();
				}
			);
			test_state
		})
	});
}

// Big jump means the new session we see with a leaf update is at least a `DISPUTE_WINDOW` bigger
// than the already known one. In this case The whole `DISPUTE_WINDOW` should be fetched.
#[test]
fn session_info_big_jump_works() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session_on_startup = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session_on_startup).await;

			// This leaf activation shouldn't fetch `SessionInfo` because the session is already
			// cached
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session_on_startup,
					3,
					vec![make_candidate_included_event(make_valid_candidate_receipt())],
				)
				.await;

			let session_after_jump = session_on_startup + DISPUTE_WINDOW.get() + 10;
			// This leaf activation should cache all missing `SessionInfo`s
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session_after_jump,
					4,
					vec![make_candidate_included_event(make_valid_candidate_receipt())],
				)
				.await;

			let first_expected_session =
				session_after_jump.saturating_sub(DISPUTE_WINDOW.get() - 1);
			for expected_idx in first_expected_session..=session_after_jump {
				assert_matches!(
					virtual_overseer.recv().await,
					AllMessages::RuntimeApi(RuntimeApiMessage::Request(
						_,
						RuntimeApiRequest::SessionInfo(session_index, tx),
					)) => {
						assert_eq!(session_index, expected_idx);
						let _ = tx.send(Ok(Some(test_state.session_info())));
					}
				);
				assert_matches!(
					virtual_overseer.recv().await,
					AllMessages::RuntimeApi(RuntimeApiMessage::Request(
						_,
						RuntimeApiRequest::SessionExecutorParams(session_index, tx),
					)) => {
						assert_eq!(session_index, expected_idx);
						let _ = tx.send(Ok(Some(ExecutorParams::default())));
					}
				);

				assert_matches!(
					virtual_overseer.recv().await,
					AllMessages::RuntimeApi(
						RuntimeApiMessage::Request(_, RuntimeApiRequest::NodeFeatures(_, si_tx), )
					) => {
						si_tx.send(Ok(NodeFeatures::EMPTY)).unwrap();
					}
				);
			}
			test_state
		})
	});
}

// Small jump means the new session we see with a leaf update is at less than last known one +
// `DISPUTE_WINDOW`. In this case fetching should start from last known one + 1.
#[test]
fn session_info_small_jump_works() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session_on_startup = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session_on_startup).await;

			// This leaf activation shouldn't fetch `SessionInfo` because the session is already
			// cached
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session_on_startup,
					3,
					vec![make_candidate_included_event(make_valid_candidate_receipt())],
				)
				.await;

			let session_after_jump = session_on_startup + DISPUTE_WINDOW.get() - 1;
			// This leaf activation should cache all missing `SessionInfo`s
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session_after_jump,
					4,
					vec![make_candidate_included_event(make_valid_candidate_receipt())],
				)
				.await;

			let first_expected_session = session_on_startup + 1;
			for expected_idx in first_expected_session..=session_after_jump {
				assert_matches!(
					virtual_overseer.recv().await,
					AllMessages::RuntimeApi(RuntimeApiMessage::Request(
						_,
						RuntimeApiRequest::SessionInfo(session_index, tx),
					)) => {
						assert_eq!(session_index, expected_idx);
						let _ = tx.send(Ok(Some(test_state.session_info())));
					}
				);
				assert_matches!(
					virtual_overseer.recv().await,
					AllMessages::RuntimeApi(RuntimeApiMessage::Request(
						_,
						RuntimeApiRequest::SessionExecutorParams(session_index, tx),
					)) => {
						assert_eq!(session_index, expected_idx);
						let _ = tx.send(Ok(Some(ExecutorParams::default())));
					}
				);
				assert_matches!(
					virtual_overseer.recv().await,
					AllMessages::RuntimeApi(
						RuntimeApiMessage::Request(_, RuntimeApiRequest::NodeFeatures(_, si_tx), )
					) => {
						si_tx.send(Ok(NodeFeatures::EMPTY)).unwrap();
					}
				);
			}
			test_state
		})
	});
}

async fn handle_disabled_validators_queries(
	virtual_overseer: &mut VirtualOverseer,
	disabled_validators: Vec<ValidatorIndex>,
) {
	assert_matches!(
		virtual_overseer.recv().await,
		AllMessages::RuntimeApi(RuntimeApiMessage::Request(
			_new_leaf,
			RuntimeApiRequest::DisabledValidators(tx),
		)) => {
			tx.send(Ok(disabled_validators)).unwrap();
		}
	);
}

/// Test for the functionality that unactivates disputes when all raising parties are disabled.
///
/// This test verifies the implementation where:
/// 1. Multiple disputes are raised by the same validator: candidate C is raised by 2 and 5
///    candidate A and B are raised by 2
/// 2. When one dispute (A) concludes against that validator, it gets disabled.
/// 3. All other active disputes in that session where this validator was the sole raising party
///    should be unactivated (B).
/// 4. Disputes can become active again if non-disabled validators vote against them or if the
///    dispute gets confirmed.
#[test]
fn disputes_unactivated_when_all_raising_parties_disabled() {
	test_harness(|mut test_state, mut virtual_overseer| {
		Box::pin(async move {
			let session = 1;

			test_state.handle_resume_sync(&mut virtual_overseer, session).await;

			let candidate_receipt_c = make_valid_candidate_receipt();
			let candidate_hash_c = candidate_receipt_c.hash();

			let block_hash = test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					1,
					vec![make_candidate_included_event(candidate_receipt_c.clone())],
				)
				.await;

			let candidate_receipt_a = make_another_valid_candidate_receipt(block_hash);
			let candidate_hash_a = candidate_receipt_a.hash();

			let mut candidate_receipt_b = make_another_valid_candidate_receipt(block_hash);
			candidate_receipt_b.descriptor.set_pov_hash(Hash::from(
				[0xFF; 32], // Altering this receipt so its hash will be changed
			));
			let candidate_hash_b = candidate_receipt_b.hash();

			// activate leaf - with both candidates included
			test_state
				.activate_leaf_at_session(
					&mut virtual_overseer,
					session,
					2,
					vec![
						make_candidate_included_event(candidate_receipt_a.clone()),
						make_candidate_included_event(candidate_receipt_b.clone()),
					],
				)
				.await;

			// Import first dispute with validator 2 as the sole invalid voter
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(1),
				ValidatorIndex(2),
				candidate_hash_a,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt_a.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(1)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash_a, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash_a,
				candidate_receipt_a.commitments_hash,
			)
			.await;

			// Import second dispute with same validator 2 as invalid voter
			let (valid_vote, invalid_vote) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(2),
				candidate_hash_b,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt_b.clone(),
						session,
						statements: vec![
							(valid_vote.clone(), ValidatorIndex(3)),
							(invalid_vote, ValidatorIndex(2)),
						],
						pending_confirmation,
					},
				})
				.await;

			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash_b, HashMap::new())
				.await;

			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash_b,
				candidate_receipt_b.commitments_hash,
			)
			.await;

			// Import third dispute with multiple validators as invalid voters

			let (valid_vote_1, invalid_vote_1) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(3),
				ValidatorIndex(2),
				candidate_hash_c,
				session,
				VoteType::Explicit,
			)
			.await;
			let (valid_vote_2, invalid_vote_2) = generate_opposing_votes_pair(
				&test_state,
				ValidatorIndex(4),
				ValidatorIndex(5),
				candidate_hash_c,
				session,
				VoteType::Explicit,
			)
			.await;

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt_c.clone(),
						session,
						statements: vec![
							(valid_vote_1, ValidatorIndex(3)),
							(invalid_vote_1, ValidatorIndex(2)),
							(valid_vote_2, ValidatorIndex(4)),
							(invalid_vote_2, ValidatorIndex(5)),
						],
						pending_confirmation,
					},
				})
				.await;

			handle_disabled_validators_queries(&mut virtual_overseer, Vec::new()).await;
			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash_c, HashMap::new())
				.await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			participation_with_distribution(
				&mut virtual_overseer,
				&candidate_hash_c,
				candidate_receipt_c.commitments_hash,
			)
			.await;

			// Verify we have 3 active/recent disputes
			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::RecentDisputes(tx),
					})
					.await;
				assert_eq!(rx.await.unwrap().len(), 3);
			}

			// Import enough valid votes to conclude dispute A as valid (disabling validator 2)
			let mut additional_votes = vec![];
			for i in 3..8 {
				let vote = test_state.issue_explicit_statement_with_index(
					ValidatorIndex(i),
					candidate_hash_a,
					session,
					true,
				);
				additional_votes.push((vote, ValidatorIndex(i)));
			}

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt_a.clone(),
						session,
						statements: additional_votes,
						pending_confirmation,
					},
				})
				.await;

			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash_a, HashMap::new())
				.await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// Verify one dispute got deactivated
			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::RecentDisputes(tx),
					})
					.await;
				assert_eq!(rx.await.unwrap().len(), 2);
			}
			// and we can finalize the chain with A and B
			{
				let (tx, rx) = oneshot::channel();

				let base_hash = Hash::repeat_byte(0x0f);
				let block_hash_a = Hash::repeat_byte(0x0a);
				let block_hash_c = Hash::repeat_byte(0x0c);

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::DetermineUndisputedChain {
							base: (10, base_hash),
							block_descriptions: vec![
								BlockDescription {
									block_hash: block_hash_a,
									session,
									candidates: vec![candidate_hash_a, candidate_hash_b],
								},
								BlockDescription {
									block_hash: block_hash_c,
									session,
									candidates: vec![candidate_hash_c],
								},
							],
							tx,
						},
					})
					.await;

				assert_eq!(rx.await.unwrap(), (11, block_hash_a));
			}

			// Now let's import a vote against B from non-disabled validator 5
			let invalid_vote_from_5 = test_state.issue_explicit_statement_with_index(
				ValidatorIndex(5),
				candidate_hash_b,
				session,
				false,
			);

			let (pending_confirmation, confirmation_rx) = oneshot::channel();
			let pending_confirmation = Some(pending_confirmation);

			virtual_overseer
				.send(FromOrchestra::Communication {
					msg: DisputeCoordinatorMessage::ImportStatements {
						candidate_receipt: candidate_receipt_b.clone(),
						session,
						statements: vec![
							(valid_vote, ValidatorIndex(3)),
							(invalid_vote_from_5, ValidatorIndex(5)),
						],
						pending_confirmation,
					},
				})
				.await;

			handle_approval_vote_request(&mut virtual_overseer, &candidate_hash_b, HashMap::new())
				.await;
			assert_eq!(confirmation_rx.await, Ok(ImportStatementsResult::ValidImport));

			// Verify dispute B is now active again
			{
				let (tx, rx) = oneshot::channel();
				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::RecentDisputes(tx),
					})
					.await;
				assert_eq!(rx.await.unwrap().len(), 3);
			}
			// and we can't finalize the chain with A and B anymore
			{
				let (tx, rx) = oneshot::channel();

				let base_hash = Hash::repeat_byte(0x0f);
				let block_hash_a = Hash::repeat_byte(0x0a);

				virtual_overseer
					.send(FromOrchestra::Communication {
						msg: DisputeCoordinatorMessage::DetermineUndisputedChain {
							base: (10, base_hash),
							block_descriptions: vec![BlockDescription {
								block_hash: block_hash_a,
								session,
								candidates: vec![candidate_hash_a, candidate_hash_b],
							}],
							tx,
						},
					})
					.await;

				assert_eq!(rx.await.unwrap(), (10, base_hash));
			}

			virtual_overseer.send(FromOrchestra::Signal(OverseerSignal::Conclude)).await;

			test_state
		})
	});
}
