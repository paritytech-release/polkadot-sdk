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

use super::*;
use frame_support::{
	assert_err, assert_noop, assert_ok, assert_storage_noop, traits::UnfilteredDispatchable,
};
use polkadot_primitives::{BlockNumber, SchedulerParams, PARACHAIN_KEY_TYPE_ID};
use polkadot_primitives_test_helpers::{dummy_head_data, dummy_validation_code, validator_pubkeys};
use sc_keystore::LocalKeystore;
use sp_keyring::Sr25519Keyring;
use sp_keystore::{Keystore, KeystorePtr};
use sp_runtime::TokenError;
use std::sync::Arc;

use crate::{
	configuration::HostConfiguration,
	mock::{
		new_test_ext, Balances, MockGenesisConfig, Paras, ParasShared, RuntimeOrigin, System, Test,
	},
	paras,
};

static VALIDATORS: &[Sr25519Keyring] = &[
	Sr25519Keyring::Alice,
	Sr25519Keyring::Bob,
	Sr25519Keyring::Charlie,
	Sr25519Keyring::Dave,
	Sr25519Keyring::Ferdie,
];

fn sign_and_include_pvf_check_statement(stmt: PvfCheckStatement) {
	let validators = &[
		Sr25519Keyring::Alice,
		Sr25519Keyring::Bob,
		Sr25519Keyring::Charlie,
		Sr25519Keyring::Dave,
		Sr25519Keyring::Ferdie,
	];
	let signature = validators[stmt.validator_index.0 as usize].sign(&stmt.signing_payload());
	Paras::include_pvf_check_statement(None.into(), stmt, signature.into()).unwrap();
}

fn submit_super_majority_pvf_votes(
	validation_code: &ValidationCode,
	session_index: SessionIndex,
	accept: bool,
) {
	[0, 1, 2, 3]
		.into_iter()
		.map(|i| PvfCheckStatement {
			accept,
			subject: validation_code.hash(),
			session_index,
			validator_index: i.into(),
		})
		.for_each(sign_and_include_pvf_check_statement);
}

fn test_validation_code_1() -> ValidationCode {
	let validation_code = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
	ValidationCode(validation_code)
}

fn test_validation_code_2() -> ValidationCode {
	let validation_code = vec![9, 8, 7, 6, 5, 4, 3, 2, 1];
	ValidationCode(validation_code)
}

fn run_to_block(to: BlockNumber, new_session: Option<Vec<BlockNumber>>) {
	let keystore: KeystorePtr = Arc::new(LocalKeystore::in_memory());
	for validator in VALIDATORS.iter() {
		Keystore::sr25519_generate_new(
			&*keystore,
			PARACHAIN_KEY_TYPE_ID,
			Some(&validator.to_seed()),
		)
		.unwrap();
	}
	let validator_pubkeys = validator_pubkeys(VALIDATORS);

	while System::block_number() < to {
		let b = System::block_number();
		Paras::initializer_finalize(b);
		ParasShared::initializer_finalize();
		if new_session.as_ref().map_or(false, |v| v.contains(&(b + 1))) {
			let mut session_change_notification = SessionChangeNotification::default();
			session_change_notification.session_index =
				shared::CurrentSessionIndex::<Test>::get() + 1;
			session_change_notification.validators = validator_pubkeys.clone();
			ParasShared::initializer_on_new_session(
				session_change_notification.session_index,
				session_change_notification.random_seed,
				&session_change_notification.new_config,
				session_change_notification.validators.clone(),
			);
			ParasShared::set_active_validators_ascending(validator_pubkeys.clone());
			Paras::initializer_on_new_session(&session_change_notification);
		}
		System::on_finalize(b);

		System::on_initialize(b + 1);
		System::set_block_number(b + 1);

		ParasShared::initializer_initialize(b + 1);
		Paras::initializer_initialize(b + 1);
	}
}

fn upgrade_at(
	expected_at: BlockNumber,
	activated_at: BlockNumber,
) -> ReplacementTimes<BlockNumber> {
	ReplacementTimes { expected_at, activated_at }
}

fn check_code_is_stored(validation_code: &ValidationCode) {
	assert!(CodeByHashRefs::<Test>::get(validation_code.hash()) != 0);
	assert!(CodeByHash::<Test>::contains_key(validation_code.hash()));
}

fn check_code_is_not_stored(validation_code: &ValidationCode) {
	assert!(!CodeByHashRefs::<Test>::contains_key(validation_code.hash()));
	assert!(!CodeByHash::<Test>::contains_key(validation_code.hash()));
}

/// An utility for checking that certain events were deposited.
struct EventValidator {
	events: Vec<
		frame_system::EventRecord<
			<Test as frame_system::Config>::RuntimeEvent,
			polkadot_primitives::Hash,
		>,
	>,
}

impl EventValidator {
	fn new() -> Self {
		Self { events: Vec::new() }
	}

	fn started(&mut self, code: &ValidationCode, id: ParaId) -> &mut Self {
		self.events.push(frame_system::EventRecord {
			phase: frame_system::Phase::Initialization,
			event: Event::PvfCheckStarted(code.hash(), id).into(),
			topics: vec![],
		});
		self
	}

	fn rejected(&mut self, code: &ValidationCode, id: ParaId) -> &mut Self {
		self.events.push(frame_system::EventRecord {
			phase: frame_system::Phase::Initialization,
			event: Event::PvfCheckRejected(code.hash(), id).into(),
			topics: vec![],
		});
		self
	}

	fn accepted(&mut self, code: &ValidationCode, id: ParaId) -> &mut Self {
		self.events.push(frame_system::EventRecord {
			phase: frame_system::Phase::Initialization,
			event: Event::PvfCheckAccepted(code.hash(), id).into(),
			topics: vec![],
		});
		self
	}

	fn check(&self) {
		assert_eq!(&frame_system::Pallet::<Test>::events(), &self.events);
	}
}

#[test]
fn para_past_code_pruning_works_correctly() {
	let mut past_code = ParaPastCodeMeta::default();
	past_code.note_replacement(10u32, 10);
	past_code.note_replacement(20, 25);
	past_code.note_replacement(30, 35);

	let old = past_code.clone();
	assert!(past_code.prune_up_to(9).collect::<Vec<_>>().is_empty());
	assert_eq!(old, past_code);

	assert_eq!(past_code.prune_up_to(10).collect::<Vec<_>>(), vec![10]);
	assert_eq!(
		past_code,
		ParaPastCodeMeta {
			upgrade_times: vec![upgrade_at(20, 25), upgrade_at(30, 35)],
			last_pruned: Some(10),
		}
	);

	assert!(past_code.prune_up_to(21).collect::<Vec<_>>().is_empty());

	assert_eq!(past_code.prune_up_to(26).collect::<Vec<_>>(), vec![20]);
	assert_eq!(
		past_code,
		ParaPastCodeMeta { upgrade_times: vec![upgrade_at(30, 35)], last_pruned: Some(25) }
	);

	past_code.note_replacement(40, 42);
	past_code.note_replacement(50, 53);
	past_code.note_replacement(60, 66);

	assert_eq!(
		past_code,
		ParaPastCodeMeta {
			upgrade_times: vec![
				upgrade_at(30, 35),
				upgrade_at(40, 42),
				upgrade_at(50, 53),
				upgrade_at(60, 66)
			],
			last_pruned: Some(25),
		}
	);

	assert_eq!(past_code.prune_up_to(60).collect::<Vec<_>>(), vec![30, 40, 50]);
	assert_eq!(
		past_code,
		ParaPastCodeMeta { upgrade_times: vec![upgrade_at(60, 66)], last_pruned: Some(53) }
	);

	assert_eq!(past_code.most_recent_change(), Some(60));
	assert_eq!(past_code.prune_up_to(66).collect::<Vec<_>>(), vec![60]);

	assert_eq!(past_code, ParaPastCodeMeta { upgrade_times: Vec::new(), last_pruned: Some(66) });
}

#[test]
fn schedule_para_init_rejects_empty_code() {
	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		assert_err!(
			Paras::schedule_para_initialize(
				1000.into(),
				ParaGenesisArgs {
					para_kind: ParaKind::Parathread,
					genesis_head: dummy_head_data(),
					validation_code: ValidationCode(vec![]),
				}
			),
			Error::<Test>::CannotOnboard,
		);

		assert_ok!(Paras::schedule_para_initialize(
			1000.into(),
			ParaGenesisArgs {
				para_kind: ParaKind::Parathread,
				genesis_head: dummy_head_data(),
				validation_code: ValidationCode(vec![1]),
			}
		));
	});
}

#[test]
fn para_past_code_pruning_in_initialize() {
	let code_retention_period = 10;
	let paras = vec![
		(
			0u32.into(),
			ParaGenesisArgs {
				para_kind: ParaKind::Parachain,
				genesis_head: dummy_head_data(),
				validation_code: dummy_validation_code(),
			},
		),
		(
			1u32.into(),
			ParaGenesisArgs {
				para_kind: ParaKind::Parathread,
				genesis_head: dummy_head_data(),
				validation_code: dummy_validation_code(),
			},
		),
	];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration { code_retention_period, ..Default::default() },
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		let id = ParaId::from(0u32);
		let at_block: BlockNumber = 10;
		let included_block: BlockNumber = 12;
		let validation_code = test_validation_code_2();

		Paras::increase_code_ref(&validation_code.hash(), &validation_code);
		PastCodeHash::<Test>::insert(&(id, at_block), &validation_code.hash());
		PastCodePruning::<Test>::put(&vec![(id, included_block)]);

		{
			let mut code_meta = paras::PastCodeMeta::<Test>::get(&id);
			code_meta.note_replacement(at_block, included_block);
			PastCodeMeta::<Test>::insert(&id, &code_meta);
		}

		let pruned_at: BlockNumber = included_block + code_retention_period + 1;
		assert_eq!(PastCodeHash::<Test>::get(&(id, at_block)), Some(validation_code.hash()));
		check_code_is_stored(&validation_code);

		run_to_block(pruned_at - 1, None);
		assert_eq!(PastCodeHash::<Test>::get(&(id, at_block)), Some(validation_code.hash()));
		assert_eq!(paras::PastCodeMeta::<Test>::get(&id).most_recent_change(), Some(at_block));
		check_code_is_stored(&validation_code);

		run_to_block(pruned_at, None);
		assert!(PastCodeHash::<Test>::get(&(id, at_block)).is_none());
		assert!(paras::PastCodeMeta::<Test>::get(&id).most_recent_change().is_none());
		check_code_is_not_stored(&validation_code);
	});
}

#[test]
fn note_new_head_sets_head() {
	let code_retention_period = 10;
	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: dummy_validation_code(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration { code_retention_period, ..Default::default() },
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		let id_a = ParaId::from(0u32);

		assert_eq!(paras::Heads::<Test>::get(&id_a), Some(dummy_head_data()));

		Paras::note_new_head(id_a, vec![1, 2, 3].into(), 0);

		assert_eq!(paras::Heads::<Test>::get(&id_a), Some(vec![1, 2, 3].into()));
	});
}

#[test]
fn note_past_code_sets_up_pruning_correctly() {
	let code_retention_period = 10;
	let paras = vec![
		(
			0u32.into(),
			ParaGenesisArgs {
				para_kind: ParaKind::Parachain,
				genesis_head: dummy_head_data(),
				validation_code: dummy_validation_code(),
			},
		),
		(
			1u32.into(),
			ParaGenesisArgs {
				para_kind: ParaKind::Parathread,
				genesis_head: dummy_head_data(),
				validation_code: dummy_validation_code(),
			},
		),
	];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration { code_retention_period, ..Default::default() },
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		let id_a = ParaId::from(0u32);
		let id_b = ParaId::from(1u32);

		Paras::note_past_code(id_a, 10, 12, test_validation_code_1().hash());
		Paras::note_past_code(id_b, 20, 23, test_validation_code_2().hash());

		assert_eq!(PastCodePruning::<Test>::get(), vec![(id_a, 12), (id_b, 23)]);
		assert_eq!(
			paras::PastCodeMeta::<Test>::get(&id_a),
			ParaPastCodeMeta { upgrade_times: vec![upgrade_at(10, 12)], last_pruned: None }
		);
		assert_eq!(
			paras::PastCodeMeta::<Test>::get(&id_b),
			ParaPastCodeMeta { upgrade_times: vec![upgrade_at(20, 23)], last_pruned: None }
		);
	});
}

#[test]
fn code_upgrade_applied_after_delay() {
	let code_retention_period = 10;
	let validation_upgrade_delay = 5;
	let validation_upgrade_cooldown = 10;

	let original_code = test_validation_code_1();
	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: original_code.clone(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				validation_upgrade_cooldown,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		check_code_is_stored(&original_code);

		let para_id = ParaId::from(0);
		let new_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(2, Some(vec![1]));
		assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));

		let (expected_at, next_possible_upgrade_at) = {
			// this parablock is in the context of block 1.
			let expected_at = 1 + validation_upgrade_delay;
			let next_possible_upgrade_at = 1 + validation_upgrade_cooldown;
			Paras::schedule_code_upgrade(
				para_id,
				new_code.clone(),
				1,
				&configuration::ActiveConfig::<Test>::get(),
				UpgradeStrategy::SetGoAheadSignal,
			);
			// Include votes for super-majority.
			submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

			Paras::note_new_head(para_id, Default::default(), 1);

			assert!(paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change().is_none());
			assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(expected_at));
			assert_eq!(FutureCodeHash::<Test>::get(&para_id), Some(new_code.hash()));
			assert_eq!(UpcomingUpgrades::<Test>::get(), vec![(para_id, expected_at)]);
			assert_eq!(UpgradeCooldowns::<Test>::get(), vec![(para_id, next_possible_upgrade_at)]);
			assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));
			check_code_is_stored(&original_code);
			check_code_is_stored(&new_code);

			(expected_at, next_possible_upgrade_at)
		};

		run_to_block(expected_at, None);

		// the candidate is in the context of the parent of `expected_at`,
		// thus does not trigger the code upgrade.
		{
			Paras::note_new_head(para_id, Default::default(), expected_at - 1);

			assert!(paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change().is_none());
			assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(expected_at));
			assert_eq!(FutureCodeHash::<Test>::get(&para_id), Some(new_code.hash()));
			assert_eq!(UpgradeGoAheadSignal::<Test>::get(&para_id), Some(UpgradeGoAhead::GoAhead));
			assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));
			check_code_is_stored(&original_code);
			check_code_is_stored(&new_code);
		}

		run_to_block(expected_at + 1, None);

		// the candidate is in the context of `expected_at`, and triggers
		// the upgrade.
		{
			Paras::note_new_head(para_id, Default::default(), expected_at);

			assert_eq!(
				paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change(),
				Some(expected_at)
			);
			assert_eq!(
				PastCodeHash::<Test>::get(&(para_id, expected_at)),
				Some(original_code.hash()),
			);
			assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_none());
			assert!(FutureCodeHash::<Test>::get(&para_id).is_none());
			assert!(UpgradeGoAheadSignal::<Test>::get(&para_id).is_none());
			assert_eq!(Paras::current_code(&para_id), Some(new_code.clone()));
			assert_eq!(
				UpgradeRestrictionSignal::<Test>::get(&para_id),
				Some(UpgradeRestriction::Present),
			);
			assert_eq!(UpgradeCooldowns::<Test>::get(), vec![(para_id, next_possible_upgrade_at)]);
			check_code_is_stored(&original_code);
			check_code_is_stored(&new_code);
		}

		run_to_block(next_possible_upgrade_at + 1, None);

		{
			assert!(UpgradeRestrictionSignal::<Test>::get(&para_id).is_none());
			assert!(UpgradeCooldowns::<Test>::get().is_empty());
		}
	});
}

#[test]
fn upgrade_strategy_apply_at_expected_block_works() {
	let code_retention_period = 10;
	let validation_upgrade_delay = 5;
	let validation_upgrade_cooldown = 10;

	let original_code = test_validation_code_1();
	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: original_code.clone(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				validation_upgrade_cooldown,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		check_code_is_stored(&original_code);

		let para_id = ParaId::from(0);
		let new_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(2, Some(vec![1]));
		assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));

		// this parablock is in the context of block 1.
		let expected_at = 1 + validation_upgrade_delay;
		let next_possible_upgrade_at = 1 + validation_upgrade_cooldown;
		// `set_go_ahead` parameter set to `false` which prevents signaling the parachain
		// with the `GoAhead` signal.
		Paras::schedule_code_upgrade(
			para_id,
			new_code.clone(),
			1,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::ApplyAtExpectedBlock,
		);
		// Include votes for super-majority.
		submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);
		assert!(FutureCodeUpgradesAt::<Test>::get().iter().any(|(id, _)| *id == para_id));

		// Going to the expected block triggers the upgrade directly.
		run_to_block(expected_at, None);

		// Reporting a head doesn't change anything.
		Paras::note_new_head(para_id, Default::default(), expected_at - 1);

		assert_eq!(
			paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change(),
			Some(expected_at)
		);
		assert_eq!(PastCodeHash::<Test>::get(&(para_id, expected_at)), Some(original_code.hash()));
		assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_none());
		assert!(FutureCodeUpgradesAt::<Test>::get().iter().all(|(id, _)| *id != para_id));
		assert!(FutureCodeHash::<Test>::get(&para_id).is_none());
		assert!(UpgradeGoAheadSignal::<Test>::get(&para_id).is_none());
		assert_eq!(Paras::current_code(&para_id), Some(new_code.clone()));
		assert_eq!(
			UpgradeRestrictionSignal::<Test>::get(&para_id),
			Some(UpgradeRestriction::Present),
		);
		assert_eq!(UpgradeCooldowns::<Test>::get(), vec![(para_id, next_possible_upgrade_at)]);
		check_code_is_stored(&original_code);
		check_code_is_stored(&new_code);

		run_to_block(next_possible_upgrade_at + 1, None);

		{
			assert!(UpgradeRestrictionSignal::<Test>::get(&para_id).is_none());
			assert!(UpgradeCooldowns::<Test>::get().is_empty());
		}
	});
}

#[test]
fn code_upgrade_applied_after_delay_even_when_late() {
	let code_retention_period = 10;
	let validation_upgrade_delay = 5;
	let validation_upgrade_cooldown = 10;

	let original_code = test_validation_code_1();
	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: original_code.clone(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				validation_upgrade_cooldown,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		let para_id = ParaId::from(0);
		let new_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(2, Some(vec![1]));
		assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));

		let expected_at = {
			// this parablock is in the context of block 1.
			let expected_at = 1 + validation_upgrade_delay;
			let next_possible_upgrade_at = 1 + validation_upgrade_cooldown;
			Paras::schedule_code_upgrade(
				para_id,
				new_code.clone(),
				1,
				&configuration::ActiveConfig::<Test>::get(),
				UpgradeStrategy::SetGoAheadSignal,
			);
			// Include votes for super-majority.
			submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

			Paras::note_new_head(para_id, Default::default(), 1);

			assert!(paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change().is_none());
			assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(expected_at));
			assert_eq!(FutureCodeHash::<Test>::get(&para_id), Some(new_code.hash()));
			assert_eq!(UpcomingUpgrades::<Test>::get(), vec![(para_id, expected_at)]);
			assert_eq!(UpgradeCooldowns::<Test>::get(), vec![(para_id, next_possible_upgrade_at)]);
			assert!(UpgradeGoAheadSignal::<Test>::get(&para_id).is_none());
			assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));

			expected_at
		};

		run_to_block(expected_at + 1 + 4, None);

		// the candidate is in the context of the first descendant of `expected_at`, and triggers
		// the upgrade.
		{
			// The signal should be set to go-ahead until the new head is actually processed.
			assert_eq!(UpgradeGoAheadSignal::<Test>::get(&para_id), Some(UpgradeGoAhead::GoAhead));

			Paras::note_new_head(para_id, Default::default(), expected_at + 4);

			assert_eq!(
				paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change(),
				Some(expected_at)
			);

			assert_eq!(
				PastCodeHash::<Test>::get(&(para_id, expected_at)),
				Some(original_code.hash()),
			);
			assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_none());
			assert!(FutureCodeHash::<Test>::get(&para_id).is_none());
			assert!(UpgradeGoAheadSignal::<Test>::get(&para_id).is_none());
			assert_eq!(Paras::current_code(&para_id), Some(new_code.clone()));
		}
	});
}

#[test]
fn submit_code_change_when_not_allowed_is_err() {
	let code_retention_period = 10;
	let validation_upgrade_delay = 7;
	let validation_upgrade_cooldown = 100;

	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: vec![1, 2, 3].into(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				validation_upgrade_cooldown,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		let para_id = ParaId::from(0);
		let new_code = test_validation_code_1();
		let newer_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(1, Some(vec![1]));

		Paras::schedule_code_upgrade(
			para_id,
			new_code.clone(),
			1,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		// Include votes for super-majority.
		submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

		assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(1 + validation_upgrade_delay));
		assert_eq!(FutureCodeHash::<Test>::get(&para_id), Some(new_code.hash()));
		check_code_is_stored(&new_code);

		// We expect that if an upgrade is signalled while there is already one pending we just
		// ignore it. Note that this is only true from perspective of this module.
		run_to_block(2, None);
		assert!(!Paras::can_upgrade_validation_code(para_id));
		Paras::schedule_code_upgrade(
			para_id,
			newer_code.clone(),
			2,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		assert_eq!(
			FutureCodeUpgrades::<Test>::get(&para_id),
			Some(1 + validation_upgrade_delay), /* did not change since the same assertion from
			                                     * the last time. */
		);
		assert_eq!(FutureCodeHash::<Test>::get(&para_id), Some(new_code.hash()));
		check_code_is_not_stored(&newer_code);
	});
}

#[test]
fn upgrade_restriction_elapsed_doesnt_mean_can_upgrade() {
	// Situation: parachain scheduled upgrade but it doesn't produce any candidate after
	// `expected_at`. When `validation_upgrade_cooldown` elapsed the parachain produces a
	// candidate that tries to upgrade the code.
	//
	// In the current code this is not allowed: the upgrade should be consumed first. This is
	// rather an artifact of the current implementation and not necessarily something we want
	// to keep in the future.
	//
	// This test exists that this is not accidentally changed.

	let code_retention_period = 10;
	let validation_upgrade_delay = 7;
	let validation_upgrade_cooldown = 30;

	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: vec![1, 2, 3].into(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				validation_upgrade_cooldown,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		let para_id = 0u32.into();
		let new_code = test_validation_code_1();
		let newer_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(1, Some(vec![1]));

		Paras::schedule_code_upgrade(
			para_id,
			new_code.clone(),
			0,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		// Include votes for super-majority.
		submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

		Paras::note_new_head(para_id, dummy_head_data(), 0);
		assert_eq!(
			UpgradeRestrictionSignal::<Test>::get(&para_id),
			Some(UpgradeRestriction::Present),
		);
		assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(0 + validation_upgrade_delay));
		assert!(!Paras::can_upgrade_validation_code(para_id));

		run_to_block(31, None);
		assert!(UpgradeRestrictionSignal::<Test>::get(&para_id).is_none());

		// Note the para still cannot upgrade the validation code.
		assert!(!Paras::can_upgrade_validation_code(para_id));

		// And scheduling another upgrade does not do anything. `expected_at` is still the same.
		Paras::schedule_code_upgrade(
			para_id,
			newer_code.clone(),
			30,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(0 + validation_upgrade_delay));
	});
}

#[test]
fn full_parachain_cleanup_storage() {
	let code_retention_period = 20;
	let validation_upgrade_delay = 1 + 5;

	let original_code = test_validation_code_1();
	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: original_code.clone(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				minimum_validation_upgrade_delay: 2,
				// Those are not relevant to this test. However, HostConfiguration is still a
				// subject for the consistency check.
				scheduler_params: SchedulerParams {
					paras_availability_period: 1,
					..Default::default()
				},
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		check_code_is_stored(&original_code);

		let para_id = ParaId::from(0);
		let new_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(2, Some(vec![1]));

		assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));
		check_code_is_stored(&original_code);

		let expected_at = {
			// this parablock is in the context of block 1.
			let expected_at = 1 + validation_upgrade_delay;
			Paras::schedule_code_upgrade(
				para_id,
				new_code.clone(),
				1,
				&configuration::ActiveConfig::<Test>::get(),
				UpgradeStrategy::SetGoAheadSignal,
			);
			// Include votes for super-majority.
			submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

			Paras::note_new_head(para_id, Default::default(), 1);

			assert!(paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change().is_none());
			assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(expected_at));
			assert_eq!(FutureCodeHash::<Test>::get(&para_id), Some(new_code.hash()));
			assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));
			check_code_is_stored(&original_code);
			check_code_is_stored(&new_code);

			expected_at
		};

		// Enact the upgrade.
		//
		// For that run to block #7 and submit a new head.
		assert_eq!(expected_at, 7);
		run_to_block(7, None);
		assert_eq!(frame_system::Pallet::<Test>::block_number(), 7);
		Paras::note_new_head(para_id, Default::default(), expected_at);

		assert_ok!(Paras::schedule_para_cleanup(para_id));

		// run to block #10, with a 2 session changes at the end of the block 7 & 8 (so 8 and 9
		// observe the new sessions).
		run_to_block(10, Some(vec![8, 9]));

		// cleaning up the parachain should place the current parachain code
		// into the past code buffer & schedule cleanup.
		//
		// Why 7 and 8? See above, the clean up scheduled above was processed at the block 8.
		// The initial upgrade was enacted at the block 7.
		assert_eq!(paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change(), Some(8));
		assert_eq!(PastCodeHash::<Test>::get(&(para_id, 8)), Some(new_code.hash()));
		assert_eq!(PastCodePruning::<Test>::get(), vec![(para_id, 7), (para_id, 8)]);
		check_code_is_stored(&original_code);
		check_code_is_stored(&new_code);

		// any future upgrades haven't been used to validate yet, so those
		// are cleaned up immediately.
		assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_none());
		assert!(FutureCodeHash::<Test>::get(&para_id).is_none());
		assert!(Paras::current_code(&para_id).is_none());

		// run to do the final cleanup
		let cleaned_up_at = 8 + code_retention_period + 1;
		run_to_block(cleaned_up_at, None);

		// now the final cleanup: last past code cleaned up, and this triggers meta cleanup.
		assert_eq!(paras::PastCodeMeta::<Test>::get(&para_id), Default::default());
		assert!(PastCodeHash::<Test>::get(&(para_id, 7)).is_none());
		assert!(PastCodeHash::<Test>::get(&(para_id, 8)).is_none());
		assert!(PastCodePruning::<Test>::get().is_empty());
		check_code_is_not_stored(&original_code);
		check_code_is_not_stored(&new_code);
	});
}

#[test]
fn cannot_offboard_ongoing_pvf_check() {
	let para_id = ParaId::from(0);

	let existing_code = test_validation_code_1();
	let new_code = test_validation_code_2();

	let paras = vec![(
		para_id,
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: Default::default(),
			validation_code: existing_code,
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		run_to_block(2, Some(vec![1]));

		// Relay parent of the block that schedules the upgrade.
		const RELAY_PARENT: BlockNumber = 1;
		// Expected current session index.
		const EXPECTED_SESSION: SessionIndex = 1;

		Paras::schedule_code_upgrade(
			para_id,
			new_code.clone(),
			RELAY_PARENT,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		assert!(!Paras::pvfs_require_precheck().is_empty());

		// Cannot offboard when there's an ongoing pvf-check voting.
		assert_err!(Paras::schedule_para_cleanup(para_id), Error::<Test>::CannotOffboard);

		// Include votes for super-majority.
		submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

		// Voting concluded, can offboard even though an upgrade is in progress.
		assert_ok!(Paras::schedule_para_cleanup(para_id));
	});
}

#[test]
fn para_incoming_at_session() {
	let code_a = ValidationCode(vec![2]);
	let code_b = ValidationCode(vec![1]);
	let code_c = ValidationCode(vec![3]);

	let genesis_config = MockGenesisConfig::default();

	new_test_ext(genesis_config).execute_with(|| {
		run_to_block(1, Some(vec![1]));

		let b = ParaId::from(525);
		let a = ParaId::from(999);
		let c = ParaId::from(333);

		assert_ok!(Paras::schedule_para_initialize(
			b,
			ParaGenesisArgs {
				para_kind: ParaKind::Parachain,
				genesis_head: vec![1].into(),
				validation_code: code_b.clone(),
			},
		));

		assert_ok!(Paras::schedule_para_initialize(
			a,
			ParaGenesisArgs {
				para_kind: ParaKind::Parathread,
				genesis_head: vec![2].into(),
				validation_code: code_a.clone(),
			},
		));

		assert_ok!(Paras::schedule_para_initialize(
			c,
			ParaGenesisArgs {
				para_kind: ParaKind::Parachain,
				genesis_head: vec![3].into(),
				validation_code: code_c.clone(),
			},
		));

		IntoIterator::into_iter([0, 1, 2, 3])
			.map(|i| PvfCheckStatement {
				accept: true,
				subject: code_a.hash(),
				session_index: 1,
				validator_index: i.into(),
			})
			.for_each(sign_and_include_pvf_check_statement);

		IntoIterator::into_iter([1, 2, 3, 4])
			.map(|i| PvfCheckStatement {
				accept: true,
				subject: code_b.hash(),
				session_index: 1,
				validator_index: i.into(),
			})
			.for_each(sign_and_include_pvf_check_statement);

		IntoIterator::into_iter([0, 2, 3, 4])
			.map(|i| PvfCheckStatement {
				accept: true,
				subject: code_c.hash(),
				session_index: 1,
				validator_index: i.into(),
			})
			.for_each(sign_and_include_pvf_check_statement);

		assert_eq!(ActionsQueue::<Test>::get(Paras::scheduled_session()), vec![c, b, a],);

		// Lifecycle is tracked correctly
		assert_eq!(ParaLifecycles::<Test>::get(&a), Some(ParaLifecycle::Onboarding));
		assert_eq!(ParaLifecycles::<Test>::get(&b), Some(ParaLifecycle::Onboarding));
		assert_eq!(ParaLifecycles::<Test>::get(&c), Some(ParaLifecycle::Onboarding));

		// run to block without session change.
		run_to_block(2, None);

		assert_eq!(paras::Parachains::<Test>::get(), Vec::new());
		assert_eq!(ActionsQueue::<Test>::get(Paras::scheduled_session()), vec![c, b, a],);

		// Lifecycle is tracked correctly
		assert_eq!(ParaLifecycles::<Test>::get(&a), Some(ParaLifecycle::Onboarding));
		assert_eq!(ParaLifecycles::<Test>::get(&b), Some(ParaLifecycle::Onboarding));
		assert_eq!(ParaLifecycles::<Test>::get(&c), Some(ParaLifecycle::Onboarding));

		// Two sessions pass, so action queue is triggered
		run_to_block(4, Some(vec![3, 4]));

		assert_eq!(paras::Parachains::<Test>::get(), vec![c, b]);
		assert_eq!(ActionsQueue::<Test>::get(Paras::scheduled_session()), Vec::new());

		// Lifecycle is tracked correctly
		assert_eq!(ParaLifecycles::<Test>::get(&a), Some(ParaLifecycle::Parathread));
		assert_eq!(ParaLifecycles::<Test>::get(&b), Some(ParaLifecycle::Parachain));
		assert_eq!(ParaLifecycles::<Test>::get(&c), Some(ParaLifecycle::Parachain));

		assert_eq!(Paras::current_code(&a), Some(vec![2].into()));
		assert_eq!(Paras::current_code(&b), Some(vec![1].into()));
		assert_eq!(Paras::current_code(&c), Some(vec![3].into()));
	})
}

#[test]
fn code_hash_at_returns_up_to_end_of_code_retention_period() {
	let code_retention_period = 10;
	let validation_upgrade_delay = 2;

	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: test_validation_code_1(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		// Wait for at least one session change to set active validators.
		run_to_block(2, Some(vec![1]));
		const EXPECTED_SESSION: SessionIndex = 1;

		let para_id = ParaId::from(0);
		let old_code = test_validation_code_1();
		let new_code = test_validation_code_2();
		Paras::schedule_code_upgrade(
			para_id,
			new_code.clone(),
			0,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		// Include votes for super-majority.
		submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);

		// The new validation code can be applied but a new parablock hasn't gotten in yet,
		// so the old code should still be current.
		run_to_block(3, None);
		assert_eq!(Paras::current_code(&para_id), Some(old_code.clone()));

		run_to_block(10, None);
		Paras::note_new_head(para_id, Default::default(), 7);

		assert_eq!(
			paras::PastCodeMeta::<Test>::get(&para_id).upgrade_times,
			vec![upgrade_at(4, 10)]
		);
		assert_eq!(Paras::current_code(&para_id), Some(new_code.clone()));

		// Make sure that the old code is available **before** the code retention period passes.
		run_to_block(10 + code_retention_period, None);
		assert_eq!(paras::CodeByHash::<Test>::get(&old_code.hash()), Some(old_code.clone()));
		assert_eq!(paras::CodeByHash::<Test>::get(&new_code.hash()), Some(new_code.clone()));

		run_to_block(10 + code_retention_period + 1, None);

		// code entry should be pruned now.

		assert_eq!(
			paras::PastCodeMeta::<Test>::get(&para_id),
			ParaPastCodeMeta { upgrade_times: Vec::new(), last_pruned: Some(10) },
		);

		assert_eq!(paras::CodeByHash::<Test>::get(&old_code.hash()), None); // pruned :(
		assert_eq!(paras::CodeByHash::<Test>::get(&new_code.hash()), Some(new_code.clone()));
	});
}

#[test]
fn code_ref_is_cleaned_correctly() {
	new_test_ext(Default::default()).execute_with(|| {
		let code = test_validation_code_1();
		Paras::increase_code_ref(&code.hash(), &code);
		Paras::increase_code_ref(&code.hash(), &code);

		assert!(CodeByHash::<Test>::contains_key(code.hash()));
		assert_eq!(CodeByHashRefs::<Test>::get(code.hash()), 2);

		Paras::decrease_code_ref(&code.hash());

		assert!(CodeByHash::<Test>::contains_key(code.hash()));
		assert_eq!(CodeByHashRefs::<Test>::get(code.hash()), 1);

		Paras::decrease_code_ref(&code.hash());

		assert!(!CodeByHash::<Test>::contains_key(code.hash()));
		assert!(!CodeByHashRefs::<Test>::contains_key(code.hash()));
	});
}

#[test]
fn pvf_check_coalescing_onboarding_and_upgrade() {
	let validation_upgrade_delay = 5;

	let a = ParaId::from(111);
	let b = ParaId::from(222);
	let existing_code = test_validation_code_1();
	let validation_code = test_validation_code_2();

	let paras = vec![(
		a,
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: Default::default(),
			validation_code: existing_code,
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration { validation_upgrade_delay, ..Default::default() },
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		// At this point `a` is already onboarded. Run to block 1 performing session change at
		// the end of block #0.
		run_to_block(2, Some(vec![1]));

		// Expected current session index.
		const EXPECTED_SESSION: SessionIndex = 1;
		// Relay parent of the parablock that schedules the upgrade.
		const RELAY_PARENT: BlockNumber = 1;

		// Now we register `b` with `validation_code`
		assert_ok!(Paras::schedule_para_initialize(
			b,
			ParaGenesisArgs {
				para_kind: ParaKind::Parachain,
				genesis_head: vec![2].into(),
				validation_code: validation_code.clone(),
			},
		));

		// And now at the same time upgrade `a` to `validation_code`
		Paras::schedule_code_upgrade(
			a,
			validation_code.clone(),
			RELAY_PARENT,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		assert!(!Paras::pvfs_require_precheck().is_empty());

		// Supermajority of validators vote for `validation_code`. It should be approved.
		submit_super_majority_pvf_votes(&validation_code, EXPECTED_SESSION, true);

		// Check that `b` actually onboards.
		assert_eq!(ActionsQueue::<Test>::get(EXPECTED_SESSION + 2), vec![b]);

		// Check that the upgrade got scheduled.
		assert_eq!(
			FutureCodeUpgrades::<Test>::get(&a),
			Some(RELAY_PARENT + validation_upgrade_delay),
		);

		// Verify that the required events were emitted.
		EventValidator::new()
			.started(&validation_code, b)
			.started(&validation_code, a)
			.accepted(&validation_code, b)
			.accepted(&validation_code, a)
			.check();
	});
}

#[test]
fn pvf_check_onboarding_reject_on_expiry() {
	let pvf_voting_ttl = 2;
	let a = ParaId::from(111);
	let validation_code = test_validation_code_1();

	let genesis_config = MockGenesisConfig {
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration { pvf_voting_ttl, ..Default::default() },
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		run_to_block(1, Some(vec![1]));

		assert_ok!(Paras::schedule_para_initialize(
			a,
			ParaGenesisArgs {
				para_kind: ParaKind::Parathread,
				genesis_head: vec![2].into(),
				validation_code: validation_code.clone(),
			},
		));

		// Make sure that we kicked off the PVF vote for this validation code and that the
		// validation code is stored.
		assert!(PvfActiveVoteMap::<Test>::get(&validation_code.hash()).is_some());
		check_code_is_stored(&validation_code);

		// Skip 2 sessions (i.e. `pvf_voting_ttl`) verifying that the code is still stored in
		// the intermediate session.
		assert_eq!(pvf_voting_ttl, 2);
		run_to_block(2, Some(vec![2]));
		check_code_is_stored(&validation_code);
		run_to_block(3, Some(vec![3]));

		// --- At this point the PVF vote for onboarding should be rejected.

		// Verify that the PVF is no longer stored and there is no active PVF vote.
		check_code_is_not_stored(&validation_code);
		assert!(PvfActiveVoteMap::<Test>::get(&validation_code.hash()).is_none());
		assert!(Paras::pvfs_require_precheck().is_empty());

		// Verify that at this point we can again try to initialize the same para.
		assert!(Paras::can_schedule_para_initialize(&a));
	});
}

#[test]
fn pvf_check_upgrade_reject() {
	let a = ParaId::from(111);
	let old_code = test_validation_code_1();
	let new_code = test_validation_code_2();

	let paras = vec![(
		a,
		ParaGenesisArgs {
			para_kind: ParaKind::Parathread,
			genesis_head: Default::default(),
			validation_code: old_code,
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		// At this point `a` is already onboarded. Run to block 1 performing session change at
		// the end of block #0.
		run_to_block(2, Some(vec![1]));

		// Relay parent of the block that schedules the upgrade.
		const RELAY_PARENT: BlockNumber = 1;
		// Expected current session index.
		const EXPECTED_SESSION: SessionIndex = 1;

		Paras::schedule_code_upgrade(
			a,
			new_code.clone(),
			RELAY_PARENT,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		check_code_is_stored(&new_code);

		// 1/3 of validators vote against `new_code`. PVF should not be rejected yet.
		sign_and_include_pvf_check_statement(PvfCheckStatement {
			accept: false,
			subject: new_code.hash(),
			session_index: EXPECTED_SESSION,
			validator_index: 0.into(),
		});

		// Verify that the new code is not yet discarded.
		check_code_is_stored(&new_code);

		// >1/3 of validators vote against `new_code`. PVF should be rejected.
		sign_and_include_pvf_check_statement(PvfCheckStatement {
			accept: false,
			subject: new_code.hash(),
			session_index: EXPECTED_SESSION,
			validator_index: 1.into(),
		});

		// Verify that the new code is discarded.
		check_code_is_not_stored(&new_code);

		assert!(PvfActiveVoteMap::<Test>::get(&new_code.hash()).is_none());
		assert!(Paras::pvfs_require_precheck().is_empty());
		assert!(FutureCodeHash::<Test>::get(&a).is_none());

		// Verify that the required events were emitted.
		EventValidator::new().started(&new_code, a).rejected(&new_code, a).check();
	});
}

#[test]
fn pvf_check_submit_vote() {
	let code_a = test_validation_code_1();
	let code_b = test_validation_code_2();

	let check = |stmt: PvfCheckStatement| -> (Result<_, _>, Result<_, _>) {
		let validators = &[
			Sr25519Keyring::Alice,
			Sr25519Keyring::Bob,
			Sr25519Keyring::Charlie,
			Sr25519Keyring::Dave,
			Sr25519Keyring::Ferdie,
			Sr25519Keyring::Eve, // <- this validator is not in the set
		];
		let signature: ValidatorSignature =
			validators[stmt.validator_index.0 as usize].sign(&stmt.signing_payload()).into();

		let call =
			Call::include_pvf_check_statement { stmt: stmt.clone(), signature: signature.clone() };
		let validate_unsigned =
			<Paras as ValidateUnsigned>::validate_unsigned(TransactionSource::InBlock, &call)
				.map(|_| ());
		let dispatch_result =
			Paras::include_pvf_check_statement(None.into(), stmt.clone(), signature.clone())
				.map(|_| ());

		(validate_unsigned, dispatch_result)
	};

	let genesis_config = MockGenesisConfig::default();

	new_test_ext(genesis_config).execute_with(|| {
		// Important to run this to seed the validators.
		run_to_block(1, Some(vec![1]));

		assert_ok!(Paras::schedule_para_initialize(
			1000.into(),
			ParaGenesisArgs {
				para_kind: ParaKind::Parathread,
				genesis_head: vec![2].into(),
				validation_code: code_a.clone(),
			},
		));

		assert_eq!(
			check(PvfCheckStatement {
				accept: false,
				subject: code_a.hash(),
				session_index: 1,
				validator_index: 1.into(),
			}),
			(Ok(()), Ok(())),
		);

		// A vote in the same direction.
		let (unsigned, dispatch) = check(PvfCheckStatement {
			accept: false,
			subject: code_a.hash(),
			session_index: 1,
			validator_index: 1.into(),
		});
		assert_eq!(unsigned, Err(InvalidTransaction::Custom(INVALID_TX_DOUBLE_VOTE).into()));
		assert_err!(dispatch, Error::<Test>::PvfCheckDoubleVote);

		// Equivocation
		let (unsigned, dispatch) = check(PvfCheckStatement {
			accept: true,
			subject: code_a.hash(),
			session_index: 1,
			validator_index: 1.into(),
		});
		assert_eq!(unsigned, Err(InvalidTransaction::Custom(INVALID_TX_DOUBLE_VOTE).into()));
		assert_err!(dispatch, Error::<Test>::PvfCheckDoubleVote);

		// Vote for an earlier session.
		let (unsigned, dispatch) = check(PvfCheckStatement {
			accept: false,
			subject: code_a.hash(),
			session_index: 0,
			validator_index: 1.into(),
		});
		assert_eq!(unsigned, Err(InvalidTransaction::Stale.into()));
		assert_err!(dispatch, Error::<Test>::PvfCheckStatementStale);

		// Vote for an later session.
		let (unsigned, dispatch) = check(PvfCheckStatement {
			accept: false,
			subject: code_a.hash(),
			session_index: 2,
			validator_index: 1.into(),
		});
		assert_eq!(unsigned, Err(InvalidTransaction::Future.into()));
		assert_err!(dispatch, Error::<Test>::PvfCheckStatementFuture);

		// Validator not in the set.
		let (unsigned, dispatch) = check(PvfCheckStatement {
			accept: false,
			subject: code_a.hash(),
			session_index: 1,
			validator_index: 5.into(),
		});
		assert_eq!(unsigned, Err(InvalidTransaction::Custom(INVALID_TX_BAD_VALIDATOR_IDX).into()));
		assert_err!(dispatch, Error::<Test>::PvfCheckValidatorIndexOutOfBounds);

		// Bad subject (code_b)
		let (unsigned, dispatch) = check(PvfCheckStatement {
			accept: false,
			subject: code_b.hash(),
			session_index: 1,
			validator_index: 1.into(),
		});
		assert_eq!(unsigned, Err(InvalidTransaction::Custom(INVALID_TX_BAD_SUBJECT).into()));
		assert_err!(dispatch, Error::<Test>::PvfCheckSubjectInvalid);
	});
}

#[test]
fn include_pvf_check_statement_refunds_weight() {
	let a = ParaId::from(111);
	let old_code = test_validation_code_1();
	let new_code = test_validation_code_2();

	let paras = vec![(
		a,
		ParaGenesisArgs {
			para_kind: ParaKind::Parathread,
			genesis_head: Default::default(),
			validation_code: old_code,
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		// At this point `a` is already onboarded. Run to block 1 performing session change at
		// the end of block #0.
		run_to_block(2, Some(vec![1]));

		// Relay parent of the block that schedules the upgrade.
		const RELAY_PARENT: BlockNumber = 1;
		// Expected current session index.
		const EXPECTED_SESSION: SessionIndex = 1;

		Paras::schedule_code_upgrade(
			a,
			new_code.clone(),
			RELAY_PARENT,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);

		let mut stmts = IntoIterator::into_iter([0, 1, 2, 3])
			.map(|i| {
				let stmt = PvfCheckStatement {
					accept: true,
					subject: new_code.hash(),
					session_index: EXPECTED_SESSION,
					validator_index: (i as u32).into(),
				};
				let sig = VALIDATORS[i].sign(&stmt.signing_payload());
				(stmt, sig)
			})
			.collect::<Vec<_>>();
		let last_one = stmts.pop().unwrap();

		// Verify that just vote submission is priced accordingly.
		for (stmt, sig) in stmts {
			let r = Paras::include_pvf_check_statement(None.into(), stmt, sig.into()).unwrap();
			assert_eq!(r.actual_weight, Some(TestWeightInfo::include_pvf_check_statement()));
		}

		// Verify that the last statement is priced maximally.
		let (stmt, sig) = last_one;
		let r = Paras::include_pvf_check_statement(None.into(), stmt, sig.into()).unwrap();
		assert_eq!(r.actual_weight, None);
	});
}

#[test]
fn add_trusted_validation_code_inserts_with_no_users() {
	// This test is to ensure that trusted validation code is inserted into the storage
	// with the reference count equal to 0.
	let validation_code = test_validation_code_1();
	new_test_ext(Default::default()).execute_with(|| {
		assert_ok!(Paras::add_trusted_validation_code(
			RuntimeOrigin::root(),
			validation_code.clone()
		));
		assert_eq!(CodeByHashRefs::<Test>::get(&validation_code.hash()), 0,);
	});
}

#[test]
fn add_trusted_validation_code_idempotent() {
	// This test makes sure that calling add_trusted_validation_code twice with the same
	// parameters is a no-op.
	let validation_code = test_validation_code_1();
	new_test_ext(Default::default()).execute_with(|| {
		assert_ok!(Paras::add_trusted_validation_code(
			RuntimeOrigin::root(),
			validation_code.clone()
		));
		assert_storage_noop!({
			assert_ok!(Paras::add_trusted_validation_code(
				RuntimeOrigin::root(),
				validation_code.clone()
			));
		});
	});
}

#[test]
fn poke_unused_validation_code_removes_code_cleanly() {
	// This test makes sure that calling poke_unused_validation_code with a code that is currently
	// in the storage but has no users will remove it cleanly from the storage.
	let validation_code = test_validation_code_1();
	new_test_ext(Default::default()).execute_with(|| {
		assert_ok!(Paras::add_trusted_validation_code(
			RuntimeOrigin::root(),
			validation_code.clone()
		));
		assert_ok!(Paras::poke_unused_validation_code(
			RuntimeOrigin::root(),
			validation_code.hash()
		));

		assert_eq!(CodeByHashRefs::<Test>::get(&validation_code.hash()), 0);
		assert!(!CodeByHash::<Test>::contains_key(&validation_code.hash()));
	});
}

#[test]
fn poke_unused_validation_code_doesnt_remove_code_with_users() {
	let para_id = 100.into();
	let validation_code = test_validation_code_1();
	new_test_ext(Default::default()).execute_with(|| {
		// First we add the code to the storage.
		assert_ok!(Paras::add_trusted_validation_code(
			RuntimeOrigin::root(),
			validation_code.clone()
		));

		// Then we add a user to the code, say by upgrading.
		run_to_block(2, None);
		Paras::schedule_code_upgrade(
			para_id,
			validation_code.clone(),
			1,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		Paras::note_new_head(para_id, HeadData::default(), 1);

		// Finally we poke the code, which should not remove it from the storage.
		assert_storage_noop!({
			assert_ok!(Paras::poke_unused_validation_code(
				RuntimeOrigin::root(),
				validation_code.hash()
			));
		});
		check_code_is_stored(&validation_code);
	});
}

#[test]
fn increase_code_ref_doesnt_have_allergy_on_add_trusted_validation_code() {
	// Verify that accidental calling of increase_code_ref or decrease_code_ref does not lead
	// to a disaster.
	// NOTE that this test is extra paranoid, as it is not really possible to hit
	// `decrease_code_ref` without calling `increase_code_ref` first.
	let code = test_validation_code_1();

	new_test_ext(Default::default()).execute_with(|| {
		assert_ok!(Paras::add_trusted_validation_code(RuntimeOrigin::root(), code.clone()));
		Paras::increase_code_ref(&code.hash(), &code);
		Paras::increase_code_ref(&code.hash(), &code);
		assert!(CodeByHash::<Test>::contains_key(code.hash()));
		assert_eq!(CodeByHashRefs::<Test>::get(code.hash()), 2);
	});

	new_test_ext(Default::default()).execute_with(|| {
		assert_ok!(Paras::add_trusted_validation_code(RuntimeOrigin::root(), code.clone()));
		Paras::decrease_code_ref(&code.hash());
		assert!(CodeByHash::<Test>::contains_key(code.hash()));
		assert_eq!(CodeByHashRefs::<Test>::get(code.hash()), 0);
	});
}

#[test]
fn add_trusted_validation_code_insta_approval() {
	// In particular, this tests that `kick_off_pvf_check` reacts to the
	// `add_trusted_validation_code` and uses the `CodeByHash::contains_key` which is what
	// `add_trusted_validation_code` uses.
	let para_id = 100.into();
	let validation_code = test_validation_code_1();
	let validation_upgrade_delay = 25;
	let minimum_validation_upgrade_delay = 2;
	let genesis_config = MockGenesisConfig {
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				validation_upgrade_delay,
				minimum_validation_upgrade_delay,
				..Default::default()
			},
		},
		..Default::default()
	};
	new_test_ext(genesis_config).execute_with(|| {
		assert_ok!(Paras::add_trusted_validation_code(
			RuntimeOrigin::root(),
			validation_code.clone()
		));

		// Then some parachain upgrades it's code with the relay-parent 1.
		run_to_block(2, None);
		Paras::schedule_code_upgrade(
			para_id,
			validation_code.clone(),
			1,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		Paras::note_new_head(para_id, HeadData::default(), 1);

		// Verify that the code upgrade has `expected_at` set to `26`.
		assert_eq!(FutureCodeUpgrades::<Test>::get(&para_id), Some(1 + validation_upgrade_delay));

		// Verify that the required events were emitted.
		EventValidator::new()
			.started(&validation_code, para_id)
			.accepted(&validation_code, para_id)
			.check();
	});
}

#[test]
fn add_trusted_validation_code_enacts_existing_pvf_vote() {
	// This test makes sure that calling `add_trusted_validation_code` with a code that is
	// already going through PVF pre-checking voting will conclude the voting and enact the
	// code upgrade.
	let para_id = 100.into();
	let validation_code = test_validation_code_1();
	let validation_upgrade_delay = 25;
	let minimum_validation_upgrade_delay = 2;
	let genesis_config = MockGenesisConfig {
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				validation_upgrade_delay,
				minimum_validation_upgrade_delay,
				..Default::default()
			},
		},
		..Default::default()
	};
	new_test_ext(genesis_config).execute_with(|| {
		// First, some parachain upgrades it's code with the relay-parent 1.
		run_to_block(2, None);
		Paras::schedule_code_upgrade(
			para_id,
			validation_code.clone(),
			1,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::SetGoAheadSignal,
		);
		Paras::note_new_head(para_id, HeadData::default(), 1);

		// No upgrade should be scheduled at this point. PVF pre-checking vote should run for
		// that PVF.
		assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_none());
		assert!(PvfActiveVoteMap::<Test>::contains_key(&validation_code.hash()));

		// Then we add a trusted validation code. That should conclude the vote.
		assert_ok!(Paras::add_trusted_validation_code(
			RuntimeOrigin::root(),
			validation_code.clone()
		));
		assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_some());
		assert!(!PvfActiveVoteMap::<Test>::contains_key(&validation_code.hash()));
	});
}

#[test]
fn verify_upgrade_go_ahead_signal_is_externally_accessible() {
	use polkadot_primitives::well_known_keys;

	let a = ParaId::from(2020);

	new_test_ext(Default::default()).execute_with(|| {
		assert!(sp_io::storage::get(&well_known_keys::upgrade_go_ahead_signal(a)).is_none());
		UpgradeGoAheadSignal::<Test>::insert(&a, UpgradeGoAhead::GoAhead);
		assert_eq!(
			sp_io::storage::get(&well_known_keys::upgrade_go_ahead_signal(a)).unwrap(),
			vec![1u8],
		);
	});
}

#[test]
fn verify_upgrade_restriction_signal_is_externally_accessible() {
	use polkadot_primitives::well_known_keys;

	let a = ParaId::from(2020);

	new_test_ext(Default::default()).execute_with(|| {
		assert!(sp_io::storage::get(&well_known_keys::upgrade_restriction_signal(a)).is_none());
		UpgradeRestrictionSignal::<Test>::insert(&a, UpgradeRestriction::Present);
		assert_eq!(
			sp_io::storage::get(&well_known_keys::upgrade_restriction_signal(a)).unwrap(),
			vec![0],
		);
	});
}

#[test]
fn verify_para_head_is_externally_accessible() {
	use polkadot_primitives::well_known_keys;

	let a = ParaId::from(2020);
	let expected_head_data = HeadData(vec![0, 1, 2, 3]);

	new_test_ext(Default::default()).execute_with(|| {
		Heads::<Test>::insert(&a, expected_head_data.clone());
		let encoded = sp_io::storage::get(&well_known_keys::para_head(a)).unwrap();
		let head_data = HeadData::decode(&mut encoded.as_ref());
		assert_eq!(head_data, Ok(expected_head_data));
	});
}

#[test]
fn most_recent_context() {
	let validation_code = test_validation_code_1();

	let genesis_config = MockGenesisConfig::default();

	new_test_ext(genesis_config).execute_with(|| {
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(1, Some(vec![1]));

		let para_id = ParaId::from(111);

		assert_eq!(paras::MostRecentContext::<Test>::get(para_id), None);

		assert_ok!(Paras::schedule_para_initialize(
			para_id,
			ParaGenesisArgs {
				para_kind: ParaKind::Parachain,
				genesis_head: vec![1].into(),
				validation_code: validation_code.clone(),
			},
		));
		submit_super_majority_pvf_votes(&validation_code, EXPECTED_SESSION, true);

		assert_eq!(ParaLifecycles::<Test>::get(&para_id), Some(ParaLifecycle::Onboarding));

		// Two sessions pass, so action queue is triggered.
		run_to_block(4, Some(vec![3, 4]));

		// Double-check the para is onboarded, the context is set to the recent block.
		assert_eq!(ParaLifecycles::<Test>::get(&para_id), Some(ParaLifecycle::Parachain));
		assert_eq!(paras::MostRecentContext::<Test>::get(para_id), Some(0));

		// Progress para to the new head and check that the recent context is updated.
		Paras::note_new_head(para_id, vec![4, 5, 6].into(), 3);
		assert_eq!(paras::MostRecentContext::<Test>::get(para_id), Some(3));

		// Finally, offboard the para and expect the context to be cleared.
		assert_ok!(Paras::schedule_para_cleanup(para_id));
		run_to_block(6, Some(vec![5, 6]));
		assert_eq!(paras::MostRecentContext::<Test>::get(para_id), None);
	})
}

#[test]
fn parakind_encodes_decodes_to_bool_scale() {
	let chain_kind = ParaKind::Parachain.encode();
	let chain_bool = true.encode();
	assert_eq!(chain_kind, chain_bool);

	let chain_dec = ParaKind::decode(&mut chain_kind.as_slice());
	assert_eq!(chain_dec, Ok(ParaKind::Parachain));

	let thread_kind = ParaKind::Parathread.encode();
	let thread_bool = false.encode();
	assert_eq!(thread_kind, thread_bool);

	let thread_dec = ParaKind::decode(&mut thread_kind.as_slice());
	assert_eq!(thread_dec, Ok(ParaKind::Parathread));

	assert_eq!(bool::type_info(), ParaKind::type_info());
}

#[test]
fn parakind_encodes_decodes_to_bool_serde() {
	let chain = ParaKind::Parachain;
	let ser_chain = serde_json::to_string(&ParaKind::Parachain).unwrap();
	let de_chain: ParaKind = serde_json::from_str(&ser_chain).unwrap();
	assert_eq!(chain, de_chain);

	let ser_true = serde_json::to_string(&true).unwrap();
	assert_eq!(ser_true, ser_chain);

	let thread = ParaKind::Parathread;
	let ser_thread = serde_json::to_string(&thread).unwrap();
	let de_thread: ParaKind = serde_json::from_str(&ser_thread).unwrap();
	assert_eq!(thread, de_thread);

	let ser_false = serde_json::to_string(&false).unwrap();
	assert_eq!(ser_false, ser_thread);
}

#[test]
fn parachains_cache_is_set() {
	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		let a = ParaId::from(111);

		let mut parachains_cache: ParachainsCache<Test> = ParachainsCache::new();

		// Add element twice
		parachains_cache.add(a);
		parachains_cache.add(a);

		// Flush cache to storage
		drop(parachains_cache);

		// In order after addition
		assert_eq!(Parachains::<Test>::get(), vec![a]);

		let mut parachains_cache: ParachainsCache<Test> = ParachainsCache::new();

		// Remove element twice
		parachains_cache.remove(a);
		parachains_cache.remove(a);

		// Flush cache to storage
		drop(parachains_cache);

		// In order after removal
		assert_eq!(Parachains::<Test>::get(), vec![]);

		let mut parachains_cache: ParachainsCache<Test> = ParachainsCache::new();

		// Remove nonexisting element
		parachains_cache.remove(a);
		assert_storage_noop!(drop(parachains_cache));
		assert_eq!(Parachains::<Test>::get(), vec![]);
	});
}

#[test]
fn parachains_cache_preserves_order() {
	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		let a = ParaId::from(111);
		let b = ParaId::from(222);
		let c = ParaId::from(333);
		let d = ParaId::from(444);

		let mut parachains_cache: ParachainsCache<Test> = ParachainsCache::new();

		// Add in mixed order
		parachains_cache.add(b);
		parachains_cache.add(c);
		parachains_cache.add(a);
		parachains_cache.add(d);

		// Flush cache to storage
		drop(parachains_cache);

		// In order after addition
		assert_eq!(Parachains::<Test>::get(), vec![a, b, c, d]);

		let mut parachains_cache: ParachainsCache<Test> = ParachainsCache::new();

		// Remove 2 elements
		parachains_cache.remove(b);
		parachains_cache.remove(d);

		// Flush cache to storage
		drop(parachains_cache);

		// In order after removal
		assert_eq!(Parachains::<Test>::get(), vec![a, c]);
	});
}

#[test]
fn remove_upgrade_cooldown_works() {
	let code_retention_period = 10;
	let validation_upgrade_delay = 5;
	let validation_upgrade_cooldown = 10;

	let original_code = test_validation_code_1();
	let paras = vec![(
		0u32.into(),
		ParaGenesisArgs {
			para_kind: ParaKind::Parachain,
			genesis_head: dummy_head_data(),
			validation_code: original_code.clone(),
		},
	)];

	let genesis_config = MockGenesisConfig {
		paras: GenesisConfig { paras, ..Default::default() },
		configuration: crate::configuration::GenesisConfig {
			config: HostConfiguration {
				code_retention_period,
				validation_upgrade_delay,
				validation_upgrade_cooldown,
				..Default::default()
			},
		},
		..Default::default()
	};

	new_test_ext(genesis_config).execute_with(|| {
		check_code_is_stored(&original_code);

		let para_id = ParaId::from(0);
		let new_code = test_validation_code_2();

		// Wait for at least one session change to set active validators.
		const EXPECTED_SESSION: SessionIndex = 1;
		run_to_block(2, Some(vec![1]));
		assert_eq!(Paras::current_code(&para_id), Some(original_code.clone()));

		// this parablock is in the context of block 1.
		let expected_at = 1 + validation_upgrade_delay;
		let next_possible_upgrade_at = 1 + validation_upgrade_cooldown;
		// `set_go_ahead` parameter set to `false` which prevents signaling the parachain
		// with the `GoAhead` signal.
		Paras::schedule_code_upgrade(
			para_id,
			new_code.clone(),
			1,
			&configuration::ActiveConfig::<Test>::get(),
			UpgradeStrategy::ApplyAtExpectedBlock,
		);
		// Include votes for super-majority.
		submit_super_majority_pvf_votes(&new_code, EXPECTED_SESSION, true);
		assert!(FutureCodeUpgradesAt::<Test>::get().iter().any(|(id, _)| *id == para_id));

		// Going to the expected block triggers the upgrade directly.
		run_to_block(expected_at, None);

		// Reporting a head doesn't change anything.
		Paras::note_new_head(para_id, Default::default(), expected_at - 1);

		assert_eq!(
			paras::PastCodeMeta::<Test>::get(&para_id).most_recent_change(),
			Some(expected_at)
		);
		assert_eq!(PastCodeHash::<Test>::get(&(para_id, expected_at)), Some(original_code.hash()));
		assert!(FutureCodeUpgrades::<Test>::get(&para_id).is_none());
		assert!(FutureCodeUpgradesAt::<Test>::get().iter().all(|(id, _)| *id != para_id));
		assert!(FutureCodeHash::<Test>::get(&para_id).is_none());
		assert!(UpgradeGoAheadSignal::<Test>::get(&para_id).is_none());
		assert_eq!(Paras::current_code(&para_id), Some(new_code.clone()));
		assert_eq!(
			UpgradeRestrictionSignal::<Test>::get(&para_id),
			Some(UpgradeRestriction::Present),
		);
		assert_eq!(UpgradeCooldowns::<Test>::get(), vec![(para_id, next_possible_upgrade_at)]);
		check_code_is_stored(&original_code);
		check_code_is_stored(&new_code);

		assert_noop!(
			Call::<Test>::remove_upgrade_cooldown { para: para_id }
				.dispatch_bypass_filter(RuntimeOrigin::signed(1)),
			DispatchError::Token(TokenError::FundsUnavailable)
		);

		Balances::force_set_balance(RuntimeOrigin::root(), 1, 10000).unwrap();
		let issuance = Balances::total_issuance();

		assert_ok!(Call::<Test>::remove_upgrade_cooldown { para: para_id }
			.dispatch_bypass_filter(RuntimeOrigin::signed(1)));

		let expected_issuance = issuance -
			Pallet::<Test>::calculate_remove_upgrade_cooldown_cost(next_possible_upgrade_at);
		// Check that we burned the funds
		assert_eq!(expected_issuance, Balances::total_issuance());

		{
			assert!(UpgradeRestrictionSignal::<Test>::get(&para_id).is_none());
			assert!(UpgradeCooldowns::<Test>::get().is_empty());
		}
	});
}

#[test]
fn force_set_current_code_works() {
	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		let para_a = ParaId::from(111);
		let code_1 = ValidationCode(vec![1]);
		let code_1_hash = code_1.hash();

		// check before
		assert!(CurrentCodeHash::<Test>::get(para_a).is_none());
		check_code_is_not_stored(&code_1);

		// non-root user cannot execute
		assert_err!(
			Paras::force_set_current_code(RuntimeOrigin::signed(1), para_a, code_1.clone()),
			DispatchError::BadOrigin,
		);
		// root can execute
		assert_ok!(Paras::force_set_current_code(RuntimeOrigin::root(), para_a, code_1.clone()));

		// check after
		assert_eq!(CurrentCodeHash::<Test>::get(para_a), Some(code_1_hash));
		check_code_is_stored(&code_1);
	})
}

#[test]
fn authorize_force_set_current_code_hash_works() {
	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		let para_a = ParaId::from(111);
		let para_b = ParaId::from(222);
		let code_1 = ValidationCode(vec![1]);
		let code_2 = ValidationCode(vec![2]);
		let code_1_hash = code_1.hash();
		let code_2_hash = code_2.hash();
		let valid_period = 143;

		// check before
		assert_eq!(AuthorizedCodeHash::<Test>::iter().count(), 0);

		// non-root user cannot authorize
		assert_err!(
			Paras::authorize_force_set_current_code_hash(
				RuntimeOrigin::signed(1),
				para_a,
				code_1_hash,
				valid_period,
			),
			DispatchError::BadOrigin,
		);

		// root can authorize
		System::set_block_number(1);
		assert_ok!(Paras::authorize_force_set_current_code_hash(
			RuntimeOrigin::root(),
			para_a,
			code_1_hash,
			valid_period
		));
		assert_eq!(
			AuthorizedCodeHash::<Test>::get(&para_a),
			Some((code_1_hash, 1 + valid_period).into())
		);
		System::set_block_number(5);
		assert_ok!(Paras::authorize_force_set_current_code_hash(
			RuntimeOrigin::root(),
			para_b,
			code_2_hash,
			valid_period,
		));
		assert_eq!(
			AuthorizedCodeHash::<Test>::get(&para_b),
			Some((code_2_hash, 5 + valid_period).into())
		);
		assert_eq!(AuthorizedCodeHash::<Test>::iter().count(), 2);

		// request for the same para is overwritten
		assert_ok!(Paras::authorize_force_set_current_code_hash(
			RuntimeOrigin::root(),
			para_a,
			code_1_hash,
			valid_period
		));
		assert_eq!(
			AuthorizedCodeHash::<Test>::get(&para_a),
			Some((code_1_hash, 5 + valid_period).into())
		);
		assert_ok!(Paras::authorize_force_set_current_code_hash(
			RuntimeOrigin::root(),
			para_a,
			code_2_hash,
			valid_period
		));
		assert_eq!(
			AuthorizedCodeHash::<Test>::get(&para_a),
			Some((code_2_hash, 5 + valid_period).into())
		);
	})
}

#[test]
fn apply_authorized_force_set_current_code_works() {
	let apply_code = |origin,
	                  para: ParaId,
	                  code: ValidationCode|
	 -> (Result<_, _>, DispatchResultWithPostInfo) {
		let call = Call::apply_authorized_force_set_current_code { para, new_code: code.clone() };
		let validate_unsigned =
			<Paras as ValidateUnsigned>::validate_unsigned(TransactionSource::InBlock, &call)
				.map(|_| ());

		let dispatch_result = Paras::apply_authorized_force_set_current_code(origin, para, code);

		(validate_unsigned, dispatch_result)
	};

	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		let para_a = ParaId::from(111);
		let code_1 = ValidationCode(vec![1]);
		let code_2 = ValidationCode(vec![2]);
		let code_1_hash = code_1.hash();
		let valid_period = 143;

		// check before
		assert_eq!(AuthorizedCodeHash::<Test>::iter().count(), 0);

		// cannot apply code when nothing authorized
		assert_eq!(
			apply_code(RuntimeOrigin::signed(1), para_a, code_1.clone()),
			(
				Err(InvalidTransaction::Custom(INVALID_TX_UNAUTHORIZED_CODE).into()),
				Err(Error::<Test>::NothingAuthorized.into())
			),
		);

		// authorize
		System::set_block_number(5);
		AuthorizedCodeHash::<Test>::insert(
			&para_a,
			AuthorizedCodeHashAndExpiry::from((code_1_hash, valid_period + 5)),
		);

		// cannot apply unauthorized code_2
		assert_eq!(
			apply_code(RuntimeOrigin::signed(1), para_a, code_2.clone()),
			(
				Err(InvalidTransaction::Custom(INVALID_TX_UNAUTHORIZED_CODE).into()),
				Err(Error::<Test>::Unauthorized.into())
			),
		);

		// cannot apply obsolete authorization
		frame_system::Pallet::<Test>::set_block_number(valid_period + 5 + 10);
		assert_eq!(
			apply_code(RuntimeOrigin::signed(1), para_a, code_1.clone(),),
			(
				Err(InvalidTransaction::Custom(INVALID_TX_UNAUTHORIZED_CODE).into()),
				Err(Error::<Test>::InvalidBlockNumber.into())
			),
		);
		frame_system::Pallet::<Test>::set_block_number(5);

		// ok - can apply authorized code
		let (validate_unsigned, dispatch_result) =
			apply_code(RuntimeOrigin::signed(1), para_a, code_1.clone());
		assert_ok!(validate_unsigned);
		assert_ok!(dispatch_result);

		// check for removed
		assert!(AuthorizedCodeHash::<Test>::get(&para_a).is_none());

		// cannot apply previously authorized code again
		assert_eq!(
			apply_code(RuntimeOrigin::signed(1), para_a, code_1,),
			(
				Err(InvalidTransaction::Custom(INVALID_TX_UNAUTHORIZED_CODE).into()),
				Err(Error::<Test>::NothingAuthorized.into())
			),
		);
	})
}

#[test]
fn prune_expired_authorizations_works() {
	new_test_ext(MockGenesisConfig::default()).execute_with(|| {
		let para_a = ParaId::from(111);
		let para_b = ParaId::from(123);
		let code_1 = ValidationCode(vec![1]);
		let code_1_hash = code_1.hash();

		// add authorizations
		AuthorizedCodeHash::<Test>::insert(
			&para_a,
			AuthorizedCodeHashAndExpiry::from((code_1_hash, 201)),
		);
		AuthorizedCodeHash::<Test>::insert(
			&para_b,
			AuthorizedCodeHashAndExpiry::from((code_1_hash, 202)),
		);

		// nothing prunned at 200
		let _ = Paras::prune_expired_authorizations(200);
		assert_eq!(AuthorizedCodeHash::<Test>::get(&para_a), Some((code_1_hash, 201).into()));
		assert_eq!(AuthorizedCodeHash::<Test>::get(&para_b), Some((code_1_hash, 202).into()));

		// pruned at 201
		let _ = Paras::prune_expired_authorizations(201);
		assert!(AuthorizedCodeHash::<Test>::get(&para_a).is_none());
		assert_eq!(AuthorizedCodeHash::<Test>::get(&para_b), Some((code_1_hash, 202).into()));

		// pruned at 203
		let _ = Paras::prune_expired_authorizations(203);
		assert!(AuthorizedCodeHash::<Test>::get(&para_a).is_none());
		assert!(AuthorizedCodeHash::<Test>::get(&para_b).is_none());
	})
}
