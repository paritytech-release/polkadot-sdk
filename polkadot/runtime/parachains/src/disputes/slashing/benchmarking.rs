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

use crate::{disputes::SlashingHandler, initializer, shared};
use codec::Decode;
use frame_benchmarking::v2::*;
use frame_support::traits::{OnFinalize, OnInitialize};
use frame_system::{pallet_prelude::BlockNumberFor, RawOrigin};
use pallet_staking::testing_utils::create_validators;
use polkadot_primitives::{Hash, PARACHAIN_KEY_TYPE_ID};
use sp_runtime::traits::{One, OpaqueKeys, StaticLookup};
use sp_session::MembershipProof;

// Candidate hash of the disputed candidate.
const CANDIDATE_HASH: CandidateHash = CandidateHash(Hash::zero());

// Simplify getting the value in the benchmark
pub const fn max_validators_for<T: super::Config>() -> u32 {
	<<T>::BenchmarkingConfig as BenchmarkingConfiguration>::MAX_VALIDATORS
}

pub trait Config:
	pallet_session::Config
	+ pallet_session::historical::Config
	+ pallet_staking::Config
	+ super::Config
	+ shared::Config
	+ initializer::Config
{
}

fn setup_validator_set<T>(n: u32) -> (SessionIndex, MembershipProof, ValidatorId)
where
	T: Config,
{
	pallet_staking::ValidatorCount::<T>::put(n);

	let balance_factor = 1000;
	// create validators and set random session keys
	for (n, who) in create_validators::<T>(n, balance_factor).unwrap().into_iter().enumerate() {
		use rand::{RngCore, SeedableRng};

		let validator = T::Lookup::lookup(who).unwrap();
		let controller = pallet_staking::Pallet::<T>::bonded(&validator).unwrap();

		let keys = {
			const SESSION_KEY_LEN: usize = 32;
			let key_ids = T::Keys::key_ids();
			let mut keys_len = key_ids.len() * SESSION_KEY_LEN;
			if key_ids.contains(&sp_core::crypto::key_types::BEEFY) {
				// BEEFY key is 33 bytes long, not 32.
				keys_len += 1;
			}
			let mut keys = vec![0u8; keys_len];
			let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(n as u64);
			rng.fill_bytes(&mut keys);
			keys
		};

		let keys: T::Keys = Decode::decode(&mut &keys[..]).expect("wrong number of session keys?");
		let proof: Vec<u8> = vec![];

		whitelist_account!(controller);
		pallet_session::Pallet::<T>::set_keys(RawOrigin::Signed(controller).into(), keys, proof)
			.expect("session::set_keys should work");
	}

	pallet_session::Pallet::<T>::on_initialize(BlockNumberFor::<T>::one());
	initializer::Pallet::<T>::on_initialize(BlockNumberFor::<T>::one());

	// signal to `pallet-staking`'s `ElectionProvider` to be ready asap.
	use frame_election_provider_support::ElectionProvider;
	<<T as pallet_staking::Config>::ElectionProvider as ElectionProvider>::asap();

	// skip sessions until the new validator set is enacted
	while pallet_session::Pallet::<T>::validators().len() < n as usize {
		pallet_session::Pallet::<T>::rotate_session();
	}
	initializer::Pallet::<T>::on_finalize(BlockNumberFor::<T>::one());

	let session_index = crate::shared::CurrentSessionIndex::<T>::get();
	let session_info = crate::session_info::Sessions::<T>::get(session_index);
	let session_info = session_info.unwrap();
	let validator_id = session_info.validators.get(ValidatorIndex::from(0)).unwrap().clone();
	let key = (PARACHAIN_KEY_TYPE_ID, validator_id.clone());
	let key_owner_proof = pallet_session::historical::Pallet::<T>::prove(key).unwrap();

	// rotate a session to make sure `key_owner_proof` is historical
	initializer::Pallet::<T>::on_initialize(BlockNumberFor::<T>::one());
	pallet_session::Pallet::<T>::rotate_session();
	initializer::Pallet::<T>::on_finalize(BlockNumberFor::<T>::one());

	let idx = crate::shared::CurrentSessionIndex::<T>::get();
	assert!(
		idx > session_index,
		"session rotation should work for parachain pallets: {} <= {}",
		idx,
		session_index,
	);

	(session_index, key_owner_proof, validator_id)
}

/// Submits a single `ForInvalid` dispute.
fn setup_dispute<T>(session_index: SessionIndex, validator_id: ValidatorId) -> DisputeProofV2
where
	T: Config,
{
	let current_session = T::ValidatorSet::session_index();
	assert_ne!(session_index, current_session);

	let validator_index = ValidatorIndex(0);
	let losers = [validator_index].into_iter();
	let backers = losers.clone();

	T::SlashingHandler::punish_for_invalid(session_index, CANDIDATE_HASH, losers, backers);

	let unapplied = <UnappliedSlashes<T>>::get(session_index, CANDIDATE_HASH);
	assert_eq!(unapplied.unwrap().keys.len(), 1);

	dispute_proof(session_index, validator_id, validator_index)
}

/// Creates a `ForInvalid` dispute proof.
fn dispute_proof(
	session_index: SessionIndex,
	validator_id: ValidatorId,
	validator_index: ValidatorIndex,
) -> DisputeProofV2 {
	let kind = DisputeOffenceKind::ForInvalidBacked;
	let time_slot = DisputesTimeSlot::new(session_index, CANDIDATE_HASH);

	DisputeProofV2 { time_slot, kind, validator_index, validator_id }
}

#[benchmarks(where T: Config<KeyOwnerProof = MembershipProof>)]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn report_dispute_lost_unsigned(n: Linear<4, { max_validators_for::<T>() }>) {
		let (session_index, key_owner_proof, validator_id) = setup_validator_set::<T>(n);

		// submit a single `ForInvalid` dispute for a past session.
		let dispute_proof = setup_dispute::<T>(session_index, validator_id);

		#[extrinsic_call]
		_(RawOrigin::None, Box::new(dispute_proof), key_owner_proof);

		let unapplied = <UnappliedSlashes<T>>::get(session_index, CANDIDATE_HASH);
		assert!(unapplied.is_none());
	}
}
