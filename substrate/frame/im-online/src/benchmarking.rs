// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
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

//! I'm Online pallet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::v2::*;
use frame_support::{traits::UnfilteredDispatchable, WeakBoundedVec};
use frame_system::RawOrigin;
use sp_runtime::{
	traits::{ValidateUnsigned, Zero},
	transaction_validity::TransactionSource,
};

use crate::*;

pub fn create_heartbeat<T: Config>(
	k: u32,
) -> Result<
	(
		crate::Heartbeat<frame_system::pallet_prelude::BlockNumberFor<T>>,
		<T::AuthorityId as RuntimeAppPublic>::Signature,
	),
	&'static str,
> {
	let mut keys = Vec::new();
	for _ in 0..k {
		keys.push(T::AuthorityId::generate_pair(None));
	}
	let bounded_keys = WeakBoundedVec::<_, T::MaxKeys>::try_from(keys.clone())
		.map_err(|()| "More than the maximum number of keys provided")?;
	Keys::<T>::put(bounded_keys);

	let input_heartbeat = Heartbeat {
		block_number: frame_system::pallet_prelude::BlockNumberFor::<T>::zero(),
		session_index: 0,
		authority_index: k - 1,
		validators_len: keys.len() as u32,
	};

	let encoded_heartbeat = input_heartbeat.encode();
	let authority_id = keys.get((k - 1) as usize).ok_or("out of range")?;
	let signature = authority_id.sign(&encoded_heartbeat).ok_or("couldn't make signature")?;

	Ok((input_heartbeat, signature))
}

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark(extra)]
	fn heartbeat(k: Linear<1, { <T as Config>::MaxKeys::get() }>) -> Result<(), BenchmarkError> {
		let (input_heartbeat, signature) = create_heartbeat::<T>(k)?;

		#[extrinsic_call]
		_(RawOrigin::None, input_heartbeat, signature);

		Ok(())
	}

	#[benchmark(extra)]
	fn validate_unsigned(
		k: Linear<1, { <T as Config>::MaxKeys::get() }>,
	) -> Result<(), BenchmarkError> {
		let (input_heartbeat, signature) = create_heartbeat::<T>(k)?;
		let call = Call::heartbeat { heartbeat: input_heartbeat, signature };

		#[block]
		{
			Pallet::<T>::validate_unsigned(TransactionSource::InBlock, &call)
				.map_err(<&str>::from)?;
		}

		Ok(())
	}

	#[benchmark]
	fn validate_unsigned_and_then_heartbeat(
		k: Linear<1, { <T as Config>::MaxKeys::get() }>,
	) -> Result<(), BenchmarkError> {
		let (input_heartbeat, signature) = create_heartbeat::<T>(k)?;
		let call = Call::heartbeat { heartbeat: input_heartbeat, signature };
		let call_enc = call.encode();

		#[block]
		{
			Pallet::<T>::validate_unsigned(TransactionSource::InBlock, &call)
				.map_err(<&str>::from)?;
			<Call<T> as Decode>::decode(&mut &*call_enc)
				.expect("call is encoded above, encoding must be correct")
				.dispatch_bypass_filter(RawOrigin::None.into())?;
		}

		Ok(())
	}

	impl_benchmark_test_suite! {
		Pallet,
		mock::new_test_ext(),
		mock::Runtime
	}
}
