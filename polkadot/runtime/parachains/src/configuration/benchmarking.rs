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
#![cfg(feature = "runtime-benchmarks")]

use crate::configuration::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;
use polkadot_primitives::{ExecutorParam, ExecutorParams, PvfExecKind, PvfPrepKind};
use sp_runtime::traits::One;

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn set_config_with_block_number() {
		#[extrinsic_call]
		set_code_retention_period(RawOrigin::Root, One::one());
	}

	#[benchmark]
	fn set_config_with_u32() {
		#[extrinsic_call]
		set_max_code_size(RawOrigin::Root, 100);
	}

	#[benchmark]
	fn set_config_with_option_u32() {
		#[extrinsic_call]
		set_max_validators(RawOrigin::Root, Some(10));
	}

	#[benchmark]
	fn set_hrmp_open_request_ttl() -> Result<(), BenchmarkError> {
		#[block]
		{
			Err(BenchmarkError::Override(BenchmarkResult::from_weight(
				T::BlockWeights::get().max_block,
			)))?;
		}
		Ok(())
	}

	#[benchmark]
	fn set_config_with_balance() {
		#[extrinsic_call]
		set_hrmp_sender_deposit(RawOrigin::Root, 100_000_000_000);
	}

	#[benchmark]
	fn set_config_with_executor_params() {
		#[extrinsic_call]
		set_executor_params(
			RawOrigin::Root,
			ExecutorParams::from(
				&[
					ExecutorParam::MaxMemoryPages(2080),
					ExecutorParam::StackLogicalMax(65536),
					ExecutorParam::StackNativeMax(256 * 1024 * 1024),
					ExecutorParam::WasmExtBulkMemory,
					ExecutorParam::PrecheckingMaxMemory(2 * 1024 * 1024 * 1024),
					ExecutorParam::PvfPrepTimeout(PvfPrepKind::Precheck, 60_000),
					ExecutorParam::PvfPrepTimeout(PvfPrepKind::Prepare, 360_000),
					ExecutorParam::PvfExecTimeout(PvfExecKind::Backing, 2_000),
					ExecutorParam::PvfExecTimeout(PvfExecKind::Approval, 12_000),
				][..],
			),
		);
	}

	#[benchmark]
	fn set_config_with_perbill() {
		#[extrinsic_call]
		set_on_demand_fee_variability(RawOrigin::Root, Perbill::from_percent(100));
	}

	#[benchmark]
	fn set_node_feature() {
		#[extrinsic_call]
		set_node_feature(RawOrigin::Root, 255, true);
	}

	#[benchmark]
	fn set_config_with_scheduler_params() {
		#[extrinsic_call]
		set_scheduler_params(RawOrigin::Root, SchedulerParams::default());
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::mock::new_test_ext(Default::default()),
		crate::mock::Test
	);
}
