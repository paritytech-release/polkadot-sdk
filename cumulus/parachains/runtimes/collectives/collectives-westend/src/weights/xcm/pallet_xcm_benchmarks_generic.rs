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

//! Autogenerated weights for `pallet_xcm_benchmarks::generic`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 32.0.0
//! DATE: 2025-07-30, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `a49f76527979`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! WASM-EXECUTION: Compiled, CHAIN: None, DB CACHE: 1024

// Executed Command:
// frame-omni-bencher
// v1
// benchmark
// pallet
// --extrinsic=*
// --runtime=target/production/wbuild/collectives-westend-runtime/collectives_westend_runtime.wasm
// --pallet=pallet_xcm_benchmarks::generic
// --header=/__w/polkadot-sdk/polkadot-sdk/cumulus/file_header.txt
// --output=./cumulus/parachains/runtimes/collectives/collectives-westend/src/weights/xcm
// --wasm-execution=compiled
// --steps=50
// --repeat=20
// --heap-pages=4096
// --template=cumulus/templates/xcm-bench-template.hbs
// --no-storage-info
// --no-min-squares
// --no-median-slopes

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weights for `pallet_xcm_benchmarks::generic`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo<T> {
	// Storage: `ParachainInfo::ParachainId` (r:1 w:0)
	// Proof: `ParachainInfo::ParachainId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::DeliveryFeeFactor` (r:1 w:0)
	// Proof: `XcmpQueue::DeliveryFeeFactor` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	// Storage: `PolkadotXcm::SupportedVersion` (r:1 w:0)
	// Proof: `PolkadotXcm::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	// Storage: `System::Account` (r:2 w:2)
	// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	// Storage: `ParachainSystem::RelevantMessagingState` (r:1 w:0)
	// Proof: `ParachainSystem::RelevantMessagingState` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	// Storage: `XcmpQueue::OutboundXcmpStatus` (r:1 w:1)
	// Proof: `XcmpQueue::OutboundXcmpStatus` (`max_values`: Some(1), `max_size`: Some(1282), added: 1777, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::OutboundXcmpMessages` (r:0 w:1)
	// Proof: `XcmpQueue::OutboundXcmpMessages` (`max_values`: None, `max_size`: Some(105506), added: 107981, mode: `MaxEncodedLen`)
	pub fn report_holding() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `448`
		//  Estimated: `6196`
		// Minimum execution time: 83_204_000 picoseconds.
		Weight::from_parts(85_444_000, 6196)
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	// Storage: `System::Account` (r:1 w:1)
	// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	pub fn buy_execution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `3593`
		// Minimum execution time: 3_812_000 picoseconds.
		Weight::from_parts(4_044_000, 3593)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: `System::Account` (r:1 w:1)
	// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	pub fn pay_fees() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `3593`
		// Minimum execution time: 3_805_000 picoseconds.
		Weight::from_parts(3_986_000, 3593)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	pub fn asset_claimer() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 722_000 picoseconds.
		Weight::from_parts(782_000, 0)
	}
	// Storage: `PolkadotXcm::Queries` (r:1 w:0)
	// Proof: `PolkadotXcm::Queries` (`max_values`: None, `max_size`: None, mode: `Measured`)
	pub fn query_response() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `3465`
		// Minimum execution time: 6_110_000 picoseconds.
		Weight::from_parts(6_319_000, 3465)
			.saturating_add(T::DbWeight::get().reads(1))
	}
	pub fn transact() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 7_483_000 picoseconds.
		Weight::from_parts(7_709_000, 0)
	}
	pub fn refund_surplus() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_210_000 picoseconds.
		Weight::from_parts(1_300_000, 0)
	}
	pub fn set_error_handler() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 707_000 picoseconds.
		Weight::from_parts(801_000, 0)
	}
	pub fn set_appendix() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 724_000 picoseconds.
		Weight::from_parts(780_000, 0)
	}
	pub fn clear_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 702_000 picoseconds.
		Weight::from_parts(786_000, 0)
	}
	pub fn descend_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 722_000 picoseconds.
		Weight::from_parts(773_000, 0)
	}
	// Storage: `Benchmark::Override` (r:0 w:0)
	// Proof: `Benchmark::Override` (`max_values`: None, `max_size`: None, mode: `Measured`)
	pub fn execute_with_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 18_446_744_073_709_551_000 picoseconds.
		Weight::from_parts(18_446_744_073_709_551_000, 0)
	}
	pub fn clear_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 680_000 picoseconds.
		Weight::from_parts(758_000, 0)
	}
	// Storage: `ParachainInfo::ParachainId` (r:1 w:0)
	// Proof: `ParachainInfo::ParachainId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::DeliveryFeeFactor` (r:1 w:0)
	// Proof: `XcmpQueue::DeliveryFeeFactor` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	// Storage: `PolkadotXcm::SupportedVersion` (r:1 w:0)
	// Proof: `PolkadotXcm::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	// Storage: `System::Account` (r:2 w:2)
	// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	// Storage: `ParachainSystem::RelevantMessagingState` (r:1 w:0)
	// Proof: `ParachainSystem::RelevantMessagingState` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	// Storage: `XcmpQueue::OutboundXcmpStatus` (r:1 w:1)
	// Proof: `XcmpQueue::OutboundXcmpStatus` (`max_values`: Some(1), `max_size`: Some(1282), added: 1777, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::OutboundXcmpMessages` (r:0 w:1)
	// Proof: `XcmpQueue::OutboundXcmpMessages` (`max_values`: None, `max_size`: Some(105506), added: 107981, mode: `MaxEncodedLen`)
	pub fn report_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `448`
		//  Estimated: `6196`
		// Minimum execution time: 79_918_000 picoseconds.
		Weight::from_parts(81_914_000, 6196)
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	// Storage: `PolkadotXcm::AssetTraps` (r:1 w:1)
	// Proof: `PolkadotXcm::AssetTraps` (`max_values`: None, `max_size`: None, mode: `Measured`)
	pub fn claim_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `23`
		//  Estimated: `3488`
		// Minimum execution time: 9_800_000 picoseconds.
		Weight::from_parts(10_101_000, 3488)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	pub fn trap() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_689_000 picoseconds.
		Weight::from_parts(3_865_000, 0)
	}
	// Storage: `PolkadotXcm::VersionNotifyTargets` (r:1 w:1)
	// Proof: `PolkadotXcm::VersionNotifyTargets` (`max_values`: None, `max_size`: None, mode: `Measured`)
	// Storage: `XcmpQueue::DeliveryFeeFactor` (r:1 w:0)
	// Proof: `XcmpQueue::DeliveryFeeFactor` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	// Storage: `PolkadotXcm::SupportedVersion` (r:1 w:0)
	// Proof: `PolkadotXcm::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	// Storage: `ParachainSystem::RelevantMessagingState` (r:1 w:0)
	// Proof: `ParachainSystem::RelevantMessagingState` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	// Storage: `XcmpQueue::OutboundXcmpStatus` (r:1 w:1)
	// Proof: `XcmpQueue::OutboundXcmpStatus` (`max_values`: Some(1), `max_size`: Some(1282), added: 1777, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::OutboundXcmpMessages` (r:0 w:1)
	// Proof: `XcmpQueue::OutboundXcmpMessages` (`max_values`: None, `max_size`: Some(105506), added: 107981, mode: `MaxEncodedLen`)
	pub fn subscribe_version() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `278`
		//  Estimated: `3743`
		// Minimum execution time: 33_263_000 picoseconds.
		Weight::from_parts(34_232_000, 3743)
			.saturating_add(T::DbWeight::get().reads(5))
			.saturating_add(T::DbWeight::get().writes(3))
	}
	// Storage: `PolkadotXcm::VersionNotifyTargets` (r:0 w:1)
	// Proof: `PolkadotXcm::VersionNotifyTargets` (`max_values`: None, `max_size`: None, mode: `Measured`)
	pub fn unsubscribe_version() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_416_000 picoseconds.
		Weight::from_parts(3_603_000, 0)
			.saturating_add(T::DbWeight::get().writes(1))
	}
	pub fn burn_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 1_104_000 picoseconds.
		Weight::from_parts(1_189_000, 0)
	}
	pub fn expect_asset() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 766_000 picoseconds.
		Weight::from_parts(817_000, 0)
	}
	pub fn expect_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_668_000 picoseconds.
		Weight::from_parts(3_796_000, 0)
	}
	pub fn expect_error() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 3_634_000 picoseconds.
		Weight::from_parts(3_824_000, 0)
	}
	pub fn expect_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 850_000 picoseconds.
		Weight::from_parts(934_000, 0)
	}
	// Storage: `ParachainInfo::ParachainId` (r:1 w:0)
	// Proof: `ParachainInfo::ParachainId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::DeliveryFeeFactor` (r:1 w:0)
	// Proof: `XcmpQueue::DeliveryFeeFactor` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	// Storage: `PolkadotXcm::SupportedVersion` (r:1 w:0)
	// Proof: `PolkadotXcm::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	// Storage: `System::Account` (r:2 w:2)
	// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	// Storage: `ParachainSystem::RelevantMessagingState` (r:1 w:0)
	// Proof: `ParachainSystem::RelevantMessagingState` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	// Storage: `XcmpQueue::OutboundXcmpStatus` (r:1 w:1)
	// Proof: `XcmpQueue::OutboundXcmpStatus` (`max_values`: Some(1), `max_size`: Some(1282), added: 1777, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::OutboundXcmpMessages` (r:0 w:1)
	// Proof: `XcmpQueue::OutboundXcmpMessages` (`max_values`: None, `max_size`: Some(105506), added: 107981, mode: `MaxEncodedLen`)
	pub fn query_pallet() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `448`
		//  Estimated: `6196`
		// Minimum execution time: 86_934_000 picoseconds.
		Weight::from_parts(88_810_000, 6196)
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	pub fn expect_pallet() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 5_523_000 picoseconds.
		Weight::from_parts(5_685_000, 0)
	}
	// Storage: `ParachainInfo::ParachainId` (r:1 w:0)
	// Proof: `ParachainInfo::ParachainId` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::DeliveryFeeFactor` (r:1 w:0)
	// Proof: `XcmpQueue::DeliveryFeeFactor` (`max_values`: None, `max_size`: Some(28), added: 2503, mode: `MaxEncodedLen`)
	// Storage: `PolkadotXcm::SupportedVersion` (r:1 w:0)
	// Proof: `PolkadotXcm::SupportedVersion` (`max_values`: None, `max_size`: None, mode: `Measured`)
	// Storage: `System::Account` (r:2 w:2)
	// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	// Storage: `ParachainSystem::RelevantMessagingState` (r:1 w:0)
	// Proof: `ParachainSystem::RelevantMessagingState` (`max_values`: Some(1), `max_size`: None, mode: `Measured`)
	// Storage: `XcmpQueue::OutboundXcmpStatus` (r:1 w:1)
	// Proof: `XcmpQueue::OutboundXcmpStatus` (`max_values`: Some(1), `max_size`: Some(1282), added: 1777, mode: `MaxEncodedLen`)
	// Storage: `XcmpQueue::OutboundXcmpMessages` (r:0 w:1)
	// Proof: `XcmpQueue::OutboundXcmpMessages` (`max_values`: None, `max_size`: Some(105506), added: 107981, mode: `MaxEncodedLen`)
	pub fn report_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `448`
		//  Estimated: `6196`
		// Minimum execution time: 80_346_000 picoseconds.
		Weight::from_parts(82_126_000, 6196)
			.saturating_add(T::DbWeight::get().reads(7))
			.saturating_add(T::DbWeight::get().writes(4))
	}
	pub fn clear_transact_status() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 751_000 picoseconds.
		Weight::from_parts(821_000, 0)
	}
	pub fn set_topic() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 679_000 picoseconds.
		Weight::from_parts(747_000, 0)
	}
	pub fn clear_topic() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 657_000 picoseconds.
		Weight::from_parts(761_000, 0)
	}
	pub fn set_fees_mode() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 732_000 picoseconds.
		Weight::from_parts(766_000, 0)
	}
	pub fn unpaid_execution() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 729_000 picoseconds.
		Weight::from_parts(779_000, 0)
	}
	pub fn alias_origin() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 730_000 picoseconds.
		Weight::from_parts(784_000, 0)
	}
}
