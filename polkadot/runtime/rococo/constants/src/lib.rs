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

#![cfg_attr(not(feature = "std"), no_std)]

pub mod weights;

/// Money matters.
pub mod currency {
	use polkadot_primitives::Balance;

	/// The existential deposit.
	pub const EXISTENTIAL_DEPOSIT: Balance = 1 * CENTS;

	pub const UNITS: Balance = 1_000_000_000_000;
	pub const CENTS: Balance = UNITS / 30_000;
	pub const GRAND: Balance = CENTS * 100_000;
	pub const MILLICENTS: Balance = CENTS / 1_000;

	pub const fn deposit(items: u32, bytes: u32) -> Balance {
		items as Balance * 2_000 * CENTS + (bytes as Balance) * 100 * MILLICENTS
	}
}

/// Time and blocks.
pub mod time {
	use polkadot_runtime_common::prod_or_fast;

	use polkadot_primitives::{BlockNumber, Moment};
	pub const MILLISECS_PER_BLOCK: Moment = 6000;
	pub const SLOT_DURATION: Moment = MILLISECS_PER_BLOCK;

	frame_support::parameter_types! {
		pub EpochDurationInBlocks: BlockNumber =
			prod_or_fast!(1 * HOURS, 1 * MINUTES, "ROCOCO_EPOCH_DURATION");
	}

	// These time units are defined in number of blocks.
	pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
	pub const HOURS: BlockNumber = MINUTES * 60;
	pub const DAYS: BlockNumber = HOURS * 24;
	pub const WEEKS: BlockNumber = DAYS * 7;

	// 1 in 4 blocks (on average, not counting collisions) will be primary babe blocks.
	// The choice of is done in accordance to the slot duration and expected target
	// block time, for safely resisting network delays of maximum two seconds.
	// <https://research.web3.foundation/Polkadot/protocols/block-production/Babe#6-practical-results>
	pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);
}

/// Fee-related.
pub mod fee {
	use crate::weights::ExtrinsicBaseWeight;
	use frame_support::weights::{
		WeightToFeeCoefficient, WeightToFeeCoefficients, WeightToFeePolynomial,
	};
	use polkadot_primitives::Balance;
	use smallvec::smallvec;
	pub use sp_runtime::Perbill;

	/// The block saturation level. Fees will be updates based on this value.
	pub const TARGET_BLOCK_FULLNESS: Perbill = Perbill::from_percent(25);

	/// Handles converting a weight scalar to a fee value, based on the scale and granularity of the
	/// node's balance type.
	///
	/// This should typically create a mapping between the following ranges:
	///   - [0, `frame_system::MaximumBlockWeight`]
	///   - [Balance::min, Balance::max]
	///
	/// Yet, it can be used for any other sort of change to weight-fee. Some examples being:
	///   - Setting it to `0` will essentially disable the weight fee.
	///   - Setting it to `1` will cause the literal `#[weight = x]` values to be charged.
	pub struct WeightToFee;
	impl WeightToFeePolynomial for WeightToFee {
		type Balance = Balance;
		fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
			// in Rococo, extrinsic base weight (smallest non-zero weight) is mapped to 1/10 CENT:
			let p = super::currency::CENTS;
			let q = 10 * Balance::from(ExtrinsicBaseWeight::get().ref_time());
			smallvec![WeightToFeeCoefficient {
				degree: 1,
				negative: false,
				coeff_frac: Perbill::from_rational(p % q, q),
				coeff_integer: p / q,
			}]
		}
	}
}

/// System Parachains.
pub mod system_parachain {
	use frame_support::parameter_types;
	use polkadot_primitives::Id as ParaId;
	use xcm_builder::IsChildSystemParachain;

	parameter_types! {
		pub AssetHubParaId: ParaId = ASSET_HUB_ID.into();
		pub PeopleParaId: ParaId = PEOPLE_ID.into();
	}

	/// Network's Asset Hub parachain ID.
	pub const ASSET_HUB_ID: u32 = 1000;
	/// Contracts parachain ID.
	pub const CONTRACTS_ID: u32 = 1002;
	/// Encointer parachain ID.
	pub const ENCOINTER_ID: u32 = 1003;
	/// People parachain ID.
	pub const PEOPLE_ID: u32 = 1004;
	/// BridgeHub parachain ID.
	pub const BRIDGE_HUB_ID: u32 = 1013;
	/// Brokerage parachain ID.
	pub const BROKER_ID: u32 = 1005;

	/// All system parachains of Rococo.
	pub type SystemParachains = IsChildSystemParachain<ParaId>;

	/// Coretime constants
	pub mod coretime {
		/// Coretime timeslice period in blocks
		/// WARNING: This constant is used accross chains, so additional care should be taken
		/// when changing it.
		#[cfg(feature = "fast-runtime")]
		pub const TIMESLICE_PERIOD: u32 = 20;
		#[cfg(not(feature = "fast-runtime"))]
		pub const TIMESLICE_PERIOD: u32 = 80;
	}
}

/// Rococo Treasury pallet instance.
pub const TREASURY_PALLET_ID: u8 = 18;

#[cfg(test)]
mod tests {
	use super::{
		currency::{CENTS, MILLICENTS},
		fee::WeightToFee,
	};
	use crate::weights::ExtrinsicBaseWeight;
	use frame_support::weights::WeightToFee as WeightToFeeT;
	use polkadot_runtime_common::MAXIMUM_BLOCK_WEIGHT;

	#[test]
	// Test that the fee for `MAXIMUM_BLOCK_WEIGHT` of weight has sane bounds.
	fn full_block_fee_is_correct() {
		// A full block should cost between 1,000 and 10,000 CENTS.
		let full_block = WeightToFee::weight_to_fee(&MAXIMUM_BLOCK_WEIGHT);
		assert!(full_block >= 1_000 * CENTS);
		assert!(full_block <= 10_000 * CENTS);
	}

	#[test]
	// This function tests that the fee for `ExtrinsicBaseWeight` of weight is correct
	fn extrinsic_base_fee_is_correct() {
		// `ExtrinsicBaseWeight` should cost 1/10 of a CENT
		println!("Base: {}", ExtrinsicBaseWeight::get());
		let x = WeightToFee::weight_to_fee(&ExtrinsicBaseWeight::get());
		let y = CENTS / 10;
		assert!(x.max(y) - x.min(y) < MILLICENTS);
	}
}
