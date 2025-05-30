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

use sp_runtime::{
	traits::{UniqueSaturatedFrom, UniqueSaturatedInto},
	SaturatedConversion,
};

/// A trait similar to `Convert` to convert values from `B` an abstract balance type
/// into u64 and back from u128. (This conversion is used in election and other places where complex
/// calculation over balance type is needed)
///
/// Total issuance of the currency is passed in, but an implementation of this trait may or may not
/// use it.
///
/// # WARNING
///
/// the total issuance being passed in implies that the implementation must be aware of the fact
/// that its values can affect the outcome. This implies that if the vote value is dependent on the
/// total issuance, it should never ber written to storage for later re-use.
pub trait CurrencyToVote<B> {
	/// Convert balance to u64.
	fn to_vote(value: B, issuance: B) -> u64;

	/// Convert u128 to balance.
	fn to_currency(value: u128, issuance: B) -> B;

	/// Send a signal whether you are going to downscale the `B` when converting to `u64` given the
	/// current issuance.
	///
	/// This is useful for automated checks in place to signal maintainers that the total issuance
	/// has reached a point where downscaling will happen.
	///
	/// `None` means we don't know. `Some(_)` means we know with certainty.
	fn will_downscale(issuance: B) -> Option<bool>;
}

/// An implementation of `CurrencyToVote` tailored for chain's that have a balance type of u128.
///
/// The factor is the `(total_issuance / u64::MAX).max(1)`, represented as u64. Let's look at the
/// important cases:
///
/// If the chain's total issuance is less than u64::MAX, this will always be 1, which means that
/// the factor will not have any effect. In this case, any account's balance is also less. Thus,
/// both of the conversions are basically an `as`; Any balance can fit in u64.
///
/// If the chain's total issuance is more than 2*u64::MAX, then a factor might be multiplied and
/// divided upon conversion.
pub struct U128CurrencyToVote;

impl U128CurrencyToVote {
	fn factor(issuance: u128) -> u128 {
		(issuance / u64::MAX as u128).max(1)
	}
}

impl CurrencyToVote<u128> for U128CurrencyToVote {
	fn to_vote(value: u128, issuance: u128) -> u64 {
		(value / Self::factor(issuance)).saturated_into()
	}

	fn to_currency(value: u128, issuance: u128) -> u128 {
		value.saturating_mul(Self::factor(issuance))
	}

	fn will_downscale(issuance: u128) -> Option<bool> {
		Some(issuance > u64::MAX as u128)
	}
}

/// A naive implementation of `CurrencyConvert` that simply saturates all conversions.
///
/// # Warning
///
/// This is designed to be used mostly for testing. Use with care, and think about the consequences.
pub struct SaturatingCurrencyToVote;

impl<B: UniqueSaturatedInto<u64> + UniqueSaturatedFrom<u128>> CurrencyToVote<B>
	for SaturatingCurrencyToVote
{
	fn to_vote(value: B, _: B) -> u64 {
		value.unique_saturated_into()
	}

	fn to_currency(value: u128, _: B) -> B {
		B::unique_saturated_from(value)
	}

	fn will_downscale(_issuance: B) -> Option<bool> {
		None
	}
}

#[cfg(feature = "std")]
impl<B: UniqueSaturatedInto<u64> + UniqueSaturatedFrom<u128>> CurrencyToVote<B> for () {
	fn to_vote(value: B, issuance: B) -> u64 {
		SaturatingCurrencyToVote::to_vote(value, issuance)
	}

	/// Convert u128 to balance.
	fn to_currency(value: u128, issuance: B) -> B {
		SaturatingCurrencyToVote::to_currency(value, issuance)
	}

	fn will_downscale(_issuance: B) -> Option<bool> {
		None
	}
}
