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

//! Adapters to work with [`frame_support::traits::fungibles`] through XCM.

use core::{fmt::Debug, marker::PhantomData, result};
use frame_support::traits::{
	tokens::{
		fungibles, Fortitude::Polite, Precision::Exact, Preservation::Expendable,
		Provenance::Minted,
	},
	Contains, Get,
};
use xcm::latest::prelude::*;
use xcm_executor::traits::{ConvertLocation, Error as MatchError, MatchesFungibles, TransactAsset};

/// `TransactAsset` implementation to convert a `fungibles` implementation to become usable in XCM.
pub struct FungiblesTransferAdapter<Assets, Matcher, AccountIdConverter, AccountId>(
	PhantomData<(Assets, Matcher, AccountIdConverter, AccountId)>,
);
impl<
		Assets: fungibles::Mutate<AccountId>,
		Matcher: MatchesFungibles<Assets::AssetId, Assets::Balance>,
		AccountIdConverter: ConvertLocation<AccountId>,
		AccountId: Eq + Clone + Debug, /* can't get away without it since Currency is generic
		                                * over it. */
	> TransactAsset for FungiblesTransferAdapter<Assets, Matcher, AccountIdConverter, AccountId>
{
	fn internal_transfer_asset(
		what: &Asset,
		from: &Location,
		to: &Location,
		_context: &XcmContext,
	) -> result::Result<xcm_executor::AssetsInHolding, XcmError> {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?what, ?from, ?to,
			"internal_transfer_asset"
		);
		// Check we handle this asset.
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		let source = AccountIdConverter::convert_location(from)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		let dest = AccountIdConverter::convert_location(to)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		Assets::transfer(asset_id.clone(), &source, &dest, amount, Expendable).map_err(|e| {
			tracing::debug!(target: "xcm::fungibles_adapter", error = ?e, ?asset_id, ?source, ?dest, ?amount, "Failed internal transfer asset");
			XcmError::FailedToTransactAsset(e.into())
		})?;
		Ok(what.clone().into())
	}
}

/// The location which is allowed to mint a particular asset.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MintLocation {
	/// This chain is allowed to mint the asset. When we track teleports of the asset we ensure
	/// that no more of the asset returns back to the chain than has been sent out.
	Local,
	/// This chain is not allowed to mint the asset. When we track teleports of the asset we ensure
	/// that no more of the asset is sent out from the chain than has been previously received.
	NonLocal,
}

/// Simple trait to indicate whether an asset is subject to having its teleportation into and out of
/// this chain recorded and if so in what `MintLocation`.
///
/// The overall purpose of asset-checking is to ensure either no more assets are teleported into a
/// chain than the outstanding balance of assets which were previously teleported out (as in the
/// case of locally-minted assets); or that no more assets are teleported out of a chain than the
/// outstanding balance of assets which have previously been teleported in (as in the case of chains
/// where the `asset` is not minted locally).
pub trait AssetChecking<AssetId> {
	/// Return the teleportation asset-checking policy for the given `asset`. `None` implies no
	/// checking. Otherwise the policy detailed by the inner `MintLocation` should be respected by
	/// teleportation.
	fn asset_checking(asset: &AssetId) -> Option<MintLocation>;
}

/// Implementation of `AssetChecking` which subjects no assets to having their teleportations
/// recorded.
pub struct NoChecking;
impl<AssetId> AssetChecking<AssetId> for NoChecking {
	fn asset_checking(_: &AssetId) -> Option<MintLocation> {
		None
	}
}

/// Implementation of `AssetChecking` which subjects a given set of assets `T` to having their
/// teleportations recorded with a `MintLocation::Local`.
pub struct LocalMint<T>(core::marker::PhantomData<T>);
impl<AssetId, T: Contains<AssetId>> AssetChecking<AssetId> for LocalMint<T> {
	fn asset_checking(asset: &AssetId) -> Option<MintLocation> {
		match T::contains(asset) {
			true => Some(MintLocation::Local),
			false => None,
		}
	}
}

/// Implementation of `AssetChecking` which subjects a given set of assets `T` to having their
/// teleportations recorded with a `MintLocation::NonLocal`.
pub struct NonLocalMint<T>(core::marker::PhantomData<T>);
impl<AssetId, T: Contains<AssetId>> AssetChecking<AssetId> for NonLocalMint<T> {
	fn asset_checking(asset: &AssetId) -> Option<MintLocation> {
		match T::contains(asset) {
			true => Some(MintLocation::NonLocal),
			false => None,
		}
	}
}

/// Implementation of `AssetChecking` which subjects a given set of assets `L` to having their
/// teleportations recorded with a `MintLocation::Local` and a second set of assets `R` to having
/// their teleportations recorded with a `MintLocation::NonLocal`.
pub struct DualMint<L, R>(core::marker::PhantomData<(L, R)>);
impl<AssetId, L: Contains<AssetId>, R: Contains<AssetId>> AssetChecking<AssetId>
	for DualMint<L, R>
{
	fn asset_checking(asset: &AssetId) -> Option<MintLocation> {
		if L::contains(asset) {
			Some(MintLocation::Local)
		} else if R::contains(asset) {
			Some(MintLocation::NonLocal)
		} else {
			None
		}
	}
}

pub struct FungiblesMutateAdapter<
	Assets,
	Matcher,
	AccountIdConverter,
	AccountId,
	CheckAsset,
	CheckingAccount,
>(PhantomData<(Assets, Matcher, AccountIdConverter, AccountId, CheckAsset, CheckingAccount)>);

impl<
		Assets: fungibles::Mutate<AccountId>,
		Matcher: MatchesFungibles<Assets::AssetId, Assets::Balance>,
		AccountIdConverter: ConvertLocation<AccountId>,
		AccountId: Eq + Clone + Debug, /* can't get away without it since Currency is generic
		                                * over it. */
		CheckAsset: AssetChecking<Assets::AssetId>,
		CheckingAccount: Get<AccountId>,
	>
	FungiblesMutateAdapter<Assets, Matcher, AccountIdConverter, AccountId, CheckAsset, CheckingAccount>
{
	fn can_accrue_checked(asset_id: Assets::AssetId, amount: Assets::Balance) -> XcmResult {
		let checking_account = CheckingAccount::get();
		Assets::can_deposit(asset_id, &checking_account, amount, Minted)
			.into_result()
			.map_err(|error| {
				tracing::debug!(
					target: "xcm::fungibles_adapter", ?error, ?checking_account, ?amount,
					"Failed to check if asset can be accrued"
				);
				XcmError::NotDepositable
			})
	}
	fn can_reduce_checked(asset_id: Assets::AssetId, amount: Assets::Balance) -> XcmResult {
		let checking_account = CheckingAccount::get();
		Assets::can_withdraw(asset_id, &checking_account, amount)
			.into_result(false)
			.map_err(|error| {
				tracing::debug!(
					target: "xcm::fungibles_adapter", ?error, ?checking_account, ?amount,
					"Failed to check if asset can be reduced"
				);
				XcmError::NotWithdrawable
			})
			.map(|_| ())
	}
	fn accrue_checked(asset_id: Assets::AssetId, amount: Assets::Balance) {
		let checking_account = CheckingAccount::get();
		let ok = Assets::mint_into(asset_id, &checking_account, amount).is_ok();
		debug_assert!(ok, "`can_accrue_checked` must have returned `true` immediately prior; qed");
	}
	fn reduce_checked(asset_id: Assets::AssetId, amount: Assets::Balance) {
		let checking_account = CheckingAccount::get();
		let ok = Assets::burn_from(asset_id, &checking_account, amount, Expendable, Exact, Polite)
			.is_ok();
		debug_assert!(ok, "`can_reduce_checked` must have returned `true` immediately prior; qed");
	}
}

impl<
		Assets: fungibles::Mutate<AccountId>,
		Matcher: MatchesFungibles<Assets::AssetId, Assets::Balance>,
		AccountIdConverter: ConvertLocation<AccountId>,
		AccountId: Eq + Clone + Debug, /* can't get away without it since Currency is generic
		                                * over it. */
		CheckAsset: AssetChecking<Assets::AssetId>,
		CheckingAccount: Get<AccountId>,
	> TransactAsset
	for FungiblesMutateAdapter<
		Assets,
		Matcher,
		AccountIdConverter,
		AccountId,
		CheckAsset,
		CheckingAccount,
	>
{
	fn can_check_in(origin: &Location, what: &Asset, _context: &XcmContext) -> XcmResult {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?origin, ?what,
			"can_check_in"
		);
		// Check we handle this asset.
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		match CheckAsset::asset_checking(&asset_id) {
			// We track this asset's teleports to ensure no more come in than have gone out.
			Some(MintLocation::Local) => Self::can_reduce_checked(asset_id, amount),
			// We track this asset's teleports to ensure no more go out than have come in.
			Some(MintLocation::NonLocal) => Self::can_accrue_checked(asset_id, amount),
			_ => Ok(()),
		}
	}

	fn check_in(origin: &Location, what: &Asset, _context: &XcmContext) {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?origin, ?what,
			"check_in"
		);
		if let Ok((asset_id, amount)) = Matcher::matches_fungibles(what) {
			match CheckAsset::asset_checking(&asset_id) {
				// We track this asset's teleports to ensure no more come in than have gone out.
				Some(MintLocation::Local) => Self::reduce_checked(asset_id, amount),
				// We track this asset's teleports to ensure no more go out than have come in.
				Some(MintLocation::NonLocal) => Self::accrue_checked(asset_id, amount),
				_ => (),
			}
		}
	}

	fn can_check_out(origin: &Location, what: &Asset, _context: &XcmContext) -> XcmResult {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?origin, ?what,
			"can_check_out"
		);
		// Check we handle this asset.
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		match CheckAsset::asset_checking(&asset_id) {
			// We track this asset's teleports to ensure no more come in than have gone out.
			Some(MintLocation::Local) => Self::can_accrue_checked(asset_id, amount),
			// We track this asset's teleports to ensure no more go out than have come in.
			Some(MintLocation::NonLocal) => Self::can_reduce_checked(asset_id, amount),
			_ => Ok(()),
		}
	}

	fn check_out(dest: &Location, what: &Asset, _context: &XcmContext) {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?dest, ?what,
			"check_out"
		);
		if let Ok((asset_id, amount)) = Matcher::matches_fungibles(what) {
			match CheckAsset::asset_checking(&asset_id) {
				// We track this asset's teleports to ensure no more come in than have gone out.
				Some(MintLocation::Local) => Self::accrue_checked(asset_id, amount),
				// We track this asset's teleports to ensure no more go out than have come in.
				Some(MintLocation::NonLocal) => Self::reduce_checked(asset_id, amount),
				_ => (),
			}
		}
	}

	fn deposit_asset(what: &Asset, who: &Location, _context: Option<&XcmContext>) -> XcmResult {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?what, ?who,
			"deposit_asset"
		);
		// Check we handle this asset.
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		let who = AccountIdConverter::convert_location(who)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		Assets::mint_into(asset_id, &who, amount).map_err(|error| {
			tracing::debug!(target: "xcm::fungibles_adapter", ?error, ?who, ?amount, "Failed to deposit asset");
			XcmError::FailedToTransactAsset(error.into())
		})?;
		Ok(())
	}

	fn withdraw_asset(
		what: &Asset,
		who: &Location,
		_maybe_context: Option<&XcmContext>,
	) -> result::Result<xcm_executor::AssetsInHolding, XcmError> {
		tracing::trace!(
			target: "xcm::fungibles_adapter",
			?what, ?who,
			"withdraw_asset"
		);
		// Check we handle this asset.
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		let who = AccountIdConverter::convert_location(who)
			.ok_or(MatchError::AccountIdConversionFailed)?;
		Assets::burn_from(asset_id, &who, amount, Expendable, Exact, Polite).map_err(|error| {
			tracing::debug!(target: "xcm::fungibles_adapter", ?error, ?who, ?amount, "Failed to withdraw asset");
			XcmError::FailedToTransactAsset(error.into())
		})?;
		Ok(what.clone().into())
	}
}

pub struct FungiblesAdapter<
	Assets,
	Matcher,
	AccountIdConverter,
	AccountId,
	CheckAsset,
	CheckingAccount,
>(PhantomData<(Assets, Matcher, AccountIdConverter, AccountId, CheckAsset, CheckingAccount)>);
impl<
		Assets: fungibles::Mutate<AccountId>,
		Matcher: MatchesFungibles<Assets::AssetId, Assets::Balance>,
		AccountIdConverter: ConvertLocation<AccountId>,
		AccountId: Eq + Clone + Debug, /* can't get away without it since Currency is generic
		                                * over it. */
		CheckAsset: AssetChecking<Assets::AssetId>,
		CheckingAccount: Get<AccountId>,
	> TransactAsset
	for FungiblesAdapter<Assets, Matcher, AccountIdConverter, AccountId, CheckAsset, CheckingAccount>
{
	fn can_check_in(origin: &Location, what: &Asset, context: &XcmContext) -> XcmResult {
		FungiblesMutateAdapter::<
			Assets,
			Matcher,
			AccountIdConverter,
			AccountId,
			CheckAsset,
			CheckingAccount,
		>::can_check_in(origin, what, context)
	}

	fn check_in(origin: &Location, what: &Asset, context: &XcmContext) {
		FungiblesMutateAdapter::<
			Assets,
			Matcher,
			AccountIdConverter,
			AccountId,
			CheckAsset,
			CheckingAccount,
		>::check_in(origin, what, context)
	}

	fn can_check_out(dest: &Location, what: &Asset, context: &XcmContext) -> XcmResult {
		FungiblesMutateAdapter::<
			Assets,
			Matcher,
			AccountIdConverter,
			AccountId,
			CheckAsset,
			CheckingAccount,
		>::can_check_out(dest, what, context)
	}

	fn check_out(dest: &Location, what: &Asset, context: &XcmContext) {
		FungiblesMutateAdapter::<
			Assets,
			Matcher,
			AccountIdConverter,
			AccountId,
			CheckAsset,
			CheckingAccount,
		>::check_out(dest, what, context)
	}

	fn deposit_asset(what: &Asset, who: &Location, context: Option<&XcmContext>) -> XcmResult {
		FungiblesMutateAdapter::<
			Assets,
			Matcher,
			AccountIdConverter,
			AccountId,
			CheckAsset,
			CheckingAccount,
		>::deposit_asset(what, who, context)
	}

	fn withdraw_asset(
		what: &Asset,
		who: &Location,
		maybe_context: Option<&XcmContext>,
	) -> result::Result<xcm_executor::AssetsInHolding, XcmError> {
		FungiblesMutateAdapter::<
			Assets,
			Matcher,
			AccountIdConverter,
			AccountId,
			CheckAsset,
			CheckingAccount,
		>::withdraw_asset(what, who, maybe_context)
	}

	fn internal_transfer_asset(
		what: &Asset,
		from: &Location,
		to: &Location,
		context: &XcmContext,
	) -> result::Result<xcm_executor::AssetsInHolding, XcmError> {
		FungiblesTransferAdapter::<Assets, Matcher, AccountIdConverter, AccountId>::internal_transfer_asset(
			what, from, to, context
		)
	}
}
