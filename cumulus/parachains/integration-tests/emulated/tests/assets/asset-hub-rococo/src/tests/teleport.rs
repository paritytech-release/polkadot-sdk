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

use crate::imports::*;

fn relay_dest_assertions_fail(_t: SystemParaToRelayTest) {
	Rococo::assert_ump_queue_processed(
		false,
		Some(AssetHubRococo::para_id()),
		Some(Weight::from_parts(157_718_000, 3_593)),
	);
}

fn para_origin_assertions(t: SystemParaToRelayTest) {
	type RuntimeEvent = <AssetHubRococo as Chain>::RuntimeEvent;

	AssetHubRococo::assert_xcm_pallet_attempted_complete(Some(Weight::from_parts(
		730_053_000,
		4_000,
	)));

	AssetHubRococo::assert_parachain_system_ump_sent();

	assert_expected_events!(
		AssetHubRococo,
		vec![
			// Amount is withdrawn from Sender's account
			RuntimeEvent::Balances(pallet_balances::Event::Burned { who, amount }) => {
				who: *who == t.sender.account_id,
				amount: *amount == t.args.amount,
			},
		]
	);
}

fn penpal_to_ah_foreign_assets_sender_assertions(t: ParaToSystemParaTest) {
	type RuntimeEvent = <PenpalA as Chain>::RuntimeEvent;
	let system_para_native_asset_location = RelayLocation::get();
	let expected_asset_id = t.args.asset_id.unwrap();
	let (_, expected_asset_amount) =
		non_fee_asset(&t.args.assets, t.args.fee_asset_item as usize).unwrap();

	PenpalA::assert_xcm_pallet_attempted_complete(None);
	assert_expected_events!(
		PenpalA,
		vec![
			RuntimeEvent::ForeignAssets(
				pallet_assets::Event::Burned { asset_id, owner, .. }
			) => {
				asset_id: *asset_id == system_para_native_asset_location,
				owner: *owner == t.sender.account_id,
			},
			RuntimeEvent::Assets(pallet_assets::Event::Burned { asset_id, owner, balance }) => {
				asset_id: *asset_id == expected_asset_id,
				owner: *owner == t.sender.account_id,
				balance: *balance == expected_asset_amount,
			},
		]
	);
}

fn penpal_to_ah_foreign_assets_receiver_assertions(t: ParaToSystemParaTest) {
	type RuntimeEvent = <AssetHubRococo as Chain>::RuntimeEvent;
	let sov_penpal_on_ahr = AssetHubRococo::sovereign_account_id_of(
		AssetHubRococo::sibling_location_of(PenpalA::para_id()),
	);
	let (_, expected_foreign_asset_amount) =
		non_fee_asset(&t.args.assets, t.args.fee_asset_item as usize).unwrap();
	let (_, fee_asset_amount) = fee_asset(&t.args.assets, t.args.fee_asset_item as usize).unwrap();

	AssetHubRococo::assert_xcmp_queue_success(None);

	assert_expected_events!(
		AssetHubRococo,
		vec![
			// native asset reserve transfer for paying fees, withdrawn from Penpal's sov account
			RuntimeEvent::Balances(
				pallet_balances::Event::Burned { who, amount }
			) => {
				who: *who == sov_penpal_on_ahr.clone().into(),
				amount: *amount == fee_asset_amount,
			},
			RuntimeEvent::Balances(pallet_balances::Event::Minted { who, .. }) => {
				who: *who == t.receiver.account_id,
			},
			RuntimeEvent::ForeignAssets(pallet_assets::Event::Issued { asset_id, owner, amount }) => {
				asset_id: *asset_id == PenpalATeleportableAssetLocation::get(),
				owner: *owner == t.receiver.account_id,
				amount: *amount == expected_foreign_asset_amount,
			},
			RuntimeEvent::Balances(pallet_balances::Event::Deposit { .. }) => {},
		]
	);
}

fn ah_to_penpal_foreign_assets_sender_assertions(t: SystemParaToParaTest) {
	type RuntimeEvent = <AssetHubRococo as Chain>::RuntimeEvent;
	AssetHubRococo::assert_xcm_pallet_attempted_complete(None);
	let (expected_foreign_asset_id, expected_foreign_asset_amount) =
		non_fee_asset(&t.args.assets, t.args.fee_asset_item as usize).unwrap();
	let (_, fee_asset_amount) = fee_asset(&t.args.assets, t.args.fee_asset_item as usize).unwrap();
	assert_expected_events!(
		AssetHubRococo,
		vec![
			// native asset used for fees is transferred to Parachain's Sovereign account as reserve
			RuntimeEvent::Balances(
				pallet_balances::Event::Transfer { from, to, amount }
			) => {
				from: *from == t.sender.account_id,
				to: *to == AssetHubRococo::sovereign_account_id_of(
					t.args.dest.clone()
				),
				amount: *amount == fee_asset_amount,
			},
			// foreign asset is burned locally as part of teleportation
			RuntimeEvent::ForeignAssets(pallet_assets::Event::Burned { asset_id, owner, balance }) => {
				asset_id: *asset_id == expected_foreign_asset_id,
				owner: *owner == t.sender.account_id,
				balance: *balance == expected_foreign_asset_amount,
			},
		]
	);
}

fn ah_to_penpal_foreign_assets_receiver_assertions(t: SystemParaToParaTest) {
	type RuntimeEvent = <PenpalA as Chain>::RuntimeEvent;
	let expected_asset_id = t.args.asset_id.unwrap();
	let (_, expected_asset_amount) =
		non_fee_asset(&t.args.assets, t.args.fee_asset_item as usize).unwrap();
	let checking_account = <PenpalA as PenpalAPallet>::PolkadotXcm::check_account();
	let system_para_native_asset_location = RelayLocation::get();

	PenpalA::assert_xcmp_queue_success(None);

	assert_expected_events!(
		PenpalA,
		vec![
			// checking account burns local asset as part of incoming teleport
			RuntimeEvent::Assets(pallet_assets::Event::Burned { asset_id, owner, balance }) => {
				asset_id: *asset_id == expected_asset_id,
				owner: *owner == checking_account,
				balance: *balance == expected_asset_amount,
			},
			// local asset is teleported into account of receiver
			RuntimeEvent::Assets(pallet_assets::Event::Issued { asset_id, owner, amount }) => {
				asset_id: *asset_id == expected_asset_id,
				owner: *owner == t.receiver.account_id,
				amount: *amount == expected_asset_amount,
			},
			// native asset for fee is deposited to receiver
			RuntimeEvent::ForeignAssets(pallet_assets::Event::Issued { asset_id, owner, .. }) => {
				asset_id: *asset_id == system_para_native_asset_location,
				owner: *owner == t.receiver.account_id,
			},
		]
	);
}

fn system_para_limited_teleport_assets(t: SystemParaToRelayTest) -> DispatchResult {
	<AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::limited_teleport_assets(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.beneficiary.into()),
		bx!(t.args.assets.into()),
		t.args.fee_asset_item,
		t.args.weight_limit,
	)
}

fn para_to_system_para_transfer_assets(t: ParaToSystemParaTest) -> DispatchResult {
	type Runtime = <PenpalA as Chain>::Runtime;
	let remote_fee_id: AssetId = t
		.args
		.assets
		.clone()
		.into_inner()
		.get(t.args.fee_asset_item as usize)
		.ok_or(pallet_xcm::Error::<Runtime>::Empty)?
		.clone()
		.id;

	<PenpalA as PenpalAPallet>::PolkadotXcm::transfer_assets_using_type_and_then(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.assets.into()),
		bx!(TransferType::Teleport),
		bx!(remote_fee_id.into()),
		bx!(TransferType::DestinationReserve),
		bx!(VersionedXcm::from(
			Xcm::<()>::builder_unsafe()
				.deposit_asset(AllCounted(2), t.args.beneficiary)
				.build()
		)),
		t.args.weight_limit,
	)
}

fn system_para_to_para_transfer_assets(t: SystemParaToParaTest) -> DispatchResult {
	type Runtime = <AssetHubRococo as Chain>::Runtime;
	let remote_fee_id: AssetId = t
		.args
		.assets
		.clone()
		.into_inner()
		.get(t.args.fee_asset_item as usize)
		.ok_or(pallet_xcm::Error::<Runtime>::Empty)?
		.clone()
		.id;

	<AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::transfer_assets_using_type_and_then(
		t.signed_origin,
		bx!(t.args.dest.into()),
		bx!(t.args.assets.into()),
		bx!(TransferType::Teleport),
		bx!(remote_fee_id.into()),
		bx!(TransferType::LocalReserve),
		bx!(VersionedXcm::from(
			Xcm::<()>::builder_unsafe()
				.deposit_asset(AllCounted(2), t.args.beneficiary)
				.build()
		)),
		t.args.weight_limit,
	)
}

#[test]
fn teleport_via_limited_teleport_assets_to_other_system_parachains_works() {
	let amount = ASSET_HUB_ROCOCO_ED * 100;
	let native_asset: Assets = (Parent, amount).into();

	test_parachain_is_trusted_teleporter!(
		AssetHubRococo,        // Origin
		vec![BridgeHubRococo], // Destinations
		(native_asset, amount),
		limited_teleport_assets
	);
}

#[test]
fn teleport_via_transfer_assets_to_other_system_parachains_works() {
	let amount = ASSET_HUB_ROCOCO_ED * 100;
	let native_asset: Assets = (Parent, amount).into();

	test_parachain_is_trusted_teleporter!(
		AssetHubRococo,        // Origin
		vec![BridgeHubRococo], // Destinations
		(native_asset, amount),
		transfer_assets
	);
}

#[test]
fn teleport_via_limited_teleport_assets_from_and_to_relay() {
	let amount = ROCOCO_ED * 100;
	let native_asset: Assets = (Here, amount).into();

	test_relay_is_trusted_teleporter!(
		Rococo,
		vec![AssetHubRococo],
		(native_asset, amount),
		limited_teleport_assets
	);

	test_parachain_is_trusted_teleporter_for_relay!(
		AssetHubRococo,
		Rococo,
		amount,
		limited_teleport_assets
	);
}

#[test]
fn teleport_via_transfer_assets_from_and_to_relay() {
	let amount = ROCOCO_ED * 100;
	let native_asset: Assets = (Here, amount).into();

	test_relay_is_trusted_teleporter!(
		Rococo,
		vec![AssetHubRococo],
		(native_asset, amount),
		transfer_assets
	);

	test_parachain_is_trusted_teleporter_for_relay!(
		AssetHubRococo,
		Rococo,
		amount,
		transfer_assets
	);
}

/// Limited Teleport of native asset from System Parachain to Relay Chain
/// shouldn't work when there is not enough balance in Relay Chain's `CheckAccount`
#[test]
fn limited_teleport_native_assets_from_system_para_to_relay_fails() {
	// Init values for Relay Chain
	let amount_to_send: Balance = ASSET_HUB_ROCOCO_ED * 1000;
	let destination = AssetHubRococo::parent_location().into();
	let beneficiary_id = RococoReceiver::get().into();
	let assets = (Parent, amount_to_send).into();

	let test_args = TestContext {
		sender: AssetHubRococoSender::get(),
		receiver: RococoReceiver::get(),
		args: TestArgs::new_para(destination, beneficiary_id, amount_to_send, assets, None, 0),
	};

	let mut test = SystemParaToRelayTest::new(test_args);

	let sender_balance_before = test.sender.balance;
	let receiver_balance_before = test.receiver.balance;

	test.set_assertion::<AssetHubRococo>(para_origin_assertions);
	test.set_assertion::<Rococo>(relay_dest_assertions_fail);
	test.set_dispatchable::<AssetHubRococo>(system_para_limited_teleport_assets);
	test.assert();

	let sender_balance_after = test.sender.balance;
	let receiver_balance_after = test.receiver.balance;

	let delivery_fees = AssetHubRococo::execute_with(|| {
		xcm_helpers::teleport_assets_delivery_fees::<
			<AssetHubRococoXcmConfig as xcm_executor::Config>::XcmSender,
		>(
			test.args.assets.clone(), 0, test.args.weight_limit, test.args.beneficiary, test.args.dest
		)
	});

	// Sender's balance is reduced
	assert_eq!(sender_balance_before - amount_to_send - delivery_fees, sender_balance_after);
	// Receiver's balance does not change
	assert_eq!(receiver_balance_after, receiver_balance_before);
}

/// Bidirectional teleports of local Penpal assets to Asset Hub as foreign assets while paying
/// fees using (reserve transferred) native asset.
pub fn do_bidirectional_teleport_foreign_assets_between_para_and_asset_hub_using_xt(
	para_to_ah_dispatchable: fn(ParaToSystemParaTest) -> DispatchResult,
	ah_to_para_dispatchable: fn(SystemParaToParaTest) -> DispatchResult,
) {
	// Init values for Parachain
	let fee_amount_to_send: Balance = ASSET_HUB_ROCOCO_ED * 10000;
	let asset_location_on_penpal = PenpalLocalTeleportableToAssetHub::get();
	let asset_id_on_penpal = match asset_location_on_penpal.last() {
		Some(Junction::GeneralIndex(id)) => *id as u32,
		_ => unreachable!(),
	};
	let asset_amount_to_send = ASSET_HUB_ROCOCO_ED * 1000;

	let asset_owner = PenpalAssetOwner::get();
	let system_para_native_asset_location = RelayLocation::get();
	let sender = PenpalASender::get();
	let penpal_check_account = <PenpalA as PenpalAPallet>::PolkadotXcm::check_account();
	let ah_as_seen_by_penpal = PenpalA::sibling_location_of(AssetHubRococo::para_id());
	let penpal_assets: Assets = vec![
		(Parent, fee_amount_to_send).into(),
		(asset_location_on_penpal.clone(), asset_amount_to_send).into(),
	]
	.into();
	let fee_asset_index = penpal_assets
		.inner()
		.iter()
		.position(|r| r == &(Parent, fee_amount_to_send).into())
		.unwrap() as u32;

	// fund Parachain's sender account
	PenpalA::mint_foreign_asset(
		<PenpalA as Chain>::RuntimeOrigin::signed(asset_owner.clone()),
		system_para_native_asset_location.clone(),
		sender.clone(),
		fee_amount_to_send * 2,
	);
	// No need to create the asset (only mint) as it exists in genesis.
	PenpalA::mint_asset(
		<PenpalA as Chain>::RuntimeOrigin::signed(asset_owner.clone()),
		asset_id_on_penpal,
		sender.clone(),
		asset_amount_to_send,
	);
	// fund Parachain's check account to be able to teleport
	PenpalA::fund_accounts(vec![(penpal_check_account.clone().into(), ASSET_HUB_ROCOCO_ED * 1000)]);

	// prefund SA of Penpal on AssetHub with enough native tokens to pay for fees
	let penpal_as_seen_by_ah = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let sov_penpal_on_ah = AssetHubRococo::sovereign_account_id_of(penpal_as_seen_by_ah);
	AssetHubRococo::fund_accounts(vec![(
		sov_penpal_on_ah.clone().into(),
		ASSET_HUB_ROCOCO_ED * 100_000_000_000,
	)]);

	// Init values for System Parachain
	let foreign_asset_at_asset_hub_rococo =
		Location::new(1, [Junction::Parachain(PenpalA::para_id().into())])
			.appended_with(asset_location_on_penpal)
			.unwrap();
	let penpal_to_ah_beneficiary_id = AssetHubRococoReceiver::get();

	// Penpal to AH test args
	let penpal_to_ah_test_args = TestContext {
		sender: PenpalASender::get(),
		receiver: AssetHubRococoReceiver::get(),
		args: TestArgs::new_para(
			ah_as_seen_by_penpal,
			penpal_to_ah_beneficiary_id,
			asset_amount_to_send,
			penpal_assets,
			Some(asset_id_on_penpal),
			fee_asset_index,
		),
	};
	let mut penpal_to_ah = ParaToSystemParaTest::new(penpal_to_ah_test_args);
	let penpal_sender_balance_before = PenpalA::execute_with(|| {
		type ForeignAssets = <PenpalA as PenpalAPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			system_para_native_asset_location.clone(),
			&PenpalASender::get(),
		)
	});

	let ah_receiver_balance_before = penpal_to_ah.receiver.balance;

	let penpal_sender_assets_before = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(asset_id_on_penpal, &PenpalASender::get())
	});
	let ah_receiver_assets_before = AssetHubRococo::execute_with(|| {
		type Assets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<Assets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo.clone().try_into().unwrap(),
			&AssetHubRococoReceiver::get(),
		)
	});

	penpal_to_ah.set_assertion::<PenpalA>(penpal_to_ah_foreign_assets_sender_assertions);
	penpal_to_ah.set_assertion::<AssetHubRococo>(penpal_to_ah_foreign_assets_receiver_assertions);
	penpal_to_ah.set_dispatchable::<PenpalA>(para_to_ah_dispatchable);
	penpal_to_ah.assert();

	let penpal_sender_balance_after = PenpalA::execute_with(|| {
		type ForeignAssets = <PenpalA as PenpalAPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			system_para_native_asset_location.clone(),
			&PenpalASender::get(),
		)
	});

	let ah_receiver_balance_after = penpal_to_ah.receiver.balance;

	let penpal_sender_assets_after = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(asset_id_on_penpal, &PenpalASender::get())
	});
	let ah_receiver_assets_after = AssetHubRococo::execute_with(|| {
		type Assets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<Assets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo.clone().try_into().unwrap(),
			&AssetHubRococoReceiver::get(),
		)
	});

	// Sender's balance is reduced
	assert!(penpal_sender_balance_after < penpal_sender_balance_before);
	// Receiver's balance is increased
	assert!(ah_receiver_balance_after > ah_receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(ah_receiver_balance_after < ah_receiver_balance_before + fee_amount_to_send);

	// Sender's balance is reduced by exact amount
	assert_eq!(penpal_sender_assets_before - asset_amount_to_send, penpal_sender_assets_after);
	// Receiver's balance is increased by exact amount
	assert_eq!(ah_receiver_assets_after, ah_receiver_assets_before + asset_amount_to_send);

	///////////////////////////////////////////////////////////////////////
	// Now test transferring foreign assets back from AssetHub to Penpal //
	///////////////////////////////////////////////////////////////////////

	// Move funds on AH from AHReceiver to AHSender
	AssetHubRococo::execute_with(|| {
		type ForeignAssets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		assert_ok!(ForeignAssets::transfer(
			<AssetHubRococo as Chain>::RuntimeOrigin::signed(AssetHubRococoReceiver::get()),
			foreign_asset_at_asset_hub_rococo.clone().try_into().unwrap(),
			AssetHubRococoSender::get().into(),
			asset_amount_to_send,
		));
	});

	let ah_to_penpal_beneficiary_id = PenpalAReceiver::get();
	let penpal_as_seen_by_ah = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let ah_assets: Assets = vec![
		(Parent, fee_amount_to_send).into(),
		(foreign_asset_at_asset_hub_rococo.clone(), asset_amount_to_send).into(),
	]
	.into();
	let fee_asset_index = ah_assets
		.inner()
		.iter()
		.position(|r| r == &(Parent, fee_amount_to_send).into())
		.unwrap() as u32;

	// AH to Penpal test args
	let ah_to_penpal_test_args = TestContext {
		sender: AssetHubRococoSender::get(),
		receiver: PenpalAReceiver::get(),
		args: TestArgs::new_para(
			penpal_as_seen_by_ah,
			ah_to_penpal_beneficiary_id,
			asset_amount_to_send,
			ah_assets,
			Some(asset_id_on_penpal),
			fee_asset_index,
		),
	};

	let mut ah_to_penpal = SystemParaToParaTest::new(ah_to_penpal_test_args);

	let ah_sender_balance_before = ah_to_penpal.sender.balance;
	let penpal_receiver_balance_before = PenpalA::execute_with(|| {
		type ForeignAssets = <PenpalA as PenpalAPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			system_para_native_asset_location.clone(),
			&PenpalAReceiver::get(),
		)
	});

	let ah_sender_assets_before = AssetHubRococo::execute_with(|| {
		type ForeignAssets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo.clone().try_into().unwrap(),
			&AssetHubRococoSender::get(),
		)
	});
	let penpal_receiver_assets_before = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(asset_id_on_penpal, &PenpalAReceiver::get())
	});

	ah_to_penpal.set_assertion::<AssetHubRococo>(ah_to_penpal_foreign_assets_sender_assertions);
	ah_to_penpal.set_assertion::<PenpalA>(ah_to_penpal_foreign_assets_receiver_assertions);
	ah_to_penpal.set_dispatchable::<AssetHubRococo>(ah_to_para_dispatchable);
	ah_to_penpal.assert();

	let ah_sender_balance_after = ah_to_penpal.sender.balance;
	let penpal_receiver_balance_after = PenpalA::execute_with(|| {
		type ForeignAssets = <PenpalA as PenpalAPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			system_para_native_asset_location,
			&PenpalAReceiver::get(),
		)
	});

	let ah_sender_assets_after = AssetHubRococo::execute_with(|| {
		type ForeignAssets = <AssetHubRococo as AssetHubRococoPallet>::ForeignAssets;
		<ForeignAssets as Inspect<_>>::balance(
			foreign_asset_at_asset_hub_rococo.try_into().unwrap(),
			&AssetHubRococoSender::get(),
		)
	});
	let penpal_receiver_assets_after = PenpalA::execute_with(|| {
		type Assets = <PenpalA as PenpalAPallet>::Assets;
		<Assets as Inspect<_>>::balance(asset_id_on_penpal, &PenpalAReceiver::get())
	});

	// Sender's balance is reduced
	assert!(ah_sender_balance_after < ah_sender_balance_before);
	// Receiver's balance is increased
	assert!(penpal_receiver_balance_after > penpal_receiver_balance_before);
	// Receiver's balance increased by `amount_to_send - delivery_fees - bought_execution`;
	// `delivery_fees` might be paid from transfer or JIT, also `bought_execution` is unknown but
	// should be non-zero
	assert!(penpal_receiver_balance_after < penpal_receiver_balance_before + fee_amount_to_send);

	// Sender's balance is reduced by exact amount
	assert_eq!(ah_sender_assets_before - asset_amount_to_send, ah_sender_assets_after);
	// Receiver's balance is increased by exact amount
	assert_eq!(penpal_receiver_assets_after, penpal_receiver_assets_before + asset_amount_to_send);
}

/// Bidirectional teleports of local Penpal assets to Asset Hub as foreign assets should work
/// (using native reserve-based transfer for fees)
#[test]
fn bidirectional_teleport_foreign_assets_between_para_and_asset_hub() {
	do_bidirectional_teleport_foreign_assets_between_para_and_asset_hub_using_xt(
		para_to_system_para_transfer_assets,
		system_para_to_para_transfer_assets,
	);
}

/// Teleport Native Asset from AssetHub to Parachain fails.
#[test]
fn teleport_to_untrusted_chain_fails() {
	// Init values for Parachain Origin
	let destination = AssetHubRococo::sibling_location_of(PenpalA::para_id());
	let signed_origin =
		<AssetHubRococo as Chain>::RuntimeOrigin::signed(AssetHubRococoSender::get().into());
	let roc_to_send: Balance = ROCOCO_ED * 10000;
	let roc_location = RelayLocation::get();

	// Assets to send
	let assets: Vec<Asset> = vec![(roc_location.clone(), roc_to_send).into()];
	let fee_id: AssetId = roc_location.into();

	// this should fail
	AssetHubRococo::execute_with(|| {
		let result = <AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::transfer_assets_using_type_and_then(
			signed_origin.clone(),
			bx!(destination.clone().into()),
			bx!(assets.clone().into()),
			bx!(TransferType::Teleport),
			bx!(fee_id.into()),
			bx!(TransferType::Teleport),
			bx!(VersionedXcm::from(Xcm::<()>::new())),
			Unlimited,
		);
		assert_err!(
			result,
			DispatchError::Module(sp_runtime::ModuleError {
				index: 31,
				error: [2, 0, 0, 0],
				message: Some("Filtered")
			})
		);
	});

	// this should also fail
	AssetHubRococo::execute_with(|| {
		let xcm: Xcm<asset_hub_rococo_runtime::RuntimeCall> = Xcm(vec![
			WithdrawAsset(assets.into()),
			InitiateTeleport { assets: Wild(All), dest: destination, xcm: Xcm::<()>::new() },
		]);
		let result = <AssetHubRococo as AssetHubRococoPallet>::PolkadotXcm::execute(
			signed_origin,
			bx!(xcm::VersionedXcm::from(xcm)),
			Weight::MAX,
		);
		assert!(result.is_err());
	});
}
