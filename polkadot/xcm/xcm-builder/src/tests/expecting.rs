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

#[test]
fn expect_pallet_should_work() {
	AllowUnpaidFrom::set(vec![[Parachain(1)].into()]);
	// They want to transfer 100 of our native asset from sovereign account of parachain #1 into #2
	// and let them know to hand it to account #3.
	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(r, Outcome::Complete { used: Weight::from_parts(10, 10) });

	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 41,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(r, Outcome::Complete { used: Weight::from_parts(10, 10) });
}

#[test]
fn expect_pallet_should_fail_correctly() {
	AllowUnpaidFrom::set(vec![[Parachain(1)].into()]);
	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 60,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::VersionIncompatible },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"System".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::NameMismatch },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_system".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::NameMismatch },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 0,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::NameMismatch },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 2,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::PalletNotFound },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 2,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::VersionIncompatible },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 0,
		min_crate_minor: 42,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::VersionIncompatible },
		}
	);

	let message = Xcm(vec![ExpectPallet {
		index: 1,
		name: b"Balances".as_ref().into(),
		module_name: b"pallet_balances".as_ref().into(),
		crate_major: 1,
		min_crate_minor: 43,
	}]);
	let mut hash = fake_message_hash(&message);
	let r = XcmExecutor::<TestConfig>::prepare_and_execute(
		Parachain(1),
		message,
		&mut hash,
		Weight::from_parts(50, 50),
		Weight::zero(),
	);
	assert_eq!(
		r,
		Outcome::Incomplete {
			used: Weight::from_parts(10, 10),
			error: InstructionError { index: 0, error: XcmError::VersionIncompatible },
		}
	);
}
