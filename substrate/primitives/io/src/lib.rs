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

//! # Substrate Primitives: IO
//!
//! This crate contains interfaces for the runtime to communicate with the outside world, ergo `io`.
//! In other context, such interfaces are referred to as "**host functions**".
//!
//! Each set of host functions are defined with an instance of the
//! [`sp_runtime_interface::runtime_interface`] macro.
//!
//! Most notably, this crate contains host functions for:
//!
//! - [`hashing`]
//! - [`crypto`]
//! - [`trie`]
//! - [`offchain`]
//! - [`storage`]
//! - [`allocator`]
//! - [`logging`]
//!
//! All of the default host functions provided by this crate, and by default contained in all
//! substrate-based clients are amalgamated in [`SubstrateHostFunctions`].
//!
//! ## Externalities
//!
//! Host functions go hand in hand with the concept of externalities. Externalities are an
//! environment in which host functions are provided, and thus can be accessed. Some host functions
//! are only accessible in an externality environment that provides it.
//!
//! A typical error for substrate developers is the following:
//!
//! ```should_panic
//! use sp_io::storage::get;
//! # fn main() {
//! let data = get(b"hello world");
//! # }
//! ```
//!
//! This code will panic with the following error:
//!
//! ```no_compile
//! thread 'main' panicked at '`get_version_1` called outside of an Externalities-provided environment.'
//! ```
//!
//! Such error messages should always be interpreted as "code accessing host functions accessed
//! outside of externalities".
//!
//! An externality is any type that implements [`sp_externalities::Externalities`]. A simple example
//! of which is [`TestExternalities`], which is commonly used in tests and is exported from this
//! crate.
//!
//! ```
//! use sp_io::{storage::get, TestExternalities};
//! # fn main() {
//! TestExternalities::default().execute_with(|| {
//! 	let data = get(b"hello world");
//! });
//! # }
//! ```

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(enable_alloc_error_handler, feature(alloc_error_handler))]

extern crate alloc;

use alloc::vec::Vec;

#[cfg(not(substrate_runtime))]
use tracing;

#[cfg(not(substrate_runtime))]
use sp_core::{
	crypto::Pair,
	hexdisplay::HexDisplay,
	offchain::{OffchainDbExt, OffchainWorkerExt, TransactionPoolExt},
	storage::ChildInfo,
};
#[cfg(not(substrate_runtime))]
use sp_keystore::KeystoreExt;

#[cfg(feature = "bandersnatch-experimental")]
use sp_core::bandersnatch;
use sp_core::{
	crypto::KeyTypeId,
	ecdsa, ed25519,
	offchain::{
		HttpError, HttpRequestId, HttpRequestStatus, OpaqueNetworkState, StorageKind, Timestamp,
	},
	sr25519,
	storage::StateVersion,
	LogLevelFilter, OpaquePeerId, RuntimeInterfaceLogLevel, H256,
};

#[cfg(feature = "bls-experimental")]
use sp_core::{bls381, ecdsa_bls381};

#[cfg(not(substrate_runtime))]
use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration};

use sp_runtime_interface::{
	pass_by::{
		AllocateAndReturnByCodec, AllocateAndReturnFatPointer, AllocateAndReturnPointer, PassAs,
		PassFatPointerAndDecode, PassFatPointerAndDecodeSlice, PassFatPointerAndRead,
		PassFatPointerAndReadWrite, PassPointerAndRead, PassPointerAndReadCopy, ReturnAs,
	},
	runtime_interface, Pointer,
};

use codec::{Decode, Encode};

#[cfg(not(substrate_runtime))]
use secp256k1::{
	ecdsa::{RecoverableSignature, RecoveryId},
	Message,
};

#[cfg(not(substrate_runtime))]
use sp_externalities::{Externalities, ExternalitiesExt};

pub use sp_externalities::MultiRemovalResults;

#[cfg(all(not(feature = "disable_allocator"), substrate_runtime, target_family = "wasm"))]
mod global_alloc_wasm;

#[cfg(all(
	not(feature = "disable_allocator"),
	substrate_runtime,
	any(target_arch = "riscv32", target_arch = "riscv64")
))]
mod global_alloc_riscv;

#[cfg(not(substrate_runtime))]
const LOG_TARGET: &str = "runtime::io";

/// Error verifying ECDSA signature
#[derive(Encode, Decode)]
pub enum EcdsaVerifyError {
	/// Incorrect value of R or S
	BadRS,
	/// Incorrect value of V
	BadV,
	/// Invalid signature
	BadSignature,
}

/// The outcome of calling `storage_kill`. Returned value is the number of storage items
/// removed from the backend from making the `storage_kill` call.
#[derive(Encode, Decode)]
pub enum KillStorageResult {
	/// All keys to remove were removed, return number of iterations performed during the
	/// operation.
	AllRemoved(u32),
	/// Not all key to remove were removed, return number of iterations performed during the
	/// operation.
	SomeRemaining(u32),
}

impl From<MultiRemovalResults> for KillStorageResult {
	fn from(r: MultiRemovalResults) -> Self {
		// We use `loops` here rather than `backend` because that's the same as the original
		// functionality pre-#11490. This won't matter once we switch to the new host function
		// since we won't be using the `KillStorageResult` type in the runtime any more.
		match r.maybe_cursor {
			None => Self::AllRemoved(r.loops),
			Some(..) => Self::SomeRemaining(r.loops),
		}
	}
}

/// Interface for accessing the storage from within the runtime.
#[runtime_interface]
pub trait Storage {
	/// Returns the data for `key` in the storage or `None` if the key can not be found.
	fn get(
		&mut self,
		key: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<bytes::Bytes>> {
		self.storage(key).map(|s| bytes::Bytes::from(s.to_vec()))
	}

	/// Get `key` from storage, placing the value into `value_out` and return the number of
	/// bytes that the entry in storage has beyond the offset or `None` if the storage entry
	/// doesn't exist at all.
	/// If `value_out` length is smaller than the returned length, only `value_out` length bytes
	/// are copied into `value_out`.
	fn read(
		&mut self,
		key: PassFatPointerAndRead<&[u8]>,
		value_out: PassFatPointerAndReadWrite<&mut [u8]>,
		value_offset: u32,
	) -> AllocateAndReturnByCodec<Option<u32>> {
		self.storage(key).map(|value| {
			let value_offset = value_offset as usize;
			let data = &value[value_offset.min(value.len())..];
			let written = core::cmp::min(data.len(), value_out.len());
			value_out[..written].copy_from_slice(&data[..written]);
			data.len() as u32
		})
	}

	/// Set `key` to `value` in the storage.
	fn set(&mut self, key: PassFatPointerAndRead<&[u8]>, value: PassFatPointerAndRead<&[u8]>) {
		self.set_storage(key.to_vec(), value.to_vec());
	}

	/// Clear the storage of the given `key` and its value.
	fn clear(&mut self, key: PassFatPointerAndRead<&[u8]>) {
		self.clear_storage(key)
	}

	/// Check whether the given `key` exists in storage.
	fn exists(&mut self, key: PassFatPointerAndRead<&[u8]>) -> bool {
		self.exists_storage(key)
	}

	/// Clear the storage of each key-value pair where the key starts with the given `prefix`.
	fn clear_prefix(&mut self, prefix: PassFatPointerAndRead<&[u8]>) {
		let _ = Externalities::clear_prefix(*self, prefix, None, None);
	}

	/// Clear the storage of each key-value pair where the key starts with the given `prefix`.
	///
	/// # Limit
	///
	/// Deletes all keys from the overlay and up to `limit` keys from the backend if
	/// it is set to `Some`. No limit is applied when `limit` is set to `None`.
	///
	/// The limit can be used to partially delete a prefix storage in case it is too large
	/// to delete in one go (block).
	///
	/// Returns [`KillStorageResult`] to inform about the result.
	///
	/// # Note
	///
	/// Please note that keys that are residing in the overlay for that prefix when
	/// issuing this call are all deleted without counting towards the `limit`. Only keys
	/// written during the current block are part of the overlay. Deleting with a `limit`
	/// mostly makes sense with an empty overlay for that prefix.
	///
	/// Calling this function multiple times per block for the same `prefix` does
	/// not make much sense because it is not cumulative when called inside the same block.
	/// The deletion would always start from `prefix` resulting in the same keys being deleted
	/// every time this function is called with the exact same arguments per block. This happens
	/// because the keys in the overlay are not taken into account when deleting keys in the
	/// backend.
	#[version(2)]
	fn clear_prefix(
		&mut self,
		prefix: PassFatPointerAndRead<&[u8]>,
		limit: PassFatPointerAndDecode<Option<u32>>,
	) -> AllocateAndReturnByCodec<KillStorageResult> {
		Externalities::clear_prefix(*self, prefix, limit, None).into()
	}

	/// Partially clear the storage of each key-value pair where the key starts with the given
	/// prefix.
	///
	/// # Limit
	///
	/// A *limit* should always be provided through `maybe_limit`. This is one fewer than the
	/// maximum number of backend iterations which may be done by this operation and as such
	/// represents the maximum number of backend deletions which may happen. A *limit* of zero
	/// implies that no keys will be deleted, though there may be a single iteration done.
	///
	/// The limit can be used to partially delete a prefix storage in case it is too large or costly
	/// to delete in a single operation.
	///
	/// # Cursor
	///
	/// A *cursor* may be passed in to this operation with `maybe_cursor`. `None` should only be
	/// passed once (in the initial call) for any given `maybe_prefix` value. Subsequent calls
	/// operating on the same prefix should always pass `Some`, and this should be equal to the
	/// previous call result's `maybe_cursor` field.
	///
	/// Returns [`MultiRemovalResults`](sp_io::MultiRemovalResults) to inform about the result. Once
	/// the resultant `maybe_cursor` field is `None`, then no further items remain to be deleted.
	///
	/// NOTE: After the initial call for any given prefix, it is important that no keys further
	/// keys under the same prefix are inserted. If so, then they may or may not be deleted by
	/// subsequent calls.
	///
	/// # Note
	///
	/// Please note that keys which are residing in the overlay for that prefix when
	/// issuing this call are deleted without counting towards the `limit`.
	#[version(3, register_only)]
	fn clear_prefix(
		&mut self,
		maybe_prefix: PassFatPointerAndRead<&[u8]>,
		maybe_limit: PassFatPointerAndDecode<Option<u32>>,
		maybe_cursor: PassFatPointerAndDecode<Option<Vec<u8>>>, /* TODO Make work or just
		                                                         * Option<Vec<u8>>? */
	) -> AllocateAndReturnByCodec<MultiRemovalResults> {
		Externalities::clear_prefix(
			*self,
			maybe_prefix,
			maybe_limit,
			maybe_cursor.as_ref().map(|x| &x[..]),
		)
		.into()
	}

	/// Append the encoded `value` to the storage item at `key`.
	///
	/// The storage item needs to implement [`EncodeAppend`](codec::EncodeAppend).
	///
	/// # Warning
	///
	/// If the storage item does not support [`EncodeAppend`](codec::EncodeAppend) or
	/// something else fails at appending, the storage item will be set to `[value]`.
	fn append(&mut self, key: PassFatPointerAndRead<&[u8]>, value: PassFatPointerAndRead<Vec<u8>>) {
		self.storage_append(key.to_vec(), value);
	}

	/// "Commit" all existing operations and compute the resulting storage root.
	///
	/// The hashing algorithm is defined by the `Block`.
	///
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	fn root(&mut self) -> AllocateAndReturnFatPointer<Vec<u8>> {
		self.storage_root(StateVersion::V0)
	}

	/// "Commit" all existing operations and compute the resulting storage root.
	///
	/// The hashing algorithm is defined by the `Block`.
	///
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	#[version(2)]
	fn root(&mut self, version: PassAs<StateVersion, u8>) -> AllocateAndReturnFatPointer<Vec<u8>> {
		self.storage_root(version)
	}

	/// Always returns `None`. This function exists for compatibility reasons.
	fn changes_root(
		&mut self,
		_parent_hash: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		None
	}

	/// Get the next key in storage after the given one in lexicographic order.
	fn next_key(
		&mut self,
		key: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		self.next_storage_key(key)
	}

	/// Start a new nested transaction.
	///
	/// This allows to either commit or roll back all changes that are made after this call.
	/// For every transaction there must be a matching call to either `rollback_transaction`
	/// or `commit_transaction`. This is also effective for all values manipulated using the
	/// `DefaultChildStorage` API.
	///
	/// # Warning
	///
	/// This is a low level API that is potentially dangerous as it can easily result
	/// in unbalanced transactions. For example, FRAME users should use high level storage
	/// abstractions.
	fn start_transaction(&mut self) {
		self.storage_start_transaction();
	}

	/// Rollback the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are discarded.
	///
	/// # Panics
	///
	/// Will panic if there is no open transaction.
	fn rollback_transaction(&mut self) {
		self.storage_rollback_transaction()
			.expect("No open transaction that can be rolled back.");
	}

	/// Commit the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are committed.
	///
	/// # Panics
	///
	/// Will panic if there is no open transaction.
	fn commit_transaction(&mut self) {
		self.storage_commit_transaction()
			.expect("No open transaction that can be committed.");
	}
}

/// Interface for accessing the child storage for default child trie,
/// from within the runtime.
#[runtime_interface]
pub trait DefaultChildStorage {
	/// Get a default child storage value for a given key.
	///
	/// Parameter `storage_key` is the unprefixed location of the root of the child trie in the
	/// parent trie. Result is `None` if the value for `key` in the child storage can not be found.
	fn get(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		key: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage(&child_info, key).map(|s| s.to_vec())
	}

	/// Allocation efficient variant of `get`.
	///
	/// Get `key` from child storage, placing the value into `value_out` and return the number
	/// of bytes that the entry in storage has beyond the offset or `None` if the storage entry
	/// doesn't exist at all.
	/// If `value_out` length is smaller than the returned length, only `value_out` length bytes
	/// are copied into `value_out`.
	fn read(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		key: PassFatPointerAndRead<&[u8]>,
		value_out: PassFatPointerAndReadWrite<&mut [u8]>,
		value_offset: u32,
	) -> AllocateAndReturnByCodec<Option<u32>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage(&child_info, key).map(|value| {
			let value_offset = value_offset as usize;
			let data = &value[value_offset.min(value.len())..];
			let written = core::cmp::min(data.len(), value_out.len());
			value_out[..written].copy_from_slice(&data[..written]);
			data.len() as u32
		})
	}

	/// Set a child storage value.
	///
	/// Set `key` to `value` in the child storage denoted by `storage_key`.
	fn set(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		key: PassFatPointerAndRead<&[u8]>,
		value: PassFatPointerAndRead<&[u8]>,
	) {
		let child_info = ChildInfo::new_default(storage_key);
		self.set_child_storage(&child_info, key.to_vec(), value.to_vec());
	}

	/// Clear a child storage key.
	///
	/// For the default child storage at `storage_key`, clear value at `key`.
	fn clear(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		key: PassFatPointerAndRead<&[u8]>,
	) {
		let child_info = ChildInfo::new_default(storage_key);
		self.clear_child_storage(&child_info, key);
	}

	/// Clear an entire child storage.
	///
	/// If it exists, the child storage for `storage_key`
	/// is removed.
	fn storage_kill(&mut self, storage_key: PassFatPointerAndRead<&[u8]>) {
		let child_info = ChildInfo::new_default(storage_key);
		let _ = self.kill_child_storage(&child_info, None, None);
	}

	/// Clear a child storage key.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(2)]
	fn storage_kill(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		limit: PassFatPointerAndDecode<Option<u32>>,
	) -> bool {
		let child_info = ChildInfo::new_default(storage_key);
		let r = self.kill_child_storage(&child_info, limit, None);
		r.maybe_cursor.is_none()
	}

	/// Clear a child storage key.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(3)]
	fn storage_kill(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		limit: PassFatPointerAndDecode<Option<u32>>,
	) -> AllocateAndReturnByCodec<KillStorageResult> {
		let child_info = ChildInfo::new_default(storage_key);
		self.kill_child_storage(&child_info, limit, None).into()
	}

	/// Clear a child storage key.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(4, register_only)]
	fn storage_kill(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		maybe_limit: PassFatPointerAndDecode<Option<u32>>,
		maybe_cursor: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnByCodec<MultiRemovalResults> {
		let child_info = ChildInfo::new_default(storage_key);
		self.kill_child_storage(&child_info, maybe_limit, maybe_cursor.as_ref().map(|x| &x[..]))
			.into()
	}

	/// Check a child storage key.
	///
	/// Check whether the given `key` exists in default child defined at `storage_key`.
	fn exists(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		key: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		let child_info = ChildInfo::new_default(storage_key);
		self.exists_child_storage(&child_info, key)
	}

	/// Clear child default key by prefix.
	///
	/// Clear the child storage of each key-value pair where the key starts with the given `prefix`.
	fn clear_prefix(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		prefix: PassFatPointerAndRead<&[u8]>,
	) {
		let child_info = ChildInfo::new_default(storage_key);
		let _ = self.clear_child_prefix(&child_info, prefix, None, None);
	}

	/// Clear the child storage of each key-value pair where the key starts with the given `prefix`.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(2)]
	fn clear_prefix(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		prefix: PassFatPointerAndRead<&[u8]>,
		limit: PassFatPointerAndDecode<Option<u32>>,
	) -> AllocateAndReturnByCodec<KillStorageResult> {
		let child_info = ChildInfo::new_default(storage_key);
		self.clear_child_prefix(&child_info, prefix, limit, None).into()
	}

	/// Clear the child storage of each key-value pair where the key starts with the given `prefix`.
	///
	/// See `Storage` module `clear_prefix` documentation for `limit` usage.
	#[version(3, register_only)]
	fn clear_prefix(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		prefix: PassFatPointerAndRead<&[u8]>,
		maybe_limit: PassFatPointerAndDecode<Option<u32>>,
		maybe_cursor: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnByCodec<MultiRemovalResults> {
		let child_info = ChildInfo::new_default(storage_key);
		self.clear_child_prefix(
			&child_info,
			prefix,
			maybe_limit,
			maybe_cursor.as_ref().map(|x| &x[..]),
		)
		.into()
	}

	/// Default child root calculation.
	///
	/// "Commit" all existing operations and compute the resulting child storage root.
	/// The hashing algorithm is defined by the `Block`.
	///
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	fn root(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage_root(&child_info, StateVersion::V0)
	}

	/// Default child root calculation.
	///
	/// "Commit" all existing operations and compute the resulting child storage root.
	/// The hashing algorithm is defined by the `Block`.
	///
	/// Returns a `Vec<u8>` that holds the SCALE encoded hash.
	#[version(2)]
	fn root(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		version: PassAs<StateVersion, u8>,
	) -> AllocateAndReturnFatPointer<Vec<u8>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.child_storage_root(&child_info, version)
	}

	/// Child storage key iteration.
	///
	/// Get the next key in storage after the given one in lexicographic order in child storage.
	fn next_key(
		&mut self,
		storage_key: PassFatPointerAndRead<&[u8]>,
		key: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		let child_info = ChildInfo::new_default(storage_key);
		self.next_child_storage_key(&child_info, key)
	}
}

/// Interface that provides trie related functionality.
#[runtime_interface]
pub trait Trie {
	/// A trie root formed from the iterated items.
	fn blake2_256_root(
		input: PassFatPointerAndDecode<Vec<(Vec<u8>, Vec<u8>)>>,
	) -> AllocateAndReturnPointer<H256, 32> {
		LayoutV0::<sp_core::Blake2Hasher>::trie_root(input)
	}

	/// A trie root formed from the iterated items.
	#[version(2)]
	fn blake2_256_root(
		input: PassFatPointerAndDecode<Vec<(Vec<u8>, Vec<u8>)>>,
		version: PassAs<StateVersion, u8>,
	) -> AllocateAndReturnPointer<H256, 32> {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::Blake2Hasher>::trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::Blake2Hasher>::trie_root(input),
		}
	}

	/// A trie root formed from the enumerated items.
	fn blake2_256_ordered_root(
		input: PassFatPointerAndDecode<Vec<Vec<u8>>>,
	) -> AllocateAndReturnPointer<H256, 32> {
		LayoutV0::<sp_core::Blake2Hasher>::ordered_trie_root(input)
	}

	/// A trie root formed from the enumerated items.
	#[version(2)]
	fn blake2_256_ordered_root(
		input: PassFatPointerAndDecode<Vec<Vec<u8>>>,
		version: PassAs<StateVersion, u8>,
	) -> AllocateAndReturnPointer<H256, 32> {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::Blake2Hasher>::ordered_trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::Blake2Hasher>::ordered_trie_root(input),
		}
	}

	/// A trie root formed from the iterated items.
	fn keccak_256_root(
		input: PassFatPointerAndDecode<Vec<(Vec<u8>, Vec<u8>)>>,
	) -> AllocateAndReturnPointer<H256, 32> {
		LayoutV0::<sp_core::KeccakHasher>::trie_root(input)
	}

	/// A trie root formed from the iterated items.
	#[version(2)]
	fn keccak_256_root(
		input: PassFatPointerAndDecode<Vec<(Vec<u8>, Vec<u8>)>>,
		version: PassAs<StateVersion, u8>,
	) -> AllocateAndReturnPointer<H256, 32> {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::KeccakHasher>::trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::KeccakHasher>::trie_root(input),
		}
	}

	/// A trie root formed from the enumerated items.
	fn keccak_256_ordered_root(
		input: PassFatPointerAndDecode<Vec<Vec<u8>>>,
	) -> AllocateAndReturnPointer<H256, 32> {
		LayoutV0::<sp_core::KeccakHasher>::ordered_trie_root(input)
	}

	/// A trie root formed from the enumerated items.
	#[version(2)]
	fn keccak_256_ordered_root(
		input: PassFatPointerAndDecode<Vec<Vec<u8>>>,
		version: PassAs<StateVersion, u8>,
	) -> AllocateAndReturnPointer<H256, 32> {
		match version {
			StateVersion::V0 => LayoutV0::<sp_core::KeccakHasher>::ordered_trie_root(input),
			StateVersion::V1 => LayoutV1::<sp_core::KeccakHasher>::ordered_trie_root(input),
		}
	}

	/// Verify trie proof
	fn blake2_256_verify_proof(
		root: PassPointerAndReadCopy<H256, 32>,
		proof: PassFatPointerAndDecodeSlice<&[Vec<u8>]>,
		key: PassFatPointerAndRead<&[u8]>,
		value: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		sp_trie::verify_trie_proof::<LayoutV0<sp_core::Blake2Hasher>, _, _, _>(
			&root,
			proof,
			&[(key, Some(value))],
		)
		.is_ok()
	}

	/// Verify trie proof
	#[version(2)]
	fn blake2_256_verify_proof(
		root: PassPointerAndReadCopy<H256, 32>,
		proof: PassFatPointerAndDecodeSlice<&[Vec<u8>]>,
		key: PassFatPointerAndRead<&[u8]>,
		value: PassFatPointerAndRead<&[u8]>,
		version: PassAs<StateVersion, u8>,
	) -> bool {
		match version {
			StateVersion::V0 => sp_trie::verify_trie_proof::<
				LayoutV0<sp_core::Blake2Hasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
			StateVersion::V1 => sp_trie::verify_trie_proof::<
				LayoutV1<sp_core::Blake2Hasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
		}
	}

	/// Verify trie proof
	fn keccak_256_verify_proof(
		root: PassPointerAndReadCopy<H256, 32>,
		proof: PassFatPointerAndDecodeSlice<&[Vec<u8>]>,
		key: PassFatPointerAndRead<&[u8]>,
		value: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		sp_trie::verify_trie_proof::<LayoutV0<sp_core::KeccakHasher>, _, _, _>(
			&root,
			proof,
			&[(key, Some(value))],
		)
		.is_ok()
	}

	/// Verify trie proof
	#[version(2)]
	fn keccak_256_verify_proof(
		root: PassPointerAndReadCopy<H256, 32>,
		proof: PassFatPointerAndDecodeSlice<&[Vec<u8>]>,
		key: PassFatPointerAndRead<&[u8]>,
		value: PassFatPointerAndRead<&[u8]>,
		version: PassAs<StateVersion, u8>,
	) -> bool {
		match version {
			StateVersion::V0 => sp_trie::verify_trie_proof::<
				LayoutV0<sp_core::KeccakHasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
			StateVersion::V1 => sp_trie::verify_trie_proof::<
				LayoutV1<sp_core::KeccakHasher>,
				_,
				_,
				_,
			>(&root, proof, &[(key, Some(value))])
			.is_ok(),
		}
	}
}

/// Interface that provides miscellaneous functions for communicating between the runtime and the
/// node.
#[runtime_interface]
pub trait Misc {
	// NOTE: We use the target 'runtime' for messages produced by general printing functions,
	// instead of LOG_TARGET.

	/// Print a number.
	fn print_num(val: u64) {
		log::debug!(target: "runtime", "{}", val);
	}

	/// Print any valid `utf8` buffer.
	fn print_utf8(utf8: PassFatPointerAndRead<&[u8]>) {
		if let Ok(data) = core::str::from_utf8(utf8) {
			log::debug!(target: "runtime", "{}", data)
		}
	}

	/// Print any `u8` slice as hex.
	fn print_hex(data: PassFatPointerAndRead<&[u8]>) {
		log::debug!(target: "runtime", "{}", HexDisplay::from(&data));
	}

	/// Extract the runtime version of the given wasm blob by calling `Core_version`.
	///
	/// Returns `None` if calling the function failed for any reason or `Some(Vec<u8>)` where
	/// the `Vec<u8>` holds the SCALE encoded runtime version.
	///
	/// # Performance
	///
	/// This function may be very expensive to call depending on the wasm binary. It may be
	/// relatively cheap if the wasm binary contains version information. In that case,
	/// uncompression of the wasm blob is the dominating factor.
	///
	/// If the wasm binary does not have the version information attached, then a legacy mechanism
	/// may be involved. This means that a runtime call will be performed to query the version.
	///
	/// Calling into the runtime may be incredible expensive and should be approached with care.
	fn runtime_version(
		&mut self,
		wasm: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		use sp_core::traits::ReadRuntimeVersionExt;

		let mut ext = sp_state_machine::BasicExternalities::default();

		match self
			.extension::<ReadRuntimeVersionExt>()
			.expect("No `ReadRuntimeVersionExt` associated for the current context!")
			.read_runtime_version(wasm, &mut ext)
		{
			Ok(v) => Some(v),
			Err(err) => {
				log::debug!(
					target: LOG_TARGET,
					"cannot read version from the given runtime: {}",
					err,
				);
				None
			},
		}
	}
}

#[cfg(not(substrate_runtime))]
sp_externalities::decl_extension! {
	/// Extension to signal to [`crypt::ed25519_verify`] to use the dalek crate.
	///
	/// The switch from `ed25519-dalek` to `ed25519-zebra` was a breaking change.
	/// `ed25519-zebra` is more permissive when it comes to the verification of signatures.
	/// This means that some chains may fail to sync from genesis when using `ed25519-zebra`.
	/// So, this extension can be registered to the runtime execution environment to signal
	/// that `ed25519-dalek` should be used for verification. The extension can be registered
	/// in the following way:
	///
	/// ```nocompile
	/// client.execution_extensions().set_extensions_factory(
	/// 	// Let the `UseDalekExt` extension being registered for each runtime invocation
	/// 	// until the execution happens in the context of block `1000`.
	/// 	sc_client_api::execution_extensions::ExtensionBeforeBlock::<Block, UseDalekExt>::new(1000)
	/// );
	/// ```
	pub struct UseDalekExt;
}

#[cfg(not(substrate_runtime))]
impl Default for UseDalekExt {
	fn default() -> Self {
		Self
	}
}

/// Interfaces for working with crypto related types from within the runtime.
#[runtime_interface]
pub trait Crypto {
	/// Returns all `ed25519` public keys for the given key id from the keystore.
	fn ed25519_public_keys(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
	) -> AllocateAndReturnByCodec<Vec<ed25519::Public>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ed25519_public_keys(id)
	}

	/// Generate an `ed22519` key for the given key type using an optional `seed` and
	/// store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	fn ed25519_generate(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		seed: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnPointer<ed25519::Public, 32> {
		let seed = seed.as_ref().map(|s| core::str::from_utf8(s).expect("Seed is valid utf8!"));
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ed25519_generate_new(id, seed)
			.expect("`ed25519_generate` failed")
	}

	/// Sign the given `msg` with the `ed25519` key that corresponds to the given public key and
	/// key type in the keystore.
	///
	/// Returns the signature.
	fn ed25519_sign(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		pub_key: PassPointerAndRead<&ed25519::Public, 32>,
		msg: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<ed25519::Signature>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ed25519_sign(id, pub_key, msg)
			.ok()
			.flatten()
	}

	/// Verify `ed25519` signature.
	///
	/// Returns `true` when the verification was successful.
	fn ed25519_verify(
		sig: PassPointerAndRead<&ed25519::Signature, 64>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&ed25519::Public, 32>,
	) -> bool {
		// We don't want to force everyone needing to call the function in an externalities context.
		// So, we assume that we should not use dalek when we are not in externalities context.
		// Otherwise, we check if the extension is present.
		if sp_externalities::with_externalities(|mut e| e.extension::<UseDalekExt>().is_some())
			.unwrap_or_default()
		{
			use ed25519_dalek::Verifier;

			let Ok(public_key) = ed25519_dalek::VerifyingKey::from_bytes(&pub_key.0) else {
				return false
			};

			let sig = ed25519_dalek::Signature::from_bytes(&sig.0);

			public_key.verify(msg, &sig).is_ok()
		} else {
			ed25519::Pair::verify(sig, msg, pub_key)
		}
	}

	/// Register a `ed25519` signature for batch verification.
	///
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediately.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	///
	/// NOTE: Is tagged with `register_only` to keep the functions around for backwards
	/// compatibility with old runtimes, but it should not be used anymore by new runtimes.
	/// The implementation emulates the old behavior, but isn't doing any batch verification
	/// anymore.
	#[version(1, register_only)]
	fn ed25519_batch_verify(
		&mut self,
		sig: PassPointerAndRead<&ed25519::Signature, 64>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&ed25519::Public, 32>,
	) -> bool {
		let res = ed25519_verify(sig, msg, pub_key);

		if let Some(ext) = self.extension::<VerificationExtDeprecated>() {
			ext.0 &= res;
		}

		res
	}

	/// Verify `sr25519` signature.
	///
	/// Returns `true` when the verification was successful.
	#[version(2)]
	fn sr25519_verify(
		sig: PassPointerAndRead<&sr25519::Signature, 64>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&sr25519::Public, 32>,
	) -> bool {
		sr25519::Pair::verify(sig, msg, pub_key)
	}

	/// Register a `sr25519` signature for batch verification.
	///
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediately.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	///
	/// NOTE: Is tagged with `register_only` to keep the functions around for backwards
	/// compatibility with old runtimes, but it should not be used anymore by new runtimes.
	/// The implementation emulates the old behavior, but isn't doing any batch verification
	/// anymore.
	#[version(1, register_only)]
	fn sr25519_batch_verify(
		&mut self,
		sig: PassPointerAndRead<&sr25519::Signature, 64>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&sr25519::Public, 32>,
	) -> bool {
		let res = sr25519_verify(sig, msg, pub_key);

		if let Some(ext) = self.extension::<VerificationExtDeprecated>() {
			ext.0 &= res;
		}

		res
	}

	/// Start verification extension.
	///
	/// NOTE: Is tagged with `register_only` to keep the functions around for backwards
	/// compatibility with old runtimes, but it should not be used anymore by new runtimes.
	/// The implementation emulates the old behavior, but isn't doing any batch verification
	/// anymore.
	#[version(1, register_only)]
	fn start_batch_verify(&mut self) {
		self.register_extension(VerificationExtDeprecated(true))
			.expect("Failed to register required extension: `VerificationExt`");
	}

	/// Finish batch-verification of signatures.
	///
	/// Verify or wait for verification to finish for all signatures which were previously
	/// deferred by `sr25519_verify`/`ed25519_verify`.
	///
	/// Will panic if no `VerificationExt` is registered (`start_batch_verify` was not called).
	///
	/// NOTE: Is tagged with `register_only` to keep the functions around for backwards
	/// compatibility with old runtimes, but it should not be used anymore by new runtimes.
	/// The implementation emulates the old behavior, but isn't doing any batch verification
	/// anymore.
	#[version(1, register_only)]
	fn finish_batch_verify(&mut self) -> bool {
		let result = self
			.extension::<VerificationExtDeprecated>()
			.expect("`finish_batch_verify` should only be called after `start_batch_verify`")
			.0;

		self.deregister_extension::<VerificationExtDeprecated>()
			.expect("No verification extension in current context!");

		result
	}

	/// Returns all `sr25519` public keys for the given key id from the keystore.
	fn sr25519_public_keys(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
	) -> AllocateAndReturnByCodec<Vec<sr25519::Public>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.sr25519_public_keys(id)
	}

	/// Generate an `sr22519` key for the given key type using an optional seed and
	/// store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	fn sr25519_generate(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		seed: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnPointer<sr25519::Public, 32> {
		let seed = seed.as_ref().map(|s| core::str::from_utf8(s).expect("Seed is valid utf8!"));
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.sr25519_generate_new(id, seed)
			.expect("`sr25519_generate` failed")
	}

	/// Sign the given `msg` with the `sr25519` key that corresponds to the given public key and
	/// key type in the keystore.
	///
	/// Returns the signature.
	fn sr25519_sign(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		pub_key: PassPointerAndRead<&sr25519::Public, 32>,
		msg: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<sr25519::Signature>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.sr25519_sign(id, pub_key, msg)
			.ok()
			.flatten()
	}

	/// Verify an `sr25519` signature.
	///
	/// Returns `true` when the verification in successful regardless of
	/// signature version.
	fn sr25519_verify(
		sig: PassPointerAndRead<&sr25519::Signature, 64>,
		msg: PassFatPointerAndRead<&[u8]>,
		pubkey: PassPointerAndRead<&sr25519::Public, 32>,
	) -> bool {
		sr25519::Pair::verify_deprecated(sig, msg, pubkey)
	}

	/// Returns all `ecdsa` public keys for the given key id from the keystore.
	fn ecdsa_public_keys(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
	) -> AllocateAndReturnByCodec<Vec<ecdsa::Public>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ecdsa_public_keys(id)
	}

	/// Generate an `ecdsa` key for the given key type using an optional `seed` and
	/// store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	fn ecdsa_generate(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		seed: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnPointer<ecdsa::Public, 33> {
		let seed = seed.as_ref().map(|s| core::str::from_utf8(s).expect("Seed is valid utf8!"));
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ecdsa_generate_new(id, seed)
			.expect("`ecdsa_generate` failed")
	}

	/// Sign the given `msg` with the `ecdsa` key that corresponds to the given public key and
	/// key type in the keystore.
	///
	/// Returns the signature.
	fn ecdsa_sign(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
		msg: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<ecdsa::Signature>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ecdsa_sign(id, pub_key, msg)
			.ok()
			.flatten()
	}

	/// Sign the given a pre-hashed `msg` with the `ecdsa` key that corresponds to the given public
	/// key and key type in the keystore.
	///
	/// Returns the signature.
	fn ecdsa_sign_prehashed(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
	) -> AllocateAndReturnByCodec<Option<ecdsa::Signature>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ecdsa_sign_prehashed(id, pub_key, msg)
			.ok()
			.flatten()
	}

	/// Verify `ecdsa` signature.
	///
	/// Returns `true` when the verification was successful.
	/// This version is able to handle, non-standard, overflowing signatures.
	fn ecdsa_verify(
		sig: PassPointerAndRead<&ecdsa::Signature, 65>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
	) -> bool {
		#[allow(deprecated)]
		ecdsa::Pair::verify_deprecated(sig, msg, pub_key)
	}

	/// Verify `ecdsa` signature.
	///
	/// Returns `true` when the verification was successful.
	#[version(2)]
	fn ecdsa_verify(
		sig: PassPointerAndRead<&ecdsa::Signature, 65>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
	) -> bool {
		ecdsa::Pair::verify(sig, msg, pub_key)
	}

	/// Verify `ecdsa` signature with pre-hashed `msg`.
	///
	/// Returns `true` when the verification was successful.
	fn ecdsa_verify_prehashed(
		sig: PassPointerAndRead<&ecdsa::Signature, 65>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
		pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
	) -> bool {
		ecdsa::Pair::verify_prehashed(sig, msg, pub_key)
	}

	/// Register a `ecdsa` signature for batch verification.
	///
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediately.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	///
	/// NOTE: Is tagged with `register_only` to keep the functions around for backwards
	/// compatibility with old runtimes, but it should not be used anymore by new runtimes.
	/// The implementation emulates the old behavior, but isn't doing any batch verification
	/// anymore.
	#[version(1, register_only)]
	fn ecdsa_batch_verify(
		&mut self,
		sig: PassPointerAndRead<&ecdsa::Signature, 65>,
		msg: PassFatPointerAndRead<&[u8]>,
		pub_key: PassPointerAndRead<&ecdsa::Public, 33>,
	) -> bool {
		let res = ecdsa_verify(sig, msg, pub_key);

		if let Some(ext) = self.extension::<VerificationExtDeprecated>() {
			ext.0 &= res;
		}

		res
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 64-byte pubkey
	/// (doesn't include the 0x04 prefix).
	/// This version is able to handle, non-standard, overflowing signatures.
	fn secp256k1_ecdsa_recover(
		sig: PassPointerAndRead<&[u8; 65], 65>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
	) -> AllocateAndReturnByCodec<Result<[u8; 64], EcdsaVerifyError>> {
		let rid = libsecp256k1::RecoveryId::parse(
			if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
		)
		.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = libsecp256k1::Signature::parse_overflowing_slice(&sig[..64])
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = libsecp256k1::Message::parse(msg);
		let pubkey =
			libsecp256k1::recover(&msg, &sig, &rid).map_err(|_| EcdsaVerifyError::BadSignature)?;
		let mut res = [0u8; 64];
		res.copy_from_slice(&pubkey.serialize()[1..65]);
		Ok(res)
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 64-byte pubkey
	/// (doesn't include the 0x04 prefix).
	#[version(2)]
	fn secp256k1_ecdsa_recover(
		sig: PassPointerAndRead<&[u8; 65], 65>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
	) -> AllocateAndReturnByCodec<Result<[u8; 64], EcdsaVerifyError>> {
		let rid = RecoveryId::from_i32(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as i32)
			.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = RecoverableSignature::from_compact(&sig[..64], rid)
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = Message::from_digest_slice(msg).expect("Message is 32 bytes; qed");
		#[cfg(feature = "std")]
		let ctx = secp256k1::SECP256K1;
		#[cfg(not(feature = "std"))]
		let ctx = secp256k1::Secp256k1::<secp256k1::VerifyOnly>::gen_new();
		let pubkey = ctx.recover_ecdsa(&msg, &sig).map_err(|_| EcdsaVerifyError::BadSignature)?;
		let mut res = [0u8; 64];
		res.copy_from_slice(&pubkey.serialize_uncompressed()[1..]);
		Ok(res)
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 33-byte compressed pubkey.
	fn secp256k1_ecdsa_recover_compressed(
		sig: PassPointerAndRead<&[u8; 65], 65>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
	) -> AllocateAndReturnByCodec<Result<[u8; 33], EcdsaVerifyError>> {
		let rid = libsecp256k1::RecoveryId::parse(
			if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
		)
		.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = libsecp256k1::Signature::parse_overflowing_slice(&sig[0..64])
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = libsecp256k1::Message::parse(msg);
		let pubkey =
			libsecp256k1::recover(&msg, &sig, &rid).map_err(|_| EcdsaVerifyError::BadSignature)?;
		Ok(pubkey.serialize_compressed())
	}

	/// Verify and recover a SECP256k1 ECDSA signature.
	///
	/// - `sig` is passed in RSV format. V should be either `0/1` or `27/28`.
	/// - `msg` is the blake2-256 hash of the message.
	///
	/// Returns `Err` if the signature is bad, otherwise the 33-byte compressed pubkey.
	#[version(2)]
	fn secp256k1_ecdsa_recover_compressed(
		sig: PassPointerAndRead<&[u8; 65], 65>,
		msg: PassPointerAndRead<&[u8; 32], 32>,
	) -> AllocateAndReturnByCodec<Result<[u8; 33], EcdsaVerifyError>> {
		let rid = RecoveryId::from_i32(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as i32)
			.map_err(|_| EcdsaVerifyError::BadV)?;
		let sig = RecoverableSignature::from_compact(&sig[..64], rid)
			.map_err(|_| EcdsaVerifyError::BadRS)?;
		let msg = Message::from_digest_slice(msg).expect("Message is 32 bytes; qed");
		#[cfg(feature = "std")]
		let ctx = secp256k1::SECP256K1;
		#[cfg(not(feature = "std"))]
		let ctx = secp256k1::Secp256k1::<secp256k1::VerifyOnly>::gen_new();
		let pubkey = ctx.recover_ecdsa(&msg, &sig).map_err(|_| EcdsaVerifyError::BadSignature)?;
		Ok(pubkey.serialize())
	}

	/// Generate an `bls12-381` key for the given key type using an optional `seed` and
	/// store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	#[cfg(feature = "bls-experimental")]
	fn bls381_generate(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		seed: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnPointer<bls381::Public, 144> {
		let seed = seed.as_ref().map(|s| core::str::from_utf8(s).expect("Seed is valid utf8!"));
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.bls381_generate_new(id, seed)
			.expect("`bls381_generate` failed")
	}

	/// Generate a 'bls12-381' Proof Of Possession for the corresponding public key.
	///
	/// Returns the Proof Of Possession as an option of the ['bls381::Signature'] type
	/// or 'None' if an error occurs.
	#[cfg(feature = "bls-experimental")]
	fn bls381_generate_proof_of_possession(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		pub_key: PassPointerAndRead<&bls381::Public, 144>,
	) -> AllocateAndReturnByCodec<Option<bls381::Signature>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.bls381_generate_proof_of_possession(id, pub_key)
			.ok()
			.flatten()
	}

	/// Generate combination `ecdsa & bls12-381` key for the given key type using an optional `seed`
	/// and store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	#[cfg(feature = "bls-experimental")]
	fn ecdsa_bls381_generate(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		seed: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnPointer<ecdsa_bls381::Public, { 144 + 33 }> {
		let seed = seed.as_ref().map(|s| core::str::from_utf8(s).expect("Seed is valid utf8!"));
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.ecdsa_bls381_generate_new(id, seed)
			.expect("`ecdsa_bls381_generate` failed")
	}

	/// Generate a `bandersnatch` key pair for the given key type using an optional
	/// `seed` and store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	#[cfg(feature = "bandersnatch-experimental")]
	fn bandersnatch_generate(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		seed: PassFatPointerAndDecode<Option<Vec<u8>>>,
	) -> AllocateAndReturnPointer<bandersnatch::Public, 32> {
		let seed = seed.as_ref().map(|s| core::str::from_utf8(s).expect("Seed is valid utf8!"));
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.bandersnatch_generate_new(id, seed)
			.expect("`bandernatch_generate` failed")
	}

	/// Sign the given `msg` with the `bandersnatch` key that corresponds to the given public key
	/// and key type in the keystore.
	///
	/// Returns the signature or `None` if an error occurred.
	#[cfg(feature = "bandersnatch-experimental")]
	fn bandersnatch_sign(
		&mut self,
		id: PassPointerAndReadCopy<KeyTypeId, 4>,
		pub_key: PassPointerAndRead<&bandersnatch::Public, 32>,
		msg: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<bandersnatch::Signature>> {
		self.extension::<KeystoreExt>()
			.expect("No `keystore` associated for the current context!")
			.bandersnatch_sign(id, pub_key, msg)
			.ok()
			.flatten()
	}
}

/// Interface that provides functions for hashing with different algorithms.
#[runtime_interface]
pub trait Hashing {
	/// Conduct a 256-bit Keccak hash.
	fn keccak_256(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 32], 32> {
		sp_crypto_hashing::keccak_256(data)
	}

	/// Conduct a 512-bit Keccak hash.
	fn keccak_512(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 64], 64> {
		sp_crypto_hashing::keccak_512(data)
	}

	/// Conduct a 256-bit Sha2 hash.
	fn sha2_256(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 32], 32> {
		sp_crypto_hashing::sha2_256(data)
	}

	/// Conduct a 128-bit Blake2 hash.
	fn blake2_128(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 16], 16> {
		sp_crypto_hashing::blake2_128(data)
	}

	/// Conduct a 256-bit Blake2 hash.
	fn blake2_256(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 32], 32> {
		sp_crypto_hashing::blake2_256(data)
	}

	/// Conduct four XX hashes to give a 256-bit result.
	fn twox_256(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 32], 32> {
		sp_crypto_hashing::twox_256(data)
	}

	/// Conduct two XX hashes to give a 128-bit result.
	fn twox_128(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 16], 16> {
		sp_crypto_hashing::twox_128(data)
	}

	/// Conduct two XX hashes to give a 64-bit result.
	fn twox_64(data: PassFatPointerAndRead<&[u8]>) -> AllocateAndReturnPointer<[u8; 8], 8> {
		sp_crypto_hashing::twox_64(data)
	}
}

/// Interface that provides transaction indexing API.
#[runtime_interface]
pub trait TransactionIndex {
	/// Add transaction index. Returns indexed content hash.
	fn index(
		&mut self,
		extrinsic: u32,
		size: u32,
		context_hash: PassPointerAndReadCopy<[u8; 32], 32>,
	) {
		self.storage_index_transaction(extrinsic, &context_hash, size);
	}

	/// Conduct a 512-bit Keccak hash.
	fn renew(&mut self, extrinsic: u32, context_hash: PassPointerAndReadCopy<[u8; 32], 32>) {
		self.storage_renew_transaction_index(extrinsic, &context_hash);
	}
}

/// Interface that provides functions to access the Offchain DB.
#[runtime_interface]
pub trait OffchainIndex {
	/// Write a key value pair to the Offchain DB database in a buffered fashion.
	fn set(&mut self, key: PassFatPointerAndRead<&[u8]>, value: PassFatPointerAndRead<&[u8]>) {
		self.set_offchain_storage(key, Some(value));
	}

	/// Remove a key and its associated value from the Offchain DB.
	fn clear(&mut self, key: PassFatPointerAndRead<&[u8]>) {
		self.set_offchain_storage(key, None);
	}
}

#[cfg(not(substrate_runtime))]
sp_externalities::decl_extension! {
	/// Deprecated verification context.
	///
	/// Stores the combined result of all verifications that are done in the same context.
	struct VerificationExtDeprecated(bool);
}

/// Interface that provides functions to access the offchain functionality.
///
/// These functions are being made available to the runtime and are called by the runtime.
#[runtime_interface]
pub trait Offchain {
	/// Returns if the local node is a potential validator.
	///
	/// Even if this function returns `true`, it does not mean that any keys are configured
	/// and that the validator is registered in the chain.
	fn is_validator(&mut self) -> bool {
		self.extension::<OffchainWorkerExt>()
			.expect("is_validator can be called only in the offchain worker context")
			.is_validator()
	}

	/// Submit an encoded transaction to the pool.
	///
	/// The transaction will end up in the pool.
	fn submit_transaction(
		&mut self,
		data: PassFatPointerAndRead<Vec<u8>>,
	) -> AllocateAndReturnByCodec<Result<(), ()>> {
		self.extension::<TransactionPoolExt>()
			.expect(
				"submit_transaction can be called only in the offchain call context with
				TransactionPool capabilities enabled",
			)
			.submit_transaction(data)
	}

	/// Returns information about the local node's network state.
	fn network_state(&mut self) -> AllocateAndReturnByCodec<Result<OpaqueNetworkState, ()>> {
		self.extension::<OffchainWorkerExt>()
			.expect("network_state can be called only in the offchain worker context")
			.network_state()
	}

	/// Returns current UNIX timestamp (in millis)
	fn timestamp(&mut self) -> ReturnAs<Timestamp, u64> {
		self.extension::<OffchainWorkerExt>()
			.expect("timestamp can be called only in the offchain worker context")
			.timestamp()
	}

	/// Pause the execution until `deadline` is reached.
	fn sleep_until(&mut self, deadline: PassAs<Timestamp, u64>) {
		self.extension::<OffchainWorkerExt>()
			.expect("sleep_until can be called only in the offchain worker context")
			.sleep_until(deadline)
	}

	/// Returns a random seed.
	///
	/// This is a truly random, non-deterministic seed generated by host environment.
	/// Obviously fine in the off-chain worker context.
	fn random_seed(&mut self) -> AllocateAndReturnPointer<[u8; 32], 32> {
		self.extension::<OffchainWorkerExt>()
			.expect("random_seed can be called only in the offchain worker context")
			.random_seed()
	}

	/// Sets a value in the local storage.
	///
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_set(
		&mut self,
		kind: PassAs<StorageKind, u32>,
		key: PassFatPointerAndRead<&[u8]>,
		value: PassFatPointerAndRead<&[u8]>,
	) {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_set can be called only in the offchain call context with
				OffchainDb extension",
			)
			.local_storage_set(kind, key, value)
	}

	/// Remove a value from the local storage.
	///
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_clear(
		&mut self,
		kind: PassAs<StorageKind, u32>,
		key: PassFatPointerAndRead<&[u8]>,
	) {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_clear can be called only in the offchain call context with
				OffchainDb extension",
			)
			.local_storage_clear(kind, key)
	}

	/// Sets a value in the local storage if it matches current value.
	///
	/// Since multiple offchain workers may be running concurrently, to prevent
	/// data races use CAS to coordinate between them.
	///
	/// Returns `true` if the value has been set, `false` otherwise.
	///
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_compare_and_set(
		&mut self,
		kind: PassAs<StorageKind, u32>,
		key: PassFatPointerAndRead<&[u8]>,
		old_value: PassFatPointerAndDecode<Option<Vec<u8>>>,
		new_value: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_compare_and_set can be called only in the offchain call context
				with OffchainDb extension",
			)
			.local_storage_compare_and_set(kind, key, old_value.as_deref(), new_value)
	}

	/// Gets a value from the local storage.
	///
	/// If the value does not exist in the storage `None` will be returned.
	/// Note this storage is not part of the consensus, it's only accessible by
	/// offchain worker tasks running on the same machine. It IS persisted between runs.
	fn local_storage_get(
		&mut self,
		kind: PassAs<StorageKind, u32>,
		key: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
		self.extension::<OffchainDbExt>()
			.expect(
				"local_storage_get can be called only in the offchain call context with
				OffchainDb extension",
			)
			.local_storage_get(kind, key)
	}

	/// Initiates a http request given HTTP verb and the URL.
	///
	/// Meta is a future-reserved field containing additional, parity-scale-codec encoded
	/// parameters. Returns the id of newly started request.
	fn http_request_start(
		&mut self,
		method: PassFatPointerAndRead<&str>,
		uri: PassFatPointerAndRead<&str>,
		meta: PassFatPointerAndRead<&[u8]>,
	) -> AllocateAndReturnByCodec<Result<HttpRequestId, ()>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_start can be called only in the offchain worker context")
			.http_request_start(method, uri, meta)
	}

	/// Append header to the request.
	fn http_request_add_header(
		&mut self,
		request_id: PassAs<HttpRequestId, u16>,
		name: PassFatPointerAndRead<&str>,
		value: PassFatPointerAndRead<&str>,
	) -> AllocateAndReturnByCodec<Result<(), ()>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_add_header can be called only in the offchain worker context")
			.http_request_add_header(request_id, name, value)
	}

	/// Write a chunk of request body.
	///
	/// Writing an empty chunks finalizes the request.
	/// Passing `None` as deadline blocks forever.
	///
	/// Returns an error in case deadline is reached or the chunk couldn't be written.
	fn http_request_write_body(
		&mut self,
		request_id: PassAs<HttpRequestId, u16>,
		chunk: PassFatPointerAndRead<&[u8]>,
		deadline: PassFatPointerAndDecode<Option<Timestamp>>,
	) -> AllocateAndReturnByCodec<Result<(), HttpError>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_request_write_body can be called only in the offchain worker context")
			.http_request_write_body(request_id, chunk, deadline)
	}

	/// Block and wait for the responses for given requests.
	///
	/// Returns a vector of request statuses (the len is the same as ids).
	/// Note that if deadline is not provided the method will block indefinitely,
	/// otherwise unready responses will produce `DeadlineReached` status.
	///
	/// Passing `None` as deadline blocks forever.
	fn http_response_wait(
		&mut self,
		ids: PassFatPointerAndDecodeSlice<&[HttpRequestId]>,
		deadline: PassFatPointerAndDecode<Option<Timestamp>>,
	) -> AllocateAndReturnByCodec<Vec<HttpRequestStatus>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_response_wait can be called only in the offchain worker context")
			.http_response_wait(ids, deadline)
	}

	/// Read all response headers.
	///
	/// Returns a vector of pairs `(HeaderKey, HeaderValue)`.
	/// NOTE: response headers have to be read before response body.
	fn http_response_headers(
		&mut self,
		request_id: PassAs<HttpRequestId, u16>,
	) -> AllocateAndReturnByCodec<Vec<(Vec<u8>, Vec<u8>)>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_response_headers can be called only in the offchain worker context")
			.http_response_headers(request_id)
	}

	/// Read a chunk of body response to given buffer.
	///
	/// Returns the number of bytes written or an error in case a deadline
	/// is reached or server closed the connection.
	/// If `0` is returned it means that the response has been fully consumed
	/// and the `request_id` is now invalid.
	/// NOTE: this implies that response headers must be read before draining the body.
	/// Passing `None` as a deadline blocks forever.
	fn http_response_read_body(
		&mut self,
		request_id: PassAs<HttpRequestId, u16>,
		buffer: PassFatPointerAndReadWrite<&mut [u8]>,
		deadline: PassFatPointerAndDecode<Option<Timestamp>>,
	) -> AllocateAndReturnByCodec<Result<u32, HttpError>> {
		self.extension::<OffchainWorkerExt>()
			.expect("http_response_read_body can be called only in the offchain worker context")
			.http_response_read_body(request_id, buffer, deadline)
			.map(|r| r as u32)
	}

	/// Set the authorized nodes and authorized_only flag.
	fn set_authorized_nodes(
		&mut self,
		nodes: PassFatPointerAndDecode<Vec<OpaquePeerId>>,
		authorized_only: bool,
	) {
		self.extension::<OffchainWorkerExt>()
			.expect("set_authorized_nodes can be called only in the offchain worker context")
			.set_authorized_nodes(nodes, authorized_only)
	}
}

/// Wasm only interface that provides functions for calling into the allocator.
#[runtime_interface(wasm_only)]
pub trait Allocator {
	/// Malloc the given number of bytes and return the pointer to the allocated memory location.
	fn malloc(&mut self, size: u32) -> Pointer<u8> {
		self.allocate_memory(size).expect("Failed to allocate memory")
	}

	/// Free the given pointer.
	fn free(&mut self, ptr: Pointer<u8>) {
		self.deallocate_memory(ptr).expect("Failed to deallocate memory")
	}
}

/// WASM-only interface which allows for aborting the execution in case
/// of an unrecoverable error.
#[runtime_interface(wasm_only)]
pub trait PanicHandler {
	/// Aborts the current execution with the given error message.
	#[trap_on_return]
	fn abort_on_panic(&mut self, message: PassFatPointerAndRead<&str>) {
		self.register_panic_error_message(message);
	}
}

/// Interface that provides functions for logging from within the runtime.
#[runtime_interface]
pub trait Logging {
	/// Request to print a log message on the host.
	///
	/// Note that this will be only displayed if the host is enabled to display log messages with
	/// given level and target.
	///
	/// Instead of using directly, prefer setting up `RuntimeLogger` and using `log` macros.
	fn log(
		level: PassAs<RuntimeInterfaceLogLevel, u8>,
		target: PassFatPointerAndRead<&str>,
		message: PassFatPointerAndRead<&[u8]>,
	) {
		if let Ok(message) = core::str::from_utf8(message) {
			log::log!(target: target, log::Level::from(level), "{}", message)
		}
	}

	/// Returns the max log level used by the host.
	fn max_level() -> ReturnAs<LogLevelFilter, u8> {
		log::max_level().into()
	}
}

/// Interface to provide tracing facilities for wasm. Modelled after tokios `tracing`-crate
/// interfaces. See `sp-tracing` for more information.
#[runtime_interface(wasm_only, no_tracing)]
pub trait WasmTracing {
	/// Whether the span described in `WasmMetadata` should be traced wasm-side
	/// On the host converts into a static Metadata and checks against the global `tracing`
	/// dispatcher.
	///
	/// When returning false the calling code should skip any tracing-related execution. In general
	/// within the same block execution this is not expected to change and it doesn't have to be
	/// checked more than once per metadata. This exists for optimisation purposes but is still not
	/// cheap as it will jump the wasm-native-barrier every time it is called. So an implementation
	/// might chose to cache the result for the execution of the entire block.
	fn enabled(&mut self, metadata: PassFatPointerAndDecode<sp_tracing::WasmMetadata>) -> bool {
		let metadata: &tracing_core::metadata::Metadata<'static> = (&metadata).into();
		tracing::dispatcher::get_default(|d| d.enabled(metadata))
	}

	/// Open a new span with the given attributes. Return the u64 Id of the span.
	///
	/// On the native side this goes through the default `tracing` dispatcher to register the span
	/// and then calls `clone_span` with the ID to signal that we are keeping it around on the wasm-
	/// side even after the local span is dropped. The resulting ID is then handed over to the wasm-
	/// side.
	fn enter_span(
		&mut self,
		span: PassFatPointerAndDecode<sp_tracing::WasmEntryAttributes>,
	) -> u64 {
		let span: tracing::Span = span.into();
		match span.id() {
			Some(id) => tracing::dispatcher::get_default(|d| {
				// inform dispatch that we'll keep the ID around
				// then enter it immediately
				let final_id = d.clone_span(&id);
				d.enter(&final_id);
				final_id.into_u64()
			}),
			_ => 0,
		}
	}

	/// Emit the given event to the global tracer on the native side
	fn event(&mut self, event: PassFatPointerAndDecode<sp_tracing::WasmEntryAttributes>) {
		event.emit();
	}

	/// Signal that a given span-id has been exited. On native, this directly
	/// proxies the span to the global dispatcher.
	fn exit(&mut self, span: u64) {
		tracing::dispatcher::get_default(|d| {
			let id = tracing_core::span::Id::from_u64(span);
			d.exit(&id);
		});
	}
}

#[cfg(all(substrate_runtime, feature = "with-tracing"))]
mod tracing_setup {
	use super::wasm_tracing;
	use core::sync::atomic::{AtomicBool, Ordering};
	use tracing_core::{
		dispatcher::{set_global_default, Dispatch},
		span::{Attributes, Id, Record},
		Event, Metadata,
	};

	static TRACING_SET: AtomicBool = AtomicBool::new(false);

	/// The PassingTracingSubscriber implements `tracing_core::Subscriber`
	/// and pushes the information across the runtime interface to the host
	struct PassingTracingSubscriber;

	impl tracing_core::Subscriber for PassingTracingSubscriber {
		fn enabled(&self, metadata: &Metadata<'_>) -> bool {
			wasm_tracing::enabled(metadata.into())
		}
		fn new_span(&self, attrs: &Attributes<'_>) -> Id {
			Id::from_u64(wasm_tracing::enter_span(attrs.into()))
		}
		fn enter(&self, _: &Id) {
			// Do nothing, we already entered the span previously
		}
		/// Not implemented! We do not support recording values later
		/// Will panic when used.
		fn record(&self, _: &Id, _: &Record<'_>) {
			unimplemented! {} // this usage is not supported
		}
		/// Not implemented! We do not support recording values later
		/// Will panic when used.
		fn record_follows_from(&self, _: &Id, _: &Id) {
			unimplemented! {} // this usage is not supported
		}
		fn event(&self, event: &Event<'_>) {
			wasm_tracing::event(event.into())
		}
		fn exit(&self, span: &Id) {
			wasm_tracing::exit(span.into_u64())
		}
	}

	/// Initialize tracing of sp_tracing on wasm with `with-tracing` enabled.
	/// Can be called multiple times from within the same process and will only
	/// set the global bridging subscriber once.
	pub fn init_tracing() {
		if TRACING_SET.load(Ordering::Relaxed) == false {
			set_global_default(Dispatch::new(PassingTracingSubscriber {}))
				.expect("We only ever call this once");
			TRACING_SET.store(true, Ordering::Relaxed);
		}
	}
}

#[cfg(not(all(substrate_runtime, feature = "with-tracing")))]
mod tracing_setup {
	/// Initialize tracing of sp_tracing not necessary – noop. To enable build
	/// when not both `substrate_runtime` and `with-tracing`-feature.
	pub fn init_tracing() {}
}

pub use tracing_setup::init_tracing;

/// Crashes the execution of the program.
///
/// Equivalent to the WASM `unreachable` instruction, RISC-V `unimp` instruction,
/// or just the `unreachable!()` macro everywhere else.
pub fn unreachable() -> ! {
	#[cfg(target_family = "wasm")]
	{
		core::arch::wasm32::unreachable();
	}

	#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
	unsafe {
		core::arch::asm!("unimp", options(noreturn));
	}

	#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64", target_family = "wasm")))]
	unreachable!();
}

/// A default panic handler for the runtime environment.
#[cfg(all(not(feature = "disable_panic_handler"), substrate_runtime))]
#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
	let message = alloc::format!("{}", info);
	#[cfg(feature = "improved_panic_error_reporting")]
	{
		panic_handler::abort_on_panic(&message);
	}
	#[cfg(not(feature = "improved_panic_error_reporting"))]
	{
		logging::log(RuntimeInterfaceLogLevel::Error, "runtime", message.as_bytes());
		unreachable();
	}
}

/// A default OOM handler for the runtime environment.
#[cfg(all(not(feature = "disable_oom"), enable_alloc_error_handler))]
#[alloc_error_handler]
pub fn oom(_: core::alloc::Layout) -> ! {
	#[cfg(feature = "improved_panic_error_reporting")]
	{
		panic_handler::abort_on_panic("Runtime memory exhausted.");
	}
	#[cfg(not(feature = "improved_panic_error_reporting"))]
	{
		logging::log(
			RuntimeInterfaceLogLevel::Error,
			"runtime",
			b"Runtime memory exhausted. Aborting",
		);
		unreachable();
	}
}

/// Type alias for Externalities implementation used in tests.
#[cfg(feature = "std")] // NOTE: Deliberately isn't `not(substrate_runtime)`.
pub type TestExternalities = sp_state_machine::TestExternalities<sp_core::Blake2Hasher>;

/// The host functions Substrate provides for the Wasm runtime environment.
///
/// All these host functions will be callable from inside the Wasm environment.
#[docify::export]
#[cfg(not(substrate_runtime))]
pub type SubstrateHostFunctions = (
	storage::HostFunctions,
	default_child_storage::HostFunctions,
	misc::HostFunctions,
	wasm_tracing::HostFunctions,
	offchain::HostFunctions,
	crypto::HostFunctions,
	hashing::HostFunctions,
	allocator::HostFunctions,
	panic_handler::HostFunctions,
	logging::HostFunctions,
	crate::trie::HostFunctions,
	offchain_index::HostFunctions,
	transaction_index::HostFunctions,
);

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::{crypto::UncheckedInto, map, storage::Storage};
	use sp_state_machine::BasicExternalities;

	#[test]
	fn storage_works() {
		let mut t = BasicExternalities::default();
		t.execute_with(|| {
			assert_eq!(storage::get(b"hello"), None);
			storage::set(b"hello", b"world");
			assert_eq!(storage::get(b"hello"), Some(b"world".to_vec().into()));
			assert_eq!(storage::get(b"foo"), None);
			storage::set(b"foo", &[1, 2, 3][..]);
		});

		t = BasicExternalities::new(Storage {
			top: map![b"foo".to_vec() => b"bar".to_vec()],
			children_default: map![],
		});

		t.execute_with(|| {
			assert_eq!(storage::get(b"hello"), None);
			assert_eq!(storage::get(b"foo"), Some(b"bar".to_vec().into()));
		});

		let value = vec![7u8; 35];
		let storage =
			Storage { top: map![b"foo00".to_vec() => value.clone()], children_default: map![] };
		t = BasicExternalities::new(storage);

		t.execute_with(|| {
			assert_eq!(storage::get(b"hello"), None);
			assert_eq!(storage::get(b"foo00"), Some(value.clone().into()));
		});
	}

	#[test]
	fn read_storage_works() {
		let value = b"\x0b\0\0\0Hello world".to_vec();
		let mut t = BasicExternalities::new(Storage {
			top: map![b":test".to_vec() => value.clone()],
			children_default: map![],
		});

		t.execute_with(|| {
			let mut v = [0u8; 4];
			assert_eq!(storage::read(b":test", &mut v[..], 0).unwrap(), value.len() as u32);
			assert_eq!(v, [11u8, 0, 0, 0]);
			let mut w = [0u8; 11];
			assert_eq!(storage::read(b":test", &mut w[..], 4).unwrap(), value.len() as u32 - 4);
			assert_eq!(&w, b"Hello world");
		});
	}

	#[test]
	fn clear_prefix_works() {
		let mut t = BasicExternalities::new(Storage {
			top: map![
				b":a".to_vec() => b"\x0b\0\0\0Hello world".to_vec(),
				b":abcd".to_vec() => b"\x0b\0\0\0Hello world".to_vec(),
				b":abc".to_vec() => b"\x0b\0\0\0Hello world".to_vec(),
				b":abdd".to_vec() => b"\x0b\0\0\0Hello world".to_vec()
			],
			children_default: map![],
		});

		t.execute_with(|| {
			// We can switch to this once we enable v3 of the `clear_prefix`.
			//assert!(matches!(
			//	storage::clear_prefix(b":abc", None),
			//	MultiRemovalResults::NoneLeft { db: 2, total: 2 }
			//));
			assert!(matches!(
				storage::clear_prefix(b":abc", None),
				KillStorageResult::AllRemoved(2),
			));

			assert!(storage::get(b":a").is_some());
			assert!(storage::get(b":abdd").is_some());
			assert!(storage::get(b":abcd").is_none());
			assert!(storage::get(b":abc").is_none());

			// We can switch to this once we enable v3 of the `clear_prefix`.
			//assert!(matches!(
			//	storage::clear_prefix(b":abc", None),
			//	MultiRemovalResults::NoneLeft { db: 0, total: 0 }
			//));
			assert!(matches!(
				storage::clear_prefix(b":abc", None),
				KillStorageResult::AllRemoved(0),
			));
		});
	}

	fn zero_ed_pub() -> ed25519::Public {
		[0u8; 32].unchecked_into()
	}

	fn zero_ed_sig() -> ed25519::Signature {
		ed25519::Signature::from_raw([0u8; 64])
	}

	#[test]
	fn use_dalek_ext_works() {
		let mut ext = BasicExternalities::default();
		ext.register_extension(UseDalekExt::default());

		// With dalek the zero signature should fail to verify.
		ext.execute_with(|| {
			assert!(!crypto::ed25519_verify(&zero_ed_sig(), &Vec::new(), &zero_ed_pub()));
		});

		// But with zebra it should work.
		BasicExternalities::default().execute_with(|| {
			assert!(crypto::ed25519_verify(&zero_ed_sig(), &Vec::new(), &zero_ed_pub()));
		})
	}

	#[test]
	fn dalek_should_not_panic_on_invalid_signature() {
		let mut ext = BasicExternalities::default();
		ext.register_extension(UseDalekExt::default());

		ext.execute_with(|| {
			let mut bytes = [0u8; 64];
			// Make it invalid
			bytes[63] = 0b1110_0000;

			assert!(!crypto::ed25519_verify(
				&ed25519::Signature::from_raw(bytes),
				&Vec::new(),
				&zero_ed_pub()
			));
		});
	}
}
