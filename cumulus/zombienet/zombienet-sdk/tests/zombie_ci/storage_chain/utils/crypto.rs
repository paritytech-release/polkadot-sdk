// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashingAlgorithm {
	Blake2b256,
	Sha2_256,
	Keccak256,
}

impl HashingAlgorithm {
	pub fn hash(&self, data: &[u8]) -> [u8; 32] {
		match self {
			Self::Blake2b256 => blake2_256(data),
			Self::Sha2_256 => sha2_256(data),
			Self::Keccak256 => keccak_256(data),
		}
	}

	pub const fn multihash_code(&self) -> u64 {
		match self {
			Self::Blake2b256 => 0xb220,
			Self::Sha2_256 => 0x12,
			Self::Keccak256 => 0x1b,
		}
	}
}

pub use sp_crypto_hashing::{blake2_256, keccak_256, sha2_256};

pub fn hash_to_cid(hash: &[u8; 32], algo: HashingAlgorithm) -> String {
	use cid::Cid;
	use multihash::Multihash;
	const RAW_CODEC: u64 = 0x55;
	let mh = Multihash::<64>::wrap(algo.multihash_code(), hash).expect("Valid multihash");
	Cid::new_v1(RAW_CODEC, mh).to_string()
}


