// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

pub use sp_crypto_hashing::blake2_256;

pub fn hash_to_cid(hash: &[u8; 32]) -> String {
	use cid::Cid;
	use multihash::Multihash;
	const BLAKE2B_256: u64 = 0xb220;
	const RAW_CODEC: u64 = 0x55;
	let mh = Multihash::<64>::wrap(BLAKE2B_256, hash).expect("Valid multihash");
	Cid::new_v1(RAW_CODEC, mh).to_string()
}

pub fn generate_test_data(size: usize, pattern: &[u8]) -> Vec<u8> {
	let mut data = Vec::with_capacity(size);
	while data.len() < size {
		let remaining = size - data.len();
		if remaining >= pattern.len() {
			data.extend_from_slice(pattern);
		} else {
			data.extend_from_slice(&pattern[..remaining]);
		}
	}
	data
}
