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

//! Simple sr25519 (Schnorr-Ristretto) API.
//!
//! Note: `CHAIN_CODE_LENGTH` must be equal to `crate::crypto::JUNCTION_ID_LEN`
//! for this to work.

#[cfg(feature = "serde")]
use crate::crypto::Ss58Codec;
use crate::{
	crypto::{CryptoBytes, DeriveError, DeriveJunction, Pair as TraitPair, SecretStringError},
	proof_of_possession::NonAggregatable,
};

use alloc::vec::Vec;
#[cfg(feature = "full_crypto")]
use schnorrkel::signing_context;
use schnorrkel::{
	derive::{ChainCode, Derivation, CHAIN_CODE_LENGTH},
	ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey,
};

use crate::crypto::{CryptoType, CryptoTypeId, Derive, Public as TraitPublic, SignatureBytes};
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(all(not(feature = "std"), feature = "serde"))]
use alloc::{format, string::String};
use schnorrkel::keys::{MINI_SECRET_KEY_LENGTH, SECRET_KEY_LENGTH};
#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

// signing context
const SIGNING_CTX: &[u8] = b"substrate";

/// An identifier used to match public keys against sr25519 keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"sr25");

/// The byte length of public key
pub const PUBLIC_KEY_SERIALIZED_SIZE: usize = 32;

/// The byte length of signature
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;

#[doc(hidden)]
pub struct Sr25519Tag;
#[doc(hidden)]
pub struct Sr25519PublicTag;

/// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
pub type Public = CryptoBytes<PUBLIC_KEY_SERIALIZED_SIZE, Sr25519PublicTag>;

impl TraitPublic for Public {}

impl Derive for Public {
	/// Derive a child key from a series of given junctions.
	///
	/// `None` if there are any hard junctions in there.
	#[cfg(feature = "serde")]
	fn derive<Iter: Iterator<Item = DeriveJunction>>(&self, path: Iter) -> Option<Public> {
		let mut acc = PublicKey::from_bytes(self.as_ref()).ok()?;
		for j in path {
			match j {
				DeriveJunction::Soft(cc) => acc = acc.derived_key_simple(ChainCode(cc), &[]).0,
				DeriveJunction::Hard(_cc) => return None,
			}
		}
		Some(Self::from(acc.to_bytes()))
	}
}

#[cfg(feature = "std")]
impl std::str::FromStr for Public {
	type Err = crate::crypto::PublicError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_ss58check(s)
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for Public {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.to_ss58check())
	}
}

impl core::fmt::Debug for Public {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		let s = self.to_ss58check();
		write!(f, "{} ({}...)", crate::hexdisplay::HexDisplay::from(&self.0), &s[0..8])
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
		Ok(())
	}
}

#[cfg(feature = "serde")]
impl Serialize for Public {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_ss58check())
	}
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Public {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		Public::from_ss58check(&String::deserialize(deserializer)?)
			.map_err(|e| de::Error::custom(format!("{:?}", e)))
	}
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") signature.
pub type Signature = SignatureBytes<SIGNATURE_SERIALIZED_SIZE, Sr25519Tag>;

#[cfg(feature = "full_crypto")]
impl From<schnorrkel::Signature> for Signature {
	fn from(s: schnorrkel::Signature) -> Signature {
		Signature::from(s.to_bytes())
	}
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") key pair.
pub struct Pair(Keypair);

impl Clone for Pair {
	fn clone(&self) -> Self {
		Pair(schnorrkel::Keypair {
			public: self.0.public,
			secret: schnorrkel::SecretKey::from_bytes(&self.0.secret.to_bytes()[..])
				.expect("key is always the correct size; qed"),
		})
	}
}

#[cfg(feature = "std")]
impl From<MiniSecretKey> for Pair {
	fn from(sec: MiniSecretKey) -> Pair {
		Pair(sec.expand_to_keypair(ExpansionMode::Ed25519))
	}
}

#[cfg(feature = "std")]
impl From<SecretKey> for Pair {
	fn from(sec: SecretKey) -> Pair {
		Pair(Keypair::from(sec))
	}
}

#[cfg(feature = "full_crypto")]
impl From<schnorrkel::Keypair> for Pair {
	fn from(p: schnorrkel::Keypair) -> Pair {
		Pair(p)
	}
}

#[cfg(feature = "full_crypto")]
impl From<Pair> for schnorrkel::Keypair {
	fn from(p: Pair) -> schnorrkel::Keypair {
		p.0
	}
}

#[cfg(feature = "full_crypto")]
impl AsRef<schnorrkel::Keypair> for Pair {
	fn as_ref(&self) -> &schnorrkel::Keypair {
		&self.0
	}
}

/// Derive a single hard junction.
fn derive_hard_junction(secret: &SecretKey, cc: &[u8; CHAIN_CODE_LENGTH]) -> MiniSecretKey {
	secret.hard_derive_mini_secret_key(Some(ChainCode(*cc)), b"").0
}

/// The raw secret seed, which can be used to recreate the `Pair`.
type Seed = [u8; MINI_SECRET_KEY_LENGTH];

impl TraitPair for Pair {
	type Public = Public;
	type Seed = Seed;
	type Signature = Signature;

	/// Get the public key.
	fn public(&self) -> Public {
		Public::from(self.0.public.to_bytes())
	}

	/// Make a new key pair from raw secret seed material.
	///
	/// This is generated using schnorrkel's Mini-Secret-Keys.
	///
	/// A `MiniSecretKey` is literally what Ed25519 calls a `SecretKey`, which is just 32 random
	/// bytes.
	fn from_seed_slice(seed: &[u8]) -> Result<Pair, SecretStringError> {
		match seed.len() {
			MINI_SECRET_KEY_LENGTH => Ok(Pair(
				MiniSecretKey::from_bytes(seed)
					.map_err(|_| SecretStringError::InvalidSeed)?
					.expand_to_keypair(ExpansionMode::Ed25519),
			)),
			SECRET_KEY_LENGTH => Ok(Pair(
				SecretKey::from_bytes(seed)
					.map_err(|_| SecretStringError::InvalidSeed)?
					.to_keypair(),
			)),
			_ => Err(SecretStringError::InvalidSeedLength),
		}
	}

	fn derive<Iter: Iterator<Item = DeriveJunction>>(
		&self,
		path: Iter,
		seed: Option<Seed>,
	) -> Result<(Pair, Option<Seed>), DeriveError> {
		let seed = seed
			.and_then(|s| MiniSecretKey::from_bytes(&s).ok())
			.filter(|msk| msk.expand(ExpansionMode::Ed25519) == self.0.secret);

		let init = self.0.secret.clone();
		let (result, seed) = path.fold((init, seed), |(acc, acc_seed), j| match (j, acc_seed) {
			(DeriveJunction::Soft(cc), _) => (acc.derived_key_simple(ChainCode(cc), &[]).0, None),
			(DeriveJunction::Hard(cc), maybe_seed) => {
				let seed = derive_hard_junction(&acc, &cc);
				(seed.expand(ExpansionMode::Ed25519), maybe_seed.map(|_| seed))
			},
		});
		Ok((Self(result.into()), seed.map(|s| MiniSecretKey::to_bytes(&s))))
	}

	#[cfg(feature = "full_crypto")]
	fn sign(&self, message: &[u8]) -> Signature {
		let context = signing_context(SIGNING_CTX);
		self.0.sign(context.bytes(message)).into()
	}

	fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
		let Ok(signature) = schnorrkel::Signature::from_bytes(sig.as_ref()) else { return false };
		let Ok(public) = PublicKey::from_bytes(pubkey.as_ref()) else { return false };
		public.verify_simple(SIGNING_CTX, message.as_ref(), &signature).is_ok()
	}

	fn to_raw_vec(&self) -> Vec<u8> {
		self.0.secret.to_bytes().to_vec()
	}
}

#[cfg(not(substrate_runtime))]
impl Pair {
	/// Verify a signature on a message. Returns `true` if the signature is good.
	/// Supports old 0.1.1 deprecated signatures and should be used only for backward
	/// compatibility.
	pub fn verify_deprecated<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
		// Match both schnorrkel 0.1.1 and 0.8.0+ signatures, supporting both wallets
		// that have not been upgraded and those that have.
		match PublicKey::from_bytes(pubkey.as_ref()) {
			Ok(pk) => pk
				.verify_simple_preaudit_deprecated(SIGNING_CTX, message.as_ref(), &sig.0[..])
				.is_ok(),
			Err(_) => false,
		}
	}
}

impl CryptoType for Public {
	type Pair = Pair;
}

impl CryptoType for Signature {
	type Pair = Pair;
}

impl CryptoType for Pair {
	type Pair = Pair;
}

impl NonAggregatable for Pair {}

/// Schnorrkel VRF related types and operations.
pub mod vrf {
	use super::*;
	#[cfg(feature = "full_crypto")]
	use crate::crypto::VrfSecret;
	use crate::crypto::{VrfCrypto, VrfPublic};
	use schnorrkel::{
		errors::MultiSignatureStage,
		vrf::{VRF_PREOUT_LENGTH, VRF_PROOF_LENGTH},
		SignatureError,
	};

	const DEFAULT_EXTRA_DATA_LABEL: &[u8] = b"VRF";

	/// Transcript ready to be used for VRF related operations.
	#[derive(Clone)]
	pub struct VrfTranscript(pub merlin::Transcript);

	impl VrfTranscript {
		/// Build a new transcript instance.
		///
		/// Each `data` element is a tuple `(domain, message)` used to build the transcript.
		pub fn new(label: &'static [u8], data: &[(&'static [u8], &[u8])]) -> Self {
			let mut transcript = merlin::Transcript::new(label);
			data.iter().for_each(|(l, b)| transcript.append_message(l, b));
			VrfTranscript(transcript)
		}

		/// Map transcript to `VrfSignData`.
		pub fn into_sign_data(self) -> VrfSignData {
			self.into()
		}
	}

	/// VRF input.
	///
	/// Technically a transcript used by the Fiat-Shamir transform.
	pub type VrfInput = VrfTranscript;

	/// VRF input ready to be used for VRF sign and verify operations.
	#[derive(Clone)]
	pub struct VrfSignData {
		/// Transcript data contributing to VRF output.
		pub(super) transcript: VrfTranscript,
		/// Extra transcript data to be signed by the VRF.
		pub(super) extra: Option<VrfTranscript>,
	}

	impl From<VrfInput> for VrfSignData {
		fn from(transcript: VrfInput) -> Self {
			VrfSignData { transcript, extra: None }
		}
	}

	// Get a reference to the inner VRF input.
	impl AsRef<VrfInput> for VrfSignData {
		fn as_ref(&self) -> &VrfInput {
			&self.transcript
		}
	}

	impl VrfSignData {
		/// Build a new instance ready to be used for VRF signer and verifier.
		///
		/// `input` will contribute to the VRF output bytes.
		pub fn new(input: VrfTranscript) -> Self {
			input.into()
		}

		/// Add some extra data to be signed.
		///
		/// `extra` will not contribute to the VRF output bytes.
		pub fn with_extra(mut self, extra: VrfTranscript) -> Self {
			self.extra = Some(extra);
			self
		}
	}

	/// VRF signature data
	#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
	pub struct VrfSignature {
		/// VRF pre-output.
		pub pre_output: VrfPreOutput,
		/// VRF proof.
		pub proof: VrfProof,
	}

	/// VRF pre-output type suitable for schnorrkel operations.
	#[derive(Clone, Debug, PartialEq, Eq)]
	pub struct VrfPreOutput(pub schnorrkel::vrf::VRFPreOut);

	impl Encode for VrfPreOutput {
		fn encode(&self) -> Vec<u8> {
			self.0.as_bytes().encode()
		}
	}

	impl Decode for VrfPreOutput {
		fn decode<R: codec::Input>(i: &mut R) -> Result<Self, codec::Error> {
			let decoded = <[u8; VRF_PREOUT_LENGTH]>::decode(i)?;
			Ok(Self(schnorrkel::vrf::VRFPreOut::from_bytes(&decoded).map_err(convert_error)?))
		}
	}

	impl MaxEncodedLen for VrfPreOutput {
		fn max_encoded_len() -> usize {
			<[u8; VRF_PREOUT_LENGTH]>::max_encoded_len()
		}
	}

	impl TypeInfo for VrfPreOutput {
		type Identity = [u8; VRF_PREOUT_LENGTH];

		fn type_info() -> scale_info::Type {
			Self::Identity::type_info()
		}
	}

	/// VRF proof type suitable for schnorrkel operations.
	#[derive(Clone, Debug, PartialEq, Eq)]
	pub struct VrfProof(pub schnorrkel::vrf::VRFProof);

	impl Encode for VrfProof {
		fn encode(&self) -> Vec<u8> {
			self.0.to_bytes().encode()
		}
	}

	impl Decode for VrfProof {
		fn decode<R: codec::Input>(i: &mut R) -> Result<Self, codec::Error> {
			let decoded = <[u8; VRF_PROOF_LENGTH]>::decode(i)?;
			Ok(Self(schnorrkel::vrf::VRFProof::from_bytes(&decoded).map_err(convert_error)?))
		}
	}

	impl MaxEncodedLen for VrfProof {
		fn max_encoded_len() -> usize {
			<[u8; VRF_PROOF_LENGTH]>::max_encoded_len()
		}
	}

	impl TypeInfo for VrfProof {
		type Identity = [u8; VRF_PROOF_LENGTH];

		fn type_info() -> scale_info::Type {
			Self::Identity::type_info()
		}
	}

	#[cfg(feature = "full_crypto")]
	impl VrfCrypto for Pair {
		type VrfInput = VrfTranscript;
		type VrfPreOutput = VrfPreOutput;
		type VrfSignData = VrfSignData;
		type VrfSignature = VrfSignature;
	}

	#[cfg(feature = "full_crypto")]
	impl VrfSecret for Pair {
		fn vrf_sign(&self, data: &Self::VrfSignData) -> Self::VrfSignature {
			let inout = self.0.vrf_create_hash(data.transcript.0.clone());

			let extra = data
				.extra
				.as_ref()
				.map(|e| e.0.clone())
				.unwrap_or_else(|| merlin::Transcript::new(DEFAULT_EXTRA_DATA_LABEL));

			let proof = self.0.dleq_proove(extra, &inout, true).0;

			VrfSignature { pre_output: VrfPreOutput(inout.to_preout()), proof: VrfProof(proof) }
		}

		fn vrf_pre_output(&self, input: &Self::VrfInput) -> Self::VrfPreOutput {
			let pre_output = self.0.vrf_create_hash(input.0.clone()).to_preout();
			VrfPreOutput(pre_output)
		}
	}

	impl VrfCrypto for Public {
		type VrfInput = VrfTranscript;
		type VrfPreOutput = VrfPreOutput;
		type VrfSignData = VrfSignData;
		type VrfSignature = VrfSignature;
	}

	impl VrfPublic for Public {
		fn vrf_verify(&self, data: &Self::VrfSignData, signature: &Self::VrfSignature) -> bool {
			let do_verify = || {
				let public = schnorrkel::PublicKey::from_bytes(&self.0)?;

				let inout =
					signature.pre_output.0.attach_input_hash(&public, data.transcript.0.clone())?;

				let extra = data
					.extra
					.as_ref()
					.map(|e| e.0.clone())
					.unwrap_or_else(|| merlin::Transcript::new(DEFAULT_EXTRA_DATA_LABEL));

				public.dleq_verify(extra, &inout, &signature.proof.0, true)
			};
			do_verify().is_ok()
		}
	}

	fn convert_error(e: SignatureError) -> codec::Error {
		use MultiSignatureStage::*;
		use SignatureError::*;
		match e {
			EquationFalse => "Signature error: `EquationFalse`".into(),
			PointDecompressionError => "Signature error: `PointDecompressionError`".into(),
			ScalarFormatError => "Signature error: `ScalarFormatError`".into(),
			NotMarkedSchnorrkel => "Signature error: `NotMarkedSchnorrkel`".into(),
			BytesLengthError { .. } => "Signature error: `BytesLengthError`".into(),
			InvalidKey => "Signature error: `InvalidKey`".into(),
			MuSigAbsent { musig_stage: Commitment } =>
				"Signature error: `MuSigAbsent` at stage `Commitment`".into(),
			MuSigAbsent { musig_stage: Reveal } =>
				"Signature error: `MuSigAbsent` at stage `Reveal`".into(),
			MuSigAbsent { musig_stage: Cosignature } =>
				"Signature error: `MuSigAbsent` at stage `Commitment`".into(),
			MuSigInconsistent { musig_stage: Commitment, duplicate: true } =>
				"Signature error: `MuSigInconsistent` at stage `Commitment` on duplicate".into(),
			MuSigInconsistent { musig_stage: Commitment, duplicate: false } =>
				"Signature error: `MuSigInconsistent` at stage `Commitment` on not duplicate".into(),
			MuSigInconsistent { musig_stage: Reveal, duplicate: true } =>
				"Signature error: `MuSigInconsistent` at stage `Reveal` on duplicate".into(),
			MuSigInconsistent { musig_stage: Reveal, duplicate: false } =>
				"Signature error: `MuSigInconsistent` at stage `Reveal` on not duplicate".into(),
			MuSigInconsistent { musig_stage: Cosignature, duplicate: true } =>
				"Signature error: `MuSigInconsistent` at stage `Cosignature` on duplicate".into(),
			MuSigInconsistent { musig_stage: Cosignature, duplicate: false } =>
				"Signature error: `MuSigInconsistent` at stage `Cosignature` on not duplicate"
					.into(),
		}
	}

	#[cfg(feature = "full_crypto")]
	impl Pair {
		/// Generate output bytes from the given VRF configuration.
		pub fn make_bytes<const N: usize>(&self, context: &[u8], input: &VrfInput) -> [u8; N]
		where
			[u8; N]: Default,
		{
			let inout = self.0.vrf_create_hash(input.0.clone());
			inout.make_bytes::<[u8; N]>(context)
		}
	}

	impl Public {
		/// Generate output bytes from the given VRF configuration.
		pub fn make_bytes<const N: usize>(
			&self,
			context: &[u8],
			input: &VrfInput,
			pre_output: &VrfPreOutput,
		) -> Result<[u8; N], codec::Error>
		where
			[u8; N]: Default,
		{
			let pubkey = schnorrkel::PublicKey::from_bytes(&self.0).map_err(convert_error)?;
			let inout = pre_output
				.0
				.attach_input_hash(&pubkey, input.0.clone())
				.map_err(convert_error)?;
			Ok(inout.make_bytes::<[u8; N]>(context))
		}
	}

	impl VrfPreOutput {
		/// Generate output bytes from the given VRF configuration.
		pub fn make_bytes<const N: usize>(
			&self,
			context: &[u8],
			input: &VrfInput,
			public: &Public,
		) -> Result<[u8; N], codec::Error>
		where
			[u8; N]: Default,
		{
			public.make_bytes(context, input, self)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{vrf::*, *};
	use crate::{
		crypto::{Ss58Codec, VrfPublic, VrfSecret, DEV_ADDRESS, DEV_PHRASE},
		proof_of_possession::{ProofOfPossessionGenerator, ProofOfPossessionVerifier},
		ByteArray as _,
	};
	use serde_json;

	#[test]
	fn derive_soft_known_pair_should_work() {
		let pair = Pair::from_string(&format!("{}/Alice", DEV_PHRASE), None).unwrap();
		// known address of DEV_PHRASE with 1.1
		let known = array_bytes::hex2bytes_unchecked(
			"d6c71059dbbe9ad2b0ed3f289738b800836eb425544ce694825285b958ca755e",
		);
		assert_eq!(pair.public().to_raw_vec(), known);
	}

	#[test]
	fn derive_hard_known_pair_should_work() {
		let pair = Pair::from_string(&format!("{}//Alice", DEV_PHRASE), None).unwrap();
		// known address of DEV_PHRASE with 1.1
		let known = array_bytes::hex2bytes_unchecked(
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
		);
		assert_eq!(pair.public().to_raw_vec(), known);
	}

	#[test]
	fn verify_known_old_message_should_work() {
		let public = Public::from_raw(array_bytes::hex2array_unchecked(
			"b4bfa1f7a5166695eb75299fd1c4c03ea212871c342f2c5dfea0902b2c246918",
		));
		// signature generated by the 1.1 version with the same ^^ public key.
		let signature = Signature::from_raw(array_bytes::hex2array_unchecked(
			"5a9755f069939f45d96aaf125cf5ce7ba1db998686f87f2fb3cbdea922078741a73891ba265f70c31436e18a9acd14d189d73c12317ab6c313285cd938453202"
		));
		let message = b"Verifying that I am the owner of 5G9hQLdsKQswNPgB499DeA5PkFBbgkLPJWkkS6FAM6xGQ8xD. Hash: 221455a3\n";
		assert!(Pair::verify_deprecated(&signature, &message[..], &public));
		assert!(!Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn default_phrase_should_be_used() {
		assert_eq!(
			Pair::from_string("//Alice///password", None).unwrap().public(),
			Pair::from_string(&format!("{}//Alice", DEV_PHRASE), Some("password"))
				.unwrap()
				.public(),
		);
		assert_eq!(
			Pair::from_string(&format!("{}/Alice", DEV_PHRASE), None)
				.as_ref()
				.map(Pair::public),
			Pair::from_string("/Alice", None).as_ref().map(Pair::public)
		);
	}

	#[test]
	fn default_address_should_be_used() {
		assert_eq!(
			Public::from_string(&format!("{}/Alice", DEV_ADDRESS)),
			Public::from_string("/Alice")
		);
	}

	#[test]
	fn default_phrase_should_correspond_to_default_address() {
		assert_eq!(
			Pair::from_string(&format!("{}/Alice", DEV_PHRASE), None).unwrap().public(),
			Public::from_string(&format!("{}/Alice", DEV_ADDRESS)).unwrap(),
		);
		assert_eq!(
			Pair::from_string("/Alice", None).unwrap().public(),
			Public::from_string("/Alice").unwrap()
		);
	}

	#[test]
	fn derive_soft_should_work() {
		let pair = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		));
		let derive_1 = pair.derive(Some(DeriveJunction::soft(1)).into_iter(), None).unwrap().0;
		let derive_1b = pair.derive(Some(DeriveJunction::soft(1)).into_iter(), None).unwrap().0;
		let derive_2 = pair.derive(Some(DeriveJunction::soft(2)).into_iter(), None).unwrap().0;
		assert_eq!(derive_1.public(), derive_1b.public());
		assert_ne!(derive_1.public(), derive_2.public());
	}

	#[test]
	fn derive_hard_should_work() {
		let pair = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		));
		let derive_1 = pair.derive(Some(DeriveJunction::hard(1)).into_iter(), None).unwrap().0;
		let derive_1b = pair.derive(Some(DeriveJunction::hard(1)).into_iter(), None).unwrap().0;
		let derive_2 = pair.derive(Some(DeriveJunction::hard(2)).into_iter(), None).unwrap().0;
		assert_eq!(derive_1.public(), derive_1b.public());
		assert_ne!(derive_1.public(), derive_2.public());
	}

	#[test]
	fn derive_soft_public_should_work() {
		let pair = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		));
		let path = Some(DeriveJunction::soft(1));
		let pair_1 = pair.derive(path.into_iter(), None).unwrap().0;
		let public_1 = pair.public().derive(path.into_iter()).unwrap();
		assert_eq!(pair_1.public(), public_1);
	}

	#[test]
	fn derive_hard_public_should_fail() {
		let pair = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		));
		let path = Some(DeriveJunction::hard(1));
		assert!(pair.public().derive(path.into_iter()).is_none());
	}

	#[test]
	fn sr_test_vector_should_work() {
		let pair = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		));
		let public = pair.public();
		assert_eq!(
			public,
			Public::from_raw(array_bytes::hex2array_unchecked(
				"44a996beb1eef7bdcab976ab6d2ca26104834164ecf28fb375600576fcc6eb0f"
			))
		);
		let message = b"";
		let signature = pair.sign(message);
		assert!(Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn generate_with_phrase_should_be_recoverable_with_from_string() {
		let (pair, phrase, seed) = Pair::generate_with_phrase(None);
		let repair_seed = Pair::from_seed_slice(seed.as_ref()).expect("seed slice is valid");
		assert_eq!(pair.public(), repair_seed.public());
		assert_eq!(pair.to_raw_vec(), repair_seed.to_raw_vec());
		let (repair_phrase, reseed) =
			Pair::from_phrase(phrase.as_ref(), None).expect("seed slice is valid");
		assert_eq!(seed, reseed);
		assert_eq!(pair.public(), repair_phrase.public());
		assert_eq!(pair.to_raw_vec(), repair_seed.to_raw_vec());
		let repair_string = Pair::from_string(phrase.as_str(), None).expect("seed slice is valid");
		assert_eq!(pair.public(), repair_string.public());
		assert_eq!(pair.to_raw_vec(), repair_seed.to_raw_vec());
	}

	#[test]
	fn generated_pair_should_work() {
		let (pair, _) = Pair::generate();
		let public = pair.public();
		let message = b"Something important";
		let signature = pair.sign(&message[..]);
		assert!(Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn messed_signature_should_not_work() {
		let (pair, _) = Pair::generate();
		let public = pair.public();
		let message = b"Signed payload";
		let mut signature = pair.sign(&message[..]);
		let bytes = &mut signature.0;
		bytes[0] = !bytes[0];
		bytes[2] = !bytes[2];
		assert!(!Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn messed_message_should_not_work() {
		let (pair, _) = Pair::generate();
		let public = pair.public();
		let message = b"Something important";
		let signature = pair.sign(&message[..]);
		assert!(!Pair::verify(&signature, &b"Something unimportant", &public));
	}

	#[test]
	fn seeded_pair_should_work() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		assert_eq!(
			public,
			Public::from_raw(array_bytes::hex2array_unchecked(
				"741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"
			))
		);
		let message = array_bytes::hex2bytes_unchecked("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee00000000000000000200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a4500000000000000");
		let signature = pair.sign(&message[..]);
		assert!(Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn ss58check_roundtrip_works() {
		let (pair, _) = Pair::generate();
		let public = pair.public();
		let s = public.to_ss58check();
		println!("Correct: {}", s);
		let cmp = Public::from_ss58check(&s).unwrap();
		assert_eq!(cmp, public);
	}

	#[test]
	fn verify_from_old_wasm_works() {
		// The values in this test case are compared to the output of `node-test.js` in
		// schnorrkel-js.
		//
		// This is to make sure that the wasm library is compatible.
		let pk = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"0000000000000000000000000000000000000000000000000000000000000000",
		));
		let public = pk.public();
		let js_signature = Signature::from_raw(array_bytes::hex2array_unchecked(
			"28a854d54903e056f89581c691c1f7d2ff39f8f896c9e9c22475e60902cc2b3547199e0e91fa32902028f2ca2355e8cdd16cfe19ba5e8b658c94aa80f3b81a00"
		));
		assert!(Pair::verify_deprecated(&js_signature, b"SUBSTRATE", &public));
		assert!(!Pair::verify(&js_signature, b"SUBSTRATE", &public));
	}

	#[test]
	fn signature_serialization_works() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let message = b"Something important";
		let signature = pair.sign(&message[..]);
		let serialized_signature = serde_json::to_string(&signature).unwrap();
		// Signature is 64 bytes, so 128 chars + 2 quote chars
		assert_eq!(serialized_signature.len(), 130);
		let signature = serde_json::from_str(&serialized_signature).unwrap();
		assert!(Pair::verify(&signature, &message[..], &pair.public()));
	}

	#[test]
	fn signature_serialization_doesnt_panic() {
		fn deserialize_signature(text: &str) -> Result<Signature, serde_json::error::Error> {
			serde_json::from_str(text)
		}
		assert!(deserialize_signature("Not valid json.").is_err());
		assert!(deserialize_signature("\"Not an actual signature.\"").is_err());
		// Poorly-sized
		assert!(deserialize_signature("\"abc123\"").is_err());
	}

	#[test]
	fn vrf_sign_verify() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();

		let data = VrfTranscript::new(b"label", &[(b"domain1", b"data1")]).into();

		let signature = pair.vrf_sign(&data);

		assert!(public.vrf_verify(&data, &signature));
	}

	#[test]
	fn vrf_sign_verify_with_extra() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();

		let extra = VrfTranscript::new(b"extra", &[(b"domain2", b"data2")]);
		let data = VrfTranscript::new(b"label", &[(b"domain1", b"data1")])
			.into_sign_data()
			.with_extra(extra);

		let signature = pair.vrf_sign(&data);

		assert!(public.vrf_verify(&data, &signature));
	}

	#[test]
	fn vrf_make_bytes_matches() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		let ctx = b"vrfbytes";

		let input = VrfTranscript::new(b"label", &[(b"domain1", b"data1")]);

		let pre_output = pair.vrf_pre_output(&input);

		let out1 = pair.make_bytes::<32>(ctx, &input);
		let out2 = pre_output.make_bytes::<32>(ctx, &input, &public).unwrap();
		assert_eq!(out1, out2);

		let extra = VrfTranscript::new(b"extra", &[(b"domain2", b"data2")]);
		let data = input.clone().into_sign_data().with_extra(extra);
		let signature = pair.vrf_sign(&data);
		assert!(public.vrf_verify(&data, &signature));

		let out3 = public.make_bytes::<32>(ctx, &input, &signature.pre_output).unwrap();
		assert_eq!(out2, out3);
	}

	#[test]
	fn vrf_backend_compat() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		let ctx = b"vrfbytes";

		let input = VrfInput::new(b"label", &[(b"domain1", b"data1")]);
		let extra = VrfTranscript::new(b"extra", &[(b"domain2", b"data2")]);

		let data = input.clone().into_sign_data().with_extra(extra.clone());
		let signature = pair.vrf_sign(&data);
		assert!(public.vrf_verify(&data, &signature));

		let out1 = pair.make_bytes::<32>(ctx, &input);
		let out2 = public.make_bytes::<32>(ctx, &input, &signature.pre_output).unwrap();
		assert_eq!(out1, out2);

		// Direct call to backend version of sign after check with extra params
		let (inout, proof, _) = pair
			.0
			.vrf_sign_extra_after_check(input.0.clone(), |inout| {
				let out3 = inout.make_bytes::<[u8; 32]>(ctx);
				assert_eq!(out2, out3);
				Some(extra.0.clone())
			})
			.unwrap();
		let signature2 =
			VrfSignature { pre_output: VrfPreOutput(inout.to_preout()), proof: VrfProof(proof) };

		assert!(public.vrf_verify(&data, &signature2));
		assert_eq!(signature.pre_output, signature2.pre_output);
	}

	#[test]
	fn good_proof_of_possession_should_work_bad_proof_of_possession_should_fail() {
		let mut pair = Pair::from_seed(b"12345678901234567890123456789012");
		let other_pair = Pair::from_seed(b"23456789012345678901234567890123");
		let proof_of_possession = pair.generate_proof_of_possession();
		assert!(Pair::verify_proof_of_possession(&proof_of_possession, &pair.public()));
		assert!(!Pair::verify_proof_of_possession(&proof_of_possession, &other_pair.public()));
	}
}
