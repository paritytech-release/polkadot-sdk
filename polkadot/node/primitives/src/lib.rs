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

//! Primitive types used on the node-side.
//!
//! Unlike the `polkadot-primitives` crate, these primitives are only used on the node-side,
//! not shared between the node and the runtime. This crate builds on top of the primitives defined
//! there.

#![deny(missing_docs)]

use std::pin::Pin;

use bounded_vec::BoundedVec;
use codec::{Decode, Encode, Error as CodecError, Input};
use futures::Future;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use polkadot_primitives::{
	vstaging::{
		CommittedCandidateReceiptError, CommittedCandidateReceiptV2 as CommittedCandidateReceipt,
	},
	BlakeTwo256, BlockNumber, CandidateCommitments, CandidateHash, ChunkIndex, CollatorPair,
	CompactStatement, CoreIndex, EncodeAs, Hash, HashT, HeadData, Id as ParaId,
	PersistedValidationData, SessionIndex, Signed, UncheckedSigned, ValidationCode,
	ValidationCodeHash, MAX_CODE_SIZE, MAX_POV_SIZE,
};
pub use sp_consensus_babe::{
	AllowedSlots as BabeAllowedSlots, BabeEpochConfiguration, Epoch as BabeEpoch,
	Randomness as BabeRandomness,
};

pub use polkadot_parachain_primitives::primitives::{
	BlockData, HorizontalMessages, UpwardMessages,
};

pub mod approval;

/// Disputes related types.
pub mod disputes;
pub use disputes::{
	dispute_is_inactive, CandidateVotes, DisputeMessage, DisputeMessageCheckError, DisputeStatus,
	InvalidDisputeVote, SignedDisputeStatement, Timestamp, UncheckedDisputeMessage,
	ValidDisputeVote, ACTIVE_DURATION_SECS,
};

/// The current node version, which takes the basic SemVer form `<major>.<minor>.<patch>`.
/// In general, minor should be bumped on every release while major or patch releases are
/// relatively rare.
///
/// The associated worker binaries should use the same version as the node that spawns them.
pub const NODE_VERSION: &'static str = "1.19.0";

// For a 16-ary Merkle Prefix Trie, we can expect at most 16 32-byte hashes per node
// plus some overhead:
// header 1 + bitmap 2 + max partial_key 8 + children 16 * (32 + len 1) + value 32 + value len 1
const MERKLE_NODE_MAX_SIZE: usize = 512 + 100;
// 16-ary Merkle Prefix Trie for 32-bit ValidatorIndex has depth at most 8.
const MERKLE_PROOF_MAX_DEPTH: usize = 8;

/// The bomb limit for decompressing code blobs.
#[deprecated(
	note = "`VALIDATION_CODE_BOMB_LIMIT` will be removed. Use `validation_code_bomb_limit`
	runtime API to retrieve the value from the runtime"
)]
pub const VALIDATION_CODE_BOMB_LIMIT: usize = (MAX_CODE_SIZE * 4u32) as usize;

/// The bomb limit for decompressing PoV blobs.
pub const POV_BOMB_LIMIT: usize = (MAX_POV_SIZE * 4u32) as usize;

/// How many blocks after finalization an information about backed/included candidate should be
/// pre-loaded (when scraping onchain votes) and kept locally (when pruning).
///
/// We don't want to remove scraped candidates on finalization because we want to
/// be sure that disputes will conclude on abandoned forks.
/// Removing the candidate on finalization creates a possibility for an attacker to
/// avoid slashing. If a bad fork is abandoned too quickly because another
/// better one gets finalized the entries for the bad fork will be pruned and we
/// might never participate in a dispute for it.
///
/// Why pre-load finalized blocks? I dispute might be raised against finalized candidate. In most
/// of the cases it will conclude valid (otherwise we are in big trouble) but never the less the
/// node must participate. It's possible to see a vote for such dispute onchain before we have it
/// imported by `dispute-distribution`. In this case we won't have `CandidateReceipt` and the import
/// will fail unless we keep them preloaded.
///
/// This value should consider the timeout we allow for participation in approval-voting. In
/// particular, the following condition should hold:
///
/// slot time * `DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION` > `APPROVAL_EXECUTION_TIMEOUT`
/// + slot time
pub const DISPUTE_CANDIDATE_LIFETIME_AFTER_FINALIZATION: BlockNumber = 10;

/// Linked to `MAX_FINALITY_LAG` in relay chain selection,
/// `MAX_HEADS_LOOK_BACK` in `approval-voting` and
/// `MAX_BATCH_SCRAPE_ANCESTORS` in `dispute-coordinator`
pub const MAX_FINALITY_LAG: u32 = 500;

/// Type of a session window size.
///
/// We are not using `NonZeroU32` here because `expect` and `unwrap` are not yet const, so global
/// constants of `SessionWindowSize` would require `LazyLock` in that case.
///
/// See: <https://github.com/rust-lang/rust/issues/67441>
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SessionWindowSize(SessionIndex);

#[macro_export]
/// Create a new checked `SessionWindowSize` which cannot be 0.
macro_rules! new_session_window_size {
	(0) => {
		compile_error!("Must be non zero");
	};
	(0_u32) => {
		compile_error!("Must be non zero");
	};
	(0 as u32) => {
		compile_error!("Must be non zero");
	};
	(0 as _) => {
		compile_error!("Must be non zero");
	};
	($l:literal) => {
		SessionWindowSize::unchecked_new($l as _)
	};
}

/// It would be nice to draw this from the chain state, but we have no tools for it right now.
/// On Polkadot this is 1 day, and on Kusama it's 6 hours.
///
/// Number of sessions we want to consider in disputes.
pub const DISPUTE_WINDOW: SessionWindowSize = new_session_window_size!(6);

impl SessionWindowSize {
	/// Get the value as `SessionIndex` for doing comparisons with those.
	pub fn get(self) -> SessionIndex {
		self.0
	}

	/// Helper function for `new_session_window_size`.
	///
	/// Don't use it. The only reason it is public, is because otherwise the
	/// `new_session_window_size` macro would not work outside of this module.
	#[doc(hidden)]
	pub const fn unchecked_new(size: SessionIndex) -> Self {
		Self(size)
	}
}

/// The cumulative weight of a block in a fork-choice rule.
pub type BlockWeight = u32;

/// A statement, where the candidate receipt is included in the `Seconded` variant.
///
/// This is the committed candidate receipt instead of the bare candidate receipt. As such,
/// it gives access to the commitments to validators who have not executed the candidate. This
/// is necessary to allow a block-producing validator to include candidates from outside the para
/// it is assigned to.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub enum Statement {
	/// A statement that a validator seconds a candidate.
	#[codec(index = 1)]
	Seconded(CommittedCandidateReceipt),
	/// A statement that a validator has deemed a candidate valid.
	#[codec(index = 2)]
	Valid(CandidateHash),
}

impl std::fmt::Debug for Statement {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Statement::Seconded(seconded) => write!(f, "Seconded: {:?}", seconded.descriptor),
			Statement::Valid(hash) => write!(f, "Valid: {:?}", hash),
		}
	}
}

impl Statement {
	/// Get the candidate hash referenced by this statement.
	///
	/// If this is a `Statement::Seconded`, this does hash the candidate receipt, which may be
	/// expensive for large candidates.
	pub fn candidate_hash(&self) -> CandidateHash {
		match *self {
			Statement::Valid(ref h) => *h,
			Statement::Seconded(ref c) => c.hash(),
		}
	}

	/// Transform this statement into its compact version, which references only the hash
	/// of the candidate.
	pub fn to_compact(&self) -> CompactStatement {
		match *self {
			Statement::Seconded(ref c) => CompactStatement::Seconded(c.hash()),
			Statement::Valid(hash) => CompactStatement::Valid(hash),
		}
	}

	/// Add the [`PersistedValidationData`] to the statement, if seconded.
	pub fn supply_pvd(self, pvd: PersistedValidationData) -> StatementWithPVD {
		match self {
			Statement::Seconded(c) => StatementWithPVD::Seconded(c, pvd),
			Statement::Valid(hash) => StatementWithPVD::Valid(hash),
		}
	}
}

impl From<&'_ Statement> for CompactStatement {
	fn from(stmt: &Statement) -> Self {
		stmt.to_compact()
	}
}

impl EncodeAs<CompactStatement> for Statement {
	fn encode_as(&self) -> Vec<u8> {
		self.to_compact().encode()
	}
}

/// A statement, exactly the same as [`Statement`] but where seconded messages carry
/// the [`PersistedValidationData`].
#[derive(Clone, PartialEq, Eq)]
pub enum StatementWithPVD {
	/// A statement that a validator seconds a candidate.
	Seconded(CommittedCandidateReceipt, PersistedValidationData),
	/// A statement that a validator has deemed a candidate valid.
	Valid(CandidateHash),
}

impl std::fmt::Debug for StatementWithPVD {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			StatementWithPVD::Seconded(seconded, _) =>
				write!(f, "Seconded: {:?}", seconded.descriptor),
			StatementWithPVD::Valid(hash) => write!(f, "Valid: {:?}", hash),
		}
	}
}

impl StatementWithPVD {
	/// Get the candidate hash referenced by this statement.
	///
	/// If this is a `Statement::Seconded`, this does hash the candidate receipt, which may be
	/// expensive for large candidates.
	pub fn candidate_hash(&self) -> CandidateHash {
		match *self {
			StatementWithPVD::Valid(ref h) => *h,
			StatementWithPVD::Seconded(ref c, _) => c.hash(),
		}
	}

	/// Transform this statement into its compact version, which references only the hash
	/// of the candidate.
	pub fn to_compact(&self) -> CompactStatement {
		match *self {
			StatementWithPVD::Seconded(ref c, _) => CompactStatement::Seconded(c.hash()),
			StatementWithPVD::Valid(hash) => CompactStatement::Valid(hash),
		}
	}

	/// Drop the [`PersistedValidationData`] from the statement.
	pub fn drop_pvd(self) -> Statement {
		match self {
			StatementWithPVD::Seconded(c, _) => Statement::Seconded(c),
			StatementWithPVD::Valid(c_h) => Statement::Valid(c_h),
		}
	}

	/// Drop the [`PersistedValidationData`] from the statement in a signed
	/// variant.
	pub fn drop_pvd_from_signed(signed: SignedFullStatementWithPVD) -> SignedFullStatement {
		signed
			.convert_to_superpayload_with(|s| s.drop_pvd())
			.expect("persisted_validation_data doesn't affect encode_as; qed")
	}

	/// Converts the statement to a compact signed statement by dropping the
	/// [`CommittedCandidateReceipt`] and the [`PersistedValidationData`].
	pub fn signed_to_compact(signed: SignedFullStatementWithPVD) -> Signed<CompactStatement> {
		signed
			.convert_to_superpayload_with(|s| s.to_compact())
			.expect("doesn't affect encode_as; qed")
	}
}

impl From<&'_ StatementWithPVD> for CompactStatement {
	fn from(stmt: &StatementWithPVD) -> Self {
		stmt.to_compact()
	}
}

impl EncodeAs<CompactStatement> for StatementWithPVD {
	fn encode_as(&self) -> Vec<u8> {
		self.to_compact().encode()
	}
}

/// A statement, the corresponding signature, and the index of the sender.
///
/// Signing context and validator set should be apparent from context.
///
/// This statement is "full" in the sense that the `Seconded` variant includes the candidate
/// receipt. Only the compact `SignedStatement` is suitable for submission to the chain.
pub type SignedFullStatement = Signed<Statement, CompactStatement>;

/// Variant of `SignedFullStatement` where the signature has not yet been verified.
pub type UncheckedSignedFullStatement = UncheckedSigned<Statement, CompactStatement>;

/// A statement, the corresponding signature, and the index of the sender.
///
/// Seconded statements are accompanied by the [`PersistedValidationData`]
///
/// Signing context and validator set should be apparent from context.
pub type SignedFullStatementWithPVD = Signed<StatementWithPVD, CompactStatement>;

/// Candidate invalidity details
#[derive(Debug)]
pub enum InvalidCandidate {
	/// Failed to execute `validate_block`. This includes function panicking.
	ExecutionError(String),
	/// Validation outputs check doesn't pass.
	InvalidOutputs,
	/// Execution timeout.
	Timeout,
	/// Validation input is over the limit.
	ParamsTooLarge(u64),
	/// Code size is over the limit.
	CodeTooLarge(u64),
	/// PoV does not decompress correctly.
	PoVDecompressionFailure,
	/// Validation function returned invalid data.
	BadReturn,
	/// Invalid relay chain parent.
	BadParent,
	/// POV hash does not match.
	PoVHashMismatch,
	/// Bad collator signature.
	BadSignature,
	/// Para head hash does not match.
	ParaHeadHashMismatch,
	/// Validation code hash does not match.
	CodeHashMismatch,
	/// Validation has generated different candidate commitments.
	CommitmentsHashMismatch,
	/// The candidate receipt contains an invalid session index.
	InvalidSessionIndex,
	/// The candidate receipt invalid UMP signals.
	InvalidUMPSignals(CommittedCandidateReceiptError),
}

/// Result of the validation of the candidate.
#[derive(Debug)]
pub enum ValidationResult {
	/// Candidate is valid. The validation process yields these outputs and the persisted
	/// validation data used to form inputs.
	Valid(CandidateCommitments, PersistedValidationData),
	/// Candidate is invalid.
	Invalid(InvalidCandidate),
}

/// A Proof-of-Validity
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct PoV {
	/// The block witness data.
	pub block_data: BlockData,
}

impl PoV {
	/// Get the blake2-256 hash of the PoV.
	pub fn hash(&self) -> Hash {
		BlakeTwo256::hash_of(self)
	}
}

/// A type that represents a maybe compressed [`PoV`].
#[derive(Clone, Encode, Decode)]
#[cfg(not(target_os = "unknown"))]
pub enum MaybeCompressedPoV {
	/// A raw [`PoV`], aka not compressed.
	Raw(PoV),
	/// The given [`PoV`] is already compressed.
	Compressed(PoV),
}

#[cfg(not(target_os = "unknown"))]
impl std::fmt::Debug for MaybeCompressedPoV {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let (variant, size) = match self {
			MaybeCompressedPoV::Raw(pov) => ("Raw", pov.block_data.0.len()),
			MaybeCompressedPoV::Compressed(pov) => ("Compressed", pov.block_data.0.len()),
		};

		write!(f, "{} PoV ({} bytes)", variant, size)
	}
}

#[cfg(not(target_os = "unknown"))]
impl MaybeCompressedPoV {
	/// Convert into a compressed [`PoV`].
	///
	/// If `self == Raw` it is compressed using [`maybe_compress_pov`].
	pub fn into_compressed(self) -> PoV {
		match self {
			Self::Raw(raw) => maybe_compress_pov(raw),
			Self::Compressed(compressed) => compressed,
		}
	}
}

/// The output of a collator.
///
/// This differs from `CandidateCommitments` in two ways:
///
/// - does not contain the erasure root; that's computed at the Polkadot level, not at Cumulus
/// - contains a proof of validity.
#[derive(Debug, Clone, Encode, Decode)]
#[cfg(not(target_os = "unknown"))]
pub struct Collation<BlockNumber = polkadot_primitives::BlockNumber> {
	/// Messages destined to be interpreted by the Relay chain itself.
	pub upward_messages: UpwardMessages,
	/// The horizontal messages sent by the parachain.
	pub horizontal_messages: HorizontalMessages,
	/// New validation code.
	pub new_validation_code: Option<ValidationCode>,
	/// The head-data produced as a result of execution.
	pub head_data: HeadData,
	/// Proof to verify the state transition of the parachain.
	pub proof_of_validity: MaybeCompressedPoV,
	/// The number of messages processed from the DMQ.
	pub processed_downward_messages: u32,
	/// The mark which specifies the block number up to which all inbound HRMP messages are
	/// processed.
	pub hrmp_watermark: BlockNumber,
}

/// Signal that is being returned when a collation was seconded by a validator.
#[derive(Debug)]
#[cfg(not(target_os = "unknown"))]
pub struct CollationSecondedSignal {
	/// The hash of the relay chain block that was used as context to sign [`Self::statement`].
	pub relay_parent: Hash,
	/// The statement about seconding the collation.
	///
	/// Anything else than [`Statement::Seconded`] is forbidden here.
	pub statement: SignedFullStatement,
}

/// Result of the [`CollatorFn`] invocation.
#[cfg(not(target_os = "unknown"))]
pub struct CollationResult {
	/// The collation that was build.
	pub collation: Collation,
	/// An optional result sender that should be informed about a successfully seconded collation.
	///
	/// There is no guarantee that this sender is informed ever about any result, it is completely
	/// okay to just drop it. However, if it is called, it should be called with the signed
	/// statement of a parachain validator seconding the collation.
	pub result_sender: Option<futures::channel::oneshot::Sender<CollationSecondedSignal>>,
}

#[cfg(not(target_os = "unknown"))]
impl CollationResult {
	/// Convert into the inner values.
	pub fn into_inner(
		self,
	) -> (Collation, Option<futures::channel::oneshot::Sender<CollationSecondedSignal>>) {
		(self.collation, self.result_sender)
	}
}

/// Collation function.
///
/// Will be called with the hash of the relay chain block the parachain block should be build on and
/// the [`PersistedValidationData`] that provides information about the state of the parachain on
/// the relay chain.
///
/// Returns an optional [`CollationResult`].
#[cfg(not(target_os = "unknown"))]
pub type CollatorFn = Box<
	dyn Fn(
			Hash,
			&PersistedValidationData,
		) -> Pin<Box<dyn Future<Output = Option<CollationResult>> + Send>>
		+ Send
		+ Sync,
>;

/// Configuration for the collation generator
#[cfg(not(target_os = "unknown"))]
pub struct CollationGenerationConfig {
	/// Collator's authentication key, so it can sign things.
	pub key: CollatorPair,
	/// Collation function. See [`CollatorFn`] for more details.
	///
	/// If this is `None`, it implies that collations are intended to be submitted
	/// out-of-band and not pulled out of the function.
	pub collator: Option<CollatorFn>,
	/// The parachain that this collator collates for
	pub para_id: ParaId,
}

#[cfg(not(target_os = "unknown"))]
impl std::fmt::Debug for CollationGenerationConfig {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "CollationGenerationConfig {{ ... }}")
	}
}

/// Parameters for `CollationGenerationMessage::SubmitCollation`.
#[derive(Debug)]
pub struct SubmitCollationParams {
	/// The relay-parent the collation is built against.
	pub relay_parent: Hash,
	/// The collation itself (PoV and commitments)
	pub collation: Collation,
	/// The parent block's head-data.
	pub parent_head: HeadData,
	/// The hash of the validation code the collation was created against.
	pub validation_code_hash: ValidationCodeHash,
	/// An optional result sender that should be informed about a successfully seconded collation.
	///
	/// There is no guarantee that this sender is informed ever about any result, it is completely
	/// okay to just drop it. However, if it is called, it should be called with the signed
	/// statement of a parachain validator seconding the collation.
	pub result_sender: Option<futures::channel::oneshot::Sender<CollationSecondedSignal>>,
	/// The core index on which the resulting candidate should be backed
	pub core_index: CoreIndex,
}

/// This is the data we keep available for each candidate included in the relay chain.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
pub struct AvailableData {
	/// The Proof-of-Validation of the candidate.
	pub pov: std::sync::Arc<PoV>,
	/// The persisted validation data needed for approval checks.
	pub validation_data: PersistedValidationData,
}

/// This is a convenience type to allow the Erasure chunk proof to Decode into a nested BoundedVec
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Proof(BoundedVec<BoundedVec<u8, 1, MERKLE_NODE_MAX_SIZE>, 1, MERKLE_PROOF_MAX_DEPTH>);

impl Proof {
	/// This function allows to convert back to the standard nested Vec format
	pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
		self.0.iter().map(|v| v.as_slice())
	}

	/// Construct an invalid dummy proof
	///
	/// Useful for testing, should absolutely not be used in production.
	pub fn dummy_proof() -> Proof {
		Proof(BoundedVec::from_vec(vec![BoundedVec::from_vec(vec![0]).unwrap()]).unwrap())
	}
}

/// Possible errors when converting from `Vec<Vec<u8>>` into [`Proof`].
#[derive(thiserror::Error, Debug)]
pub enum MerkleProofError {
	#[error("Merkle max proof depth exceeded {0} > {} .", MERKLE_PROOF_MAX_DEPTH)]
	/// This error signifies that the Proof length exceeds the trie's max depth
	MerkleProofDepthExceeded(usize),

	#[error("Merkle node max size exceeded {0} > {} .", MERKLE_NODE_MAX_SIZE)]
	/// This error signifies that a Proof node exceeds the 16-ary max node size
	MerkleProofNodeSizeExceeded(usize),
}

impl TryFrom<Vec<Vec<u8>>> for Proof {
	type Error = MerkleProofError;

	fn try_from(input: Vec<Vec<u8>>) -> Result<Self, Self::Error> {
		if input.len() > MERKLE_PROOF_MAX_DEPTH {
			return Err(Self::Error::MerkleProofDepthExceeded(input.len()))
		}
		let mut out = Vec::new();
		for element in input.into_iter() {
			let length = element.len();
			let data: BoundedVec<u8, 1, MERKLE_NODE_MAX_SIZE> = BoundedVec::from_vec(element)
				.map_err(|_| Self::Error::MerkleProofNodeSizeExceeded(length))?;
			out.push(data);
		}
		Ok(Proof(BoundedVec::from_vec(out).expect("Buffer size is deterined above. qed")))
	}
}

impl Decode for Proof {
	fn decode<I: Input>(value: &mut I) -> Result<Self, CodecError> {
		let temp: Vec<Vec<u8>> = Decode::decode(value)?;
		let mut out = Vec::new();
		for element in temp.into_iter() {
			let bounded_temp: Result<BoundedVec<u8, 1, MERKLE_NODE_MAX_SIZE>, CodecError> =
				BoundedVec::from_vec(element)
					.map_err(|_| "Inner node exceeds maximum node size.".into());
			out.push(bounded_temp?);
		}
		BoundedVec::from_vec(out)
			.map(Self)
			.map_err(|_| "Merkle proof depth exceeds maximum trie depth".into())
	}
}

impl Encode for Proof {
	fn size_hint(&self) -> usize {
		MERKLE_NODE_MAX_SIZE * MERKLE_PROOF_MAX_DEPTH
	}

	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		let temp = self.0.iter().map(|v| v.as_vec()).collect::<Vec<_>>();
		temp.using_encoded(f)
	}
}

impl Serialize for Proof {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_bytes(&self.encode())
	}
}

impl<'de> Deserialize<'de> for Proof {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		// Deserialize the string and get individual components
		let s = Vec::<u8>::deserialize(deserializer)?;
		let mut slice = s.as_slice();
		Decode::decode(&mut slice).map_err(de::Error::custom)
	}
}

/// A chunk of erasure-encoded block data.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Serialize, Deserialize, Debug, Hash)]
pub struct ErasureChunk {
	/// The erasure-encoded chunk of data belonging to the candidate block.
	pub chunk: Vec<u8>,
	/// The index of this erasure-encoded chunk of data.
	pub index: ChunkIndex,
	/// Proof for this chunk's branch in the Merkle tree.
	pub proof: Proof,
}

impl ErasureChunk {
	/// Convert bounded Vec Proof to regular `Vec<Vec<u8>>`
	pub fn proof(&self) -> &Proof {
		&self.proof
	}
}

/// Compress a PoV, unless it exceeds the [`POV_BOMB_LIMIT`].
#[cfg(not(target_os = "unknown"))]
pub fn maybe_compress_pov(pov: PoV) -> PoV {
	let PoV { block_data: BlockData(raw) } = pov;
	let raw = sp_maybe_compressed_blob::compress(&raw, POV_BOMB_LIMIT).unwrap_or(raw);

	let pov = PoV { block_data: BlockData(raw) };
	pov
}
