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

/// # Overview
///
/// A set of utilities for node-side code to emulate the logic the runtime uses for checking
/// parachain blocks in order to build prospective parachains that are produced ahead of the
/// relay chain. These utilities allow the node-side to predict, with high accuracy, what
/// the relay-chain will accept in the near future.
///
/// This module has 2 key data types: [`Constraints`] and [`Fragment`]s. [`Constraints`]
/// exhaustively define the set of valid inputs and outputs to parachain execution. A
/// [`Fragment`] indicates a parachain block, anchored to the relay-chain at a particular
/// relay-chain block, known as the relay-parent.
///
/// ## Fragment Validity
///
/// Every relay-parent is implicitly associated with a unique set of [`Constraints`] that
/// describe the properties that must be true for a block to be included in a direct child of
/// that block, assuming there is no intermediate parachain block pending availability.
///
/// However, the key factor that makes asynchronously-grown prospective chains
/// possible is the fact that the relay-chain accepts candidate blocks based on whether they
/// are valid under the constraints of the present moment, not based on whether they were
/// valid at the time of construction.
///
/// As such, [`Fragment`]s are often, but not always constructed in such a way that they are
/// invalid at first and become valid later on, as the relay chain grows.
///
/// # Usage
///
/// It's expected that the users of this module will be building up chains or trees of
/// [`Fragment`]s and consistently pruning and adding to them.
///
/// ## Operating Constraints
///
/// The *operating constraints* of a `Fragment` are the constraints with which that fragment
/// was intended to comply. The operating constraints are defined as the base constraints
/// of the relay-parent of the fragment modified by the cumulative modifications of all
/// fragments between the relay-parent and the current fragment.
///
/// What the operating constraints are, in practice, is a prediction about the state of the
/// relay-chain in the future. The relay-chain is aware of some current state, and we want to
/// make an intelligent prediction about what might be accepted in the future based on
/// prior fragments that also exist off-chain.
///
/// ## Fragment Chains
///
/// For the sake of this module, we don't care how higher-level code is managing parachain
/// fragments, whether or not they're kept as a chain or tree. In reality,
/// prospective-parachains is maintaining for every active leaf, a chain of the "best" backable
/// candidates and a storage of potential candidates which may be added to this chain in the
/// future.
///
/// As the relay-chain grows, some predictions come true and others come false.
/// And new predictions get made. Higher-level code is responsible for adding and pruning the
/// fragments chains.
///
/// Avoiding fragment-chain blowup is beyond the scope of this module. Higher-level must ensure
/// proper spam protection.
///
/// ### Code Upgrades
///
/// Code upgrades are the main place where this emulation fails. The on-chain PVF upgrade
/// scheduling logic is very path-dependent and intricate so we just assume that code upgrades
/// can't be initiated and applied within a single fragment-chain. Fragment-chains aren't deep,
/// in practice (bounded by a linear function of the the number of cores assigned to a
/// parachain) and code upgrades are fairly rare. So what's likely to happen around code
/// upgrades is that the entire fragment-chain has to get discarded at some point.
///
/// That means a few blocks of execution time lost, which is not a big deal for code upgrades
/// in practice at most once every few weeks.
use polkadot_node_subsystem::messages::HypotheticalCandidate;
use polkadot_primitives::{
	async_backing::Constraints as OldPrimitiveConstraints,
	vstaging::{async_backing::Constraints as PrimitiveConstraints, skip_ump_signals},
	BlockNumber, CandidateCommitments, CandidateHash, Hash, HeadData, Id as ParaId,
	PersistedValidationData, UpgradeRestriction, ValidationCodeHash,
};
use std::{collections::HashMap, sync::Arc};

/// Constraints on inbound HRMP channels.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundHrmpLimitations {
	/// An exhaustive set of all valid watermarks, sorted ascending
	pub valid_watermarks: Vec<BlockNumber>,
}

/// Constraints on outbound HRMP channels.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboundHrmpChannelLimitations {
	/// The maximum bytes that can be written to the channel.
	pub bytes_remaining: usize,
	/// The maximum messages that can be written to the channel.
	pub messages_remaining: usize,
}

/// Constraints on the actions that can be taken by a new parachain
/// block. These limitations are implicitly associated with some particular
/// parachain, which should be apparent from usage.
#[derive(Debug, Clone, PartialEq)]
pub struct Constraints {
	/// The minimum relay-parent number accepted under these constraints.
	pub min_relay_parent_number: BlockNumber,
	/// The maximum Proof-of-Validity size allowed, in bytes.
	pub max_pov_size: usize,
	/// The maximum new validation code size allowed, in bytes.
	pub max_code_size: usize,
	/// The maximum head-data size, in bytes.
	pub max_head_data_size: usize,
	/// The amount of UMP messages remaining.
	pub ump_remaining: usize,
	/// The amount of UMP bytes remaining.
	pub ump_remaining_bytes: usize,
	/// The maximum number of UMP messages allowed per candidate.
	pub max_ump_num_per_candidate: usize,
	/// Remaining DMP queue. Only includes sent-at block numbers.
	pub dmp_remaining_messages: Vec<BlockNumber>,
	/// The limitations of all registered inbound HRMP channels.
	pub hrmp_inbound: InboundHrmpLimitations,
	/// The limitations of all registered outbound HRMP channels.
	pub hrmp_channels_out: HashMap<ParaId, OutboundHrmpChannelLimitations>,
	/// The maximum number of HRMP messages allowed per candidate.
	pub max_hrmp_num_per_candidate: usize,
	/// The required parent head-data of the parachain.
	pub required_parent: HeadData,
	/// The expected validation-code-hash of this parachain.
	pub validation_code_hash: ValidationCodeHash,
	/// The code upgrade restriction signal as-of this parachain.
	pub upgrade_restriction: Option<UpgradeRestriction>,
	/// The future validation code hash, if any, and at what relay-parent
	/// number the upgrade would be minimally applied.
	pub future_validation_code: Option<(BlockNumber, ValidationCodeHash)>,
}

impl From<PrimitiveConstraints> for Constraints {
	fn from(c: PrimitiveConstraints) -> Self {
		Constraints {
			min_relay_parent_number: c.min_relay_parent_number,
			max_pov_size: c.max_pov_size as _,
			max_code_size: c.max_code_size as _,
			max_head_data_size: c.max_head_data_size as _,
			ump_remaining: c.ump_remaining as _,
			ump_remaining_bytes: c.ump_remaining_bytes as _,
			max_ump_num_per_candidate: c.max_ump_num_per_candidate as _,
			dmp_remaining_messages: c.dmp_remaining_messages,
			hrmp_inbound: InboundHrmpLimitations {
				valid_watermarks: c.hrmp_inbound.valid_watermarks,
			},
			hrmp_channels_out: c
				.hrmp_channels_out
				.into_iter()
				.map(|(para_id, limits)| {
					(
						para_id,
						OutboundHrmpChannelLimitations {
							bytes_remaining: limits.bytes_remaining as _,
							messages_remaining: limits.messages_remaining as _,
						},
					)
				})
				.collect(),
			max_hrmp_num_per_candidate: c.max_hrmp_num_per_candidate as _,
			required_parent: c.required_parent,
			validation_code_hash: c.validation_code_hash,
			upgrade_restriction: c.upgrade_restriction,
			future_validation_code: c.future_validation_code,
		}
	}
}

impl From<OldPrimitiveConstraints> for Constraints {
	fn from(c: OldPrimitiveConstraints) -> Self {
		Constraints {
			min_relay_parent_number: c.min_relay_parent_number,
			max_pov_size: c.max_pov_size as _,
			max_code_size: c.max_code_size as _,
			// Equal to Polkadot/Kusama config.
			max_head_data_size: 20480,
			ump_remaining: c.ump_remaining as _,
			ump_remaining_bytes: c.ump_remaining_bytes as _,
			max_ump_num_per_candidate: c.max_ump_num_per_candidate as _,
			dmp_remaining_messages: c.dmp_remaining_messages,
			hrmp_inbound: InboundHrmpLimitations {
				valid_watermarks: c.hrmp_inbound.valid_watermarks,
			},
			hrmp_channels_out: c
				.hrmp_channels_out
				.into_iter()
				.map(|(para_id, limits)| {
					(
						para_id,
						OutboundHrmpChannelLimitations {
							bytes_remaining: limits.bytes_remaining as _,
							messages_remaining: limits.messages_remaining as _,
						},
					)
				})
				.collect(),
			max_hrmp_num_per_candidate: c.max_hrmp_num_per_candidate as _,
			required_parent: c.required_parent,
			validation_code_hash: c.validation_code_hash,
			upgrade_restriction: c.upgrade_restriction,
			future_validation_code: c.future_validation_code,
		}
	}
}

/// Kinds of errors that can occur when modifying constraints.
#[derive(Debug, Clone, PartialEq)]
pub enum ModificationError {
	/// The HRMP watermark is not allowed.
	DisallowedHrmpWatermark(BlockNumber),
	/// No such HRMP outbound channel.
	NoSuchHrmpChannel(ParaId),
	/// Too many messages submitted to HRMP channel.
	HrmpMessagesOverflow {
		/// The ID of the recipient.
		para_id: ParaId,
		/// The amount of remaining messages in the capacity of the channel.
		messages_remaining: usize,
		/// The amount of messages submitted to the channel.
		messages_submitted: usize,
	},
	/// Too many bytes submitted to HRMP channel.
	HrmpBytesOverflow {
		/// The ID of the recipient.
		para_id: ParaId,
		/// The amount of remaining bytes in the capacity of the channel.
		bytes_remaining: usize,
		/// The amount of bytes submitted to the channel.
		bytes_submitted: usize,
	},
	/// Too many messages submitted to UMP.
	UmpMessagesOverflow {
		/// The amount of remaining messages in the capacity of UMP.
		messages_remaining: usize,
		/// The amount of messages submitted to UMP.
		messages_submitted: usize,
	},
	/// Too many bytes submitted to UMP.
	UmpBytesOverflow {
		/// The amount of remaining bytes in the capacity of UMP.
		bytes_remaining: usize,
		/// The amount of bytes submitted to UMP.
		bytes_submitted: usize,
	},
	/// Too many messages processed from DMP.
	DmpMessagesUnderflow {
		/// The amount of messages waiting to be processed from DMP.
		messages_remaining: usize,
		/// The amount of messages processed.
		messages_processed: usize,
	},
	/// No validation code upgrade to apply.
	AppliedNonexistentCodeUpgrade,
}

impl Constraints {
	/// Check modifications against constraints.
	pub fn check_modifications(
		&self,
		modifications: &ConstraintModifications,
	) -> Result<(), ModificationError> {
		if let Some(HrmpWatermarkUpdate::Trunk(hrmp_watermark)) = modifications.hrmp_watermark {
			// head updates are always valid.
			if !self.hrmp_inbound.valid_watermarks.contains(&hrmp_watermark) {
				return Err(ModificationError::DisallowedHrmpWatermark(hrmp_watermark))
			}
		}

		for (id, outbound_hrmp_mod) in &modifications.outbound_hrmp {
			if let Some(outbound) = self.hrmp_channels_out.get(&id) {
				outbound.bytes_remaining.checked_sub(outbound_hrmp_mod.bytes_submitted).ok_or(
					ModificationError::HrmpBytesOverflow {
						para_id: *id,
						bytes_remaining: outbound.bytes_remaining,
						bytes_submitted: outbound_hrmp_mod.bytes_submitted,
					},
				)?;

				outbound
					.messages_remaining
					.checked_sub(outbound_hrmp_mod.messages_submitted)
					.ok_or(ModificationError::HrmpMessagesOverflow {
						para_id: *id,
						messages_remaining: outbound.messages_remaining,
						messages_submitted: outbound_hrmp_mod.messages_submitted,
					})?;
			} else {
				return Err(ModificationError::NoSuchHrmpChannel(*id))
			}
		}

		self.ump_remaining.checked_sub(modifications.ump_messages_sent).ok_or(
			ModificationError::UmpMessagesOverflow {
				messages_remaining: self.ump_remaining,
				messages_submitted: modifications.ump_messages_sent,
			},
		)?;

		self.ump_remaining_bytes.checked_sub(modifications.ump_bytes_sent).ok_or(
			ModificationError::UmpBytesOverflow {
				bytes_remaining: self.ump_remaining_bytes,
				bytes_submitted: modifications.ump_bytes_sent,
			},
		)?;

		self.dmp_remaining_messages
			.len()
			.checked_sub(modifications.dmp_messages_processed)
			.ok_or(ModificationError::DmpMessagesUnderflow {
				messages_remaining: self.dmp_remaining_messages.len(),
				messages_processed: modifications.dmp_messages_processed,
			})?;

		if self.future_validation_code.is_none() && modifications.code_upgrade_applied {
			return Err(ModificationError::AppliedNonexistentCodeUpgrade)
		}

		Ok(())
	}

	/// Apply modifications to these constraints. If this succeeds, it passes
	/// all sanity-checks.
	pub fn apply_modifications(
		&self,
		modifications: &ConstraintModifications,
	) -> Result<Self, ModificationError> {
		let mut new = self.clone();

		if let Some(required_parent) = modifications.required_parent.as_ref() {
			new.required_parent = required_parent.clone();
		}

		if let Some(ref hrmp_watermark) = modifications.hrmp_watermark {
			match new.hrmp_inbound.valid_watermarks.binary_search(&hrmp_watermark.watermark()) {
				Ok(pos) => {
					// Exact match, so this is OK in all cases.
					let _ = new.hrmp_inbound.valid_watermarks.drain(..pos);
				},
				Err(pos) => match hrmp_watermark {
					HrmpWatermarkUpdate::Head(_) => {
						// Updates to Head are always OK.
						let _ = new.hrmp_inbound.valid_watermarks.drain(..pos);
					},
					HrmpWatermarkUpdate::Trunk(n) => {
						// Trunk update landing on disallowed watermark is not OK.
						return Err(ModificationError::DisallowedHrmpWatermark(*n))
					},
				},
			}
		}

		for (id, outbound_hrmp_mod) in &modifications.outbound_hrmp {
			if let Some(outbound) = new.hrmp_channels_out.get_mut(&id) {
				outbound.bytes_remaining = outbound
					.bytes_remaining
					.checked_sub(outbound_hrmp_mod.bytes_submitted)
					.ok_or(ModificationError::HrmpBytesOverflow {
						para_id: *id,
						bytes_remaining: outbound.bytes_remaining,
						bytes_submitted: outbound_hrmp_mod.bytes_submitted,
					})?;

				outbound.messages_remaining = outbound
					.messages_remaining
					.checked_sub(outbound_hrmp_mod.messages_submitted)
					.ok_or(ModificationError::HrmpMessagesOverflow {
						para_id: *id,
						messages_remaining: outbound.messages_remaining,
						messages_submitted: outbound_hrmp_mod.messages_submitted,
					})?;
			} else {
				return Err(ModificationError::NoSuchHrmpChannel(*id))
			}
		}

		new.ump_remaining = new.ump_remaining.checked_sub(modifications.ump_messages_sent).ok_or(
			ModificationError::UmpMessagesOverflow {
				messages_remaining: new.ump_remaining,
				messages_submitted: modifications.ump_messages_sent,
			},
		)?;

		new.ump_remaining_bytes = new
			.ump_remaining_bytes
			.checked_sub(modifications.ump_bytes_sent)
			.ok_or(ModificationError::UmpBytesOverflow {
				bytes_remaining: new.ump_remaining_bytes,
				bytes_submitted: modifications.ump_bytes_sent,
			})?;

		if modifications.dmp_messages_processed > new.dmp_remaining_messages.len() {
			return Err(ModificationError::DmpMessagesUnderflow {
				messages_remaining: new.dmp_remaining_messages.len(),
				messages_processed: modifications.dmp_messages_processed,
			})
		} else {
			new.dmp_remaining_messages =
				new.dmp_remaining_messages[modifications.dmp_messages_processed..].to_vec();
		}

		if modifications.code_upgrade_applied {
			new.validation_code_hash = new
				.future_validation_code
				.take()
				.ok_or(ModificationError::AppliedNonexistentCodeUpgrade)?
				.1;
		}

		Ok(new)
	}
}

/// Information about a relay-chain block.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayChainBlockInfo {
	/// The hash of the relay-chain block.
	pub hash: Hash,
	/// The number of the relay-chain block.
	pub number: BlockNumber,
	/// The storage-root of the relay-chain block.
	pub storage_root: Hash,
}

/// An update to outbound HRMP channels.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OutboundHrmpChannelModification {
	/// The number of bytes submitted to the channel.
	pub bytes_submitted: usize,
	/// The number of messages submitted to the channel.
	pub messages_submitted: usize,
}

/// An update to the HRMP Watermark.
#[derive(Debug, Clone, PartialEq)]
pub enum HrmpWatermarkUpdate {
	/// This is an update placing the watermark at the head of the chain,
	/// which is always legal.
	Head(BlockNumber),
	/// This is an update placing the watermark behind the head of the
	/// chain, which is only legal if it lands on a block where messages
	/// were queued.
	Trunk(BlockNumber),
}

impl HrmpWatermarkUpdate {
	fn watermark(&self) -> BlockNumber {
		match *self {
			HrmpWatermarkUpdate::Head(n) | HrmpWatermarkUpdate::Trunk(n) => n,
		}
	}
}

/// Modifications to constraints as a result of prospective candidates.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstraintModifications {
	/// The required parent head to build upon.
	pub required_parent: Option<HeadData>,
	/// The new HRMP watermark
	pub hrmp_watermark: Option<HrmpWatermarkUpdate>,
	/// Outbound HRMP channel modifications.
	pub outbound_hrmp: HashMap<ParaId, OutboundHrmpChannelModification>,
	/// The amount of UMP XCM messages sent. `UMPSignal` and separator are excluded.
	pub ump_messages_sent: usize,
	/// The amount of UMP XCM bytes sent. `UMPSignal` and separator are excluded.
	pub ump_bytes_sent: usize,
	/// The amount of DMP messages processed.
	pub dmp_messages_processed: usize,
	/// Whether a pending code upgrade has been applied.
	pub code_upgrade_applied: bool,
}

impl ConstraintModifications {
	/// The 'identity' modifications: these can be applied to
	/// any constraints and yield the exact same result.
	pub fn identity() -> Self {
		ConstraintModifications {
			required_parent: None,
			hrmp_watermark: None,
			outbound_hrmp: HashMap::new(),
			ump_messages_sent: 0,
			ump_bytes_sent: 0,
			dmp_messages_processed: 0,
			code_upgrade_applied: false,
		}
	}

	/// Stack other modifications on top of these.
	///
	/// This does no sanity-checking, so if `other` is garbage relative
	/// to `self`, then the new value will be garbage as well.
	///
	/// This is an addition which is not commutative.
	pub fn stack(&mut self, other: &Self) {
		if let Some(ref new_parent) = other.required_parent {
			self.required_parent = Some(new_parent.clone());
		}
		if let Some(ref new_hrmp_watermark) = other.hrmp_watermark {
			self.hrmp_watermark = Some(new_hrmp_watermark.clone());
		}

		for (id, mods) in &other.outbound_hrmp {
			let record = self.outbound_hrmp.entry(*id).or_default();
			record.messages_submitted += mods.messages_submitted;
			record.bytes_submitted += mods.bytes_submitted;
		}

		self.ump_messages_sent += other.ump_messages_sent;
		self.ump_bytes_sent += other.ump_bytes_sent;
		self.dmp_messages_processed += other.dmp_messages_processed;
		self.code_upgrade_applied |= other.code_upgrade_applied;
	}
}

/// The prospective candidate.
///
/// This comprises the key information that represent a candidate
/// without pinning it to a particular session. For example commitments are
/// represented here. But the erasure-root is not. This means that prospective candidates
/// are not correlated to any session in particular.
#[derive(Debug, Clone, PartialEq)]
pub struct ProspectiveCandidate {
	/// The commitments to the output of the execution.
	pub commitments: CandidateCommitments,
	/// The persisted validation data used to create the candidate.
	pub persisted_validation_data: PersistedValidationData,
	/// The hash of the PoV.
	pub pov_hash: Hash,
	/// The validation code hash used by the candidate.
	pub validation_code_hash: ValidationCodeHash,
}

/// Kinds of errors with the validity of a fragment.
#[derive(Debug, Clone, PartialEq)]
pub enum FragmentValidityError {
	/// The validation code of the candidate doesn't match the
	/// operating constraints.
	///
	/// Expected, Got
	ValidationCodeMismatch(ValidationCodeHash, ValidationCodeHash),
	/// The persisted-validation-data doesn't match.
	///
	/// Expected, Got
	PersistedValidationDataMismatch(PersistedValidationData, PersistedValidationData),
	/// The outputs of the candidate are invalid under the operating
	/// constraints.
	OutputsInvalid(ModificationError),
	/// New validation code size too big.
	///
	/// Max allowed, new.
	CodeSizeTooLarge(usize, usize),
	/// Head data size too big.
	///
	/// Max allowed, new.
	HeadDataTooLarge(usize, usize),
	/// Relay parent too old.
	///
	/// Min allowed, current.
	RelayParentTooOld(BlockNumber, BlockNumber),
	/// Para is required to process at least one DMP message from the queue.
	DmpAdvancementRule,
	/// Too many messages upward messages submitted.
	UmpMessagesPerCandidateOverflow {
		/// The amount of messages a single candidate can submit.
		messages_allowed: usize,
		/// The amount of messages sent to all HRMP channels.
		messages_submitted: usize,
	},
	/// Too many messages submitted to all HRMP channels.
	HrmpMessagesPerCandidateOverflow {
		/// The amount of messages a single candidate can submit.
		messages_allowed: usize,
		/// The amount of messages sent to all HRMP channels.
		messages_submitted: usize,
	},
	/// Code upgrade not allowed.
	CodeUpgradeRestricted,
	/// HRMP messages are not ascending or are duplicate.
	///
	/// The `usize` is the index into the outbound HRMP messages of
	/// the candidate.
	HrmpMessagesDescendingOrDuplicate(usize),
}

/// A parachain fragment, representing another prospective parachain block.
///
/// This is a type which guarantees that the candidate is valid under the
/// operating constraints.
#[derive(Debug, Clone, PartialEq)]
pub struct Fragment {
	/// The new relay-parent.
	relay_parent: RelayChainBlockInfo,
	/// The constraints this fragment is operating under.
	operating_constraints: Constraints,
	/// The core information about the prospective candidate.
	candidate: Arc<ProspectiveCandidate>,
	/// Modifications to the constraints based on the outputs of
	/// the candidate.
	modifications: ConstraintModifications,
}

impl Fragment {
	/// Create a new fragment.
	///
	/// This fails if the fragment isn't in line with the operating
	/// constraints. That is, either its inputs or its outputs fail
	/// checks against the constraints.
	///
	/// This doesn't check that the collator signature is valid or
	/// whether the PoV is small enough.
	pub fn new(
		relay_parent: RelayChainBlockInfo,
		operating_constraints: Constraints,
		candidate: Arc<ProspectiveCandidate>,
	) -> Result<Self, FragmentValidityError> {
		let modifications = Self::check_against_constraints(
			&relay_parent,
			&operating_constraints,
			&candidate.commitments,
			&candidate.validation_code_hash,
			&candidate.persisted_validation_data,
		)?;

		Ok(Fragment { relay_parent, operating_constraints, candidate, modifications })
	}

	/// Check the candidate against the operating constrains and return the constraint modifications
	/// made by this candidate.
	pub fn check_against_constraints(
		relay_parent: &RelayChainBlockInfo,
		operating_constraints: &Constraints,
		commitments: &CandidateCommitments,
		validation_code_hash: &ValidationCodeHash,
		persisted_validation_data: &PersistedValidationData,
	) -> Result<ConstraintModifications, FragmentValidityError> {
		// Filter UMP signals and the separator.
		let upward_messages =
			skip_ump_signals(commitments.upward_messages.iter()).collect::<Vec<_>>();

		let ump_messages_sent = upward_messages.len();
		let ump_bytes_sent = upward_messages.iter().map(|msg| msg.len()).sum();

		let modifications = {
			ConstraintModifications {
				required_parent: Some(commitments.head_data.clone()),
				hrmp_watermark: Some({
					if commitments.hrmp_watermark == relay_parent.number {
						HrmpWatermarkUpdate::Head(commitments.hrmp_watermark)
					} else {
						HrmpWatermarkUpdate::Trunk(commitments.hrmp_watermark)
					}
				}),
				outbound_hrmp: {
					let mut outbound_hrmp = HashMap::<_, OutboundHrmpChannelModification>::new();

					let mut last_recipient = None::<ParaId>;
					for (i, message) in commitments.horizontal_messages.iter().enumerate() {
						if let Some(last) = last_recipient {
							if last >= message.recipient {
								return Err(
									FragmentValidityError::HrmpMessagesDescendingOrDuplicate(i),
								)
							}
						}

						last_recipient = Some(message.recipient);
						let record = outbound_hrmp.entry(message.recipient).or_default();

						record.bytes_submitted += message.data.len();
						record.messages_submitted += 1;
					}

					outbound_hrmp
				},
				ump_messages_sent,
				ump_bytes_sent,
				dmp_messages_processed: commitments.processed_downward_messages as _,
				code_upgrade_applied: operating_constraints
					.future_validation_code
					.map_or(false, |(at, _)| relay_parent.number >= at),
			}
		};

		validate_against_constraints(
			&operating_constraints,
			&relay_parent,
			commitments,
			persisted_validation_data,
			validation_code_hash,
			&modifications,
		)?;

		Ok(modifications)
	}

	/// Access the relay parent information.
	pub fn relay_parent(&self) -> &RelayChainBlockInfo {
		&self.relay_parent
	}

	/// Access the operating constraints
	pub fn operating_constraints(&self) -> &Constraints {
		&self.operating_constraints
	}

	/// Access the underlying prospective candidate.
	pub fn candidate(&self) -> &ProspectiveCandidate {
		&self.candidate
	}

	/// Get a cheap ref-counted copy of the underlying prospective candidate.
	pub fn candidate_clone(&self) -> Arc<ProspectiveCandidate> {
		self.candidate.clone()
	}

	/// Modifications to constraints based on the outputs of the candidate.
	pub fn constraint_modifications(&self) -> &ConstraintModifications {
		&self.modifications
	}
}

/// Validates if the candidate commitments are obeying the constraints.
pub fn validate_commitments(
	constraints: &Constraints,
	relay_parent: &RelayChainBlockInfo,
	commitments: &CandidateCommitments,
	validation_code_hash: &ValidationCodeHash,
) -> Result<(), FragmentValidityError> {
	if constraints.validation_code_hash != *validation_code_hash {
		return Err(FragmentValidityError::ValidationCodeMismatch(
			constraints.validation_code_hash,
			*validation_code_hash,
		))
	}

	if commitments.head_data.0.len() > constraints.max_head_data_size {
		return Err(FragmentValidityError::HeadDataTooLarge(
			constraints.max_head_data_size,
			commitments.head_data.0.len(),
		))
	}

	if relay_parent.number < constraints.min_relay_parent_number {
		return Err(FragmentValidityError::RelayParentTooOld(
			constraints.min_relay_parent_number,
			relay_parent.number,
		))
	}

	if commitments.new_validation_code.is_some() {
		match constraints.upgrade_restriction {
			None => {},
			Some(UpgradeRestriction::Present) =>
				return Err(FragmentValidityError::CodeUpgradeRestricted),
		}
	}

	let announced_code_size =
		commitments.new_validation_code.as_ref().map_or(0, |code| code.0.len());

	if announced_code_size > constraints.max_code_size {
		return Err(FragmentValidityError::CodeSizeTooLarge(
			constraints.max_code_size,
			announced_code_size,
		))
	}

	if commitments.horizontal_messages.len() > constraints.max_hrmp_num_per_candidate {
		return Err(FragmentValidityError::HrmpMessagesPerCandidateOverflow {
			messages_allowed: constraints.max_hrmp_num_per_candidate,
			messages_submitted: commitments.horizontal_messages.len(),
		})
	}

	Ok(())
}

fn validate_against_constraints(
	constraints: &Constraints,
	relay_parent: &RelayChainBlockInfo,
	commitments: &CandidateCommitments,
	persisted_validation_data: &PersistedValidationData,
	validation_code_hash: &ValidationCodeHash,
	modifications: &ConstraintModifications,
) -> Result<(), FragmentValidityError> {
	validate_commitments(constraints, relay_parent, commitments, validation_code_hash)?;

	let expected_pvd = PersistedValidationData {
		parent_head: constraints.required_parent.clone(),
		relay_parent_number: relay_parent.number,
		relay_parent_storage_root: relay_parent.storage_root,
		max_pov_size: constraints.max_pov_size as u32,
	};

	if expected_pvd != *persisted_validation_data {
		return Err(FragmentValidityError::PersistedValidationDataMismatch(
			expected_pvd,
			persisted_validation_data.clone(),
		))
	}
	if modifications.dmp_messages_processed == 0 {
		if constraints
			.dmp_remaining_messages
			.get(0)
			.map_or(false, |&msg_sent_at| msg_sent_at <= relay_parent.number)
		{
			return Err(FragmentValidityError::DmpAdvancementRule)
		}
	}

	if modifications.ump_messages_sent > constraints.max_ump_num_per_candidate {
		return Err(FragmentValidityError::UmpMessagesPerCandidateOverflow {
			messages_allowed: constraints.max_ump_num_per_candidate,
			messages_submitted: commitments.upward_messages.len(),
		})
	}
	constraints
		.check_modifications(&modifications)
		.map_err(FragmentValidityError::OutputsInvalid)
}

/// Trait for a hypothetical or concrete candidate, as needed when assessing the validity of a
/// potential candidate.
pub trait HypotheticalOrConcreteCandidate {
	/// Return a reference to the candidate commitments, if present.
	fn commitments(&self) -> Option<&CandidateCommitments>;
	/// Return a reference to the persisted validation data, if present.
	fn persisted_validation_data(&self) -> Option<&PersistedValidationData>;
	/// Return a reference to the validation code hash, if present.
	fn validation_code_hash(&self) -> Option<ValidationCodeHash>;
	/// Return the parent head hash.
	fn parent_head_data_hash(&self) -> Hash;
	/// Return the output head hash, if present.
	fn output_head_data_hash(&self) -> Option<Hash>;
	/// Return the relay parent hash.
	fn relay_parent(&self) -> Hash;
	/// Return the candidate hash.
	fn candidate_hash(&self) -> CandidateHash;
}

impl HypotheticalOrConcreteCandidate for HypotheticalCandidate {
	fn commitments(&self) -> Option<&CandidateCommitments> {
		self.commitments()
	}

	fn persisted_validation_data(&self) -> Option<&PersistedValidationData> {
		self.persisted_validation_data()
	}

	fn validation_code_hash(&self) -> Option<ValidationCodeHash> {
		self.validation_code_hash()
	}

	fn parent_head_data_hash(&self) -> Hash {
		self.parent_head_data_hash()
	}

	fn output_head_data_hash(&self) -> Option<Hash> {
		self.output_head_data_hash()
	}

	fn relay_parent(&self) -> Hash {
		self.relay_parent()
	}

	fn candidate_hash(&self) -> CandidateHash {
		self.candidate_hash()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use polkadot_primitives::{
		vstaging::{ClaimQueueOffset, CoreSelector, UMPSignal, UMP_SEPARATOR},
		HorizontalMessages, OutboundHrmpMessage, ValidationCode,
	};

	#[test]
	fn stack_modifications() {
		let para_a = ParaId::from(1u32);
		let para_b = ParaId::from(2u32);
		let para_c = ParaId::from(3u32);

		let a = ConstraintModifications {
			required_parent: None,
			hrmp_watermark: None,
			outbound_hrmp: {
				let mut map = HashMap::new();
				map.insert(
					para_a,
					OutboundHrmpChannelModification { bytes_submitted: 100, messages_submitted: 5 },
				);

				map.insert(
					para_b,
					OutboundHrmpChannelModification { bytes_submitted: 100, messages_submitted: 5 },
				);

				map
			},
			ump_messages_sent: 6,
			ump_bytes_sent: 1000,
			dmp_messages_processed: 5,
			code_upgrade_applied: true,
		};

		let b = ConstraintModifications {
			required_parent: None,
			hrmp_watermark: None,
			outbound_hrmp: {
				let mut map = HashMap::new();
				map.insert(
					para_b,
					OutboundHrmpChannelModification { bytes_submitted: 100, messages_submitted: 5 },
				);

				map.insert(
					para_c,
					OutboundHrmpChannelModification { bytes_submitted: 100, messages_submitted: 5 },
				);

				map
			},
			ump_messages_sent: 6,
			ump_bytes_sent: 1000,
			dmp_messages_processed: 5,
			code_upgrade_applied: true,
		};

		let mut c = a.clone();
		c.stack(&b);

		assert_eq!(
			c,
			ConstraintModifications {
				required_parent: None,
				hrmp_watermark: None,
				outbound_hrmp: {
					let mut map = HashMap::new();
					map.insert(
						para_a,
						OutboundHrmpChannelModification {
							bytes_submitted: 100,
							messages_submitted: 5,
						},
					);

					map.insert(
						para_b,
						OutboundHrmpChannelModification {
							bytes_submitted: 200,
							messages_submitted: 10,
						},
					);

					map.insert(
						para_c,
						OutboundHrmpChannelModification {
							bytes_submitted: 100,
							messages_submitted: 5,
						},
					);

					map
				},
				ump_messages_sent: 12,
				ump_bytes_sent: 2000,
				dmp_messages_processed: 10,
				code_upgrade_applied: true,
			},
		);

		let mut d = ConstraintModifications::identity();
		d.stack(&a);
		d.stack(&b);

		assert_eq!(c, d);
	}

	fn make_constraints() -> Constraints {
		let para_a = ParaId::from(1u32);
		let para_b = ParaId::from(2u32);
		let para_c = ParaId::from(3u32);

		Constraints {
			min_relay_parent_number: 5,
			max_pov_size: 1000,
			max_code_size: 1000,
			ump_remaining: 10,
			ump_remaining_bytes: 1024,
			max_ump_num_per_candidate: 5,
			dmp_remaining_messages: Vec::new(),
			hrmp_inbound: InboundHrmpLimitations { valid_watermarks: vec![6, 8] },
			hrmp_channels_out: {
				let mut map = HashMap::new();

				map.insert(
					para_a,
					OutboundHrmpChannelLimitations { messages_remaining: 5, bytes_remaining: 512 },
				);

				map.insert(
					para_b,
					OutboundHrmpChannelLimitations {
						messages_remaining: 10,
						bytes_remaining: 1024,
					},
				);

				map.insert(
					para_c,
					OutboundHrmpChannelLimitations { messages_remaining: 1, bytes_remaining: 128 },
				);

				map
			},
			max_hrmp_num_per_candidate: 5,
			required_parent: HeadData::from(vec![1, 2, 3]),
			validation_code_hash: ValidationCode(vec![4, 5, 6]).hash(),
			upgrade_restriction: None,
			future_validation_code: None,
			max_head_data_size: 1024,
		}
	}

	#[test]
	fn constraints_check_trunk_watermark() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();

		// The current hrmp watermark is kept
		modifications.hrmp_watermark = Some(HrmpWatermarkUpdate::Trunk(6));
		assert!(constraints.check_modifications(&modifications).is_ok());
		let new_constraints = constraints.apply_modifications(&modifications).unwrap();
		assert_eq!(new_constraints.hrmp_inbound.valid_watermarks, vec![6, 8]);

		modifications.hrmp_watermark = Some(HrmpWatermarkUpdate::Trunk(7));
		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::DisallowedHrmpWatermark(7)),
		);
		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::DisallowedHrmpWatermark(7)),
		);

		modifications.hrmp_watermark = Some(HrmpWatermarkUpdate::Trunk(8));
		assert!(constraints.check_modifications(&modifications).is_ok());
		let new_constraints = constraints.apply_modifications(&modifications).unwrap();
		assert_eq!(new_constraints.hrmp_inbound.valid_watermarks, vec![8]);
	}

	#[test]
	fn constraints_check_head_watermark() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();

		modifications.hrmp_watermark = Some(HrmpWatermarkUpdate::Head(5));
		assert!(constraints.check_modifications(&modifications).is_ok());
		let new_constraints = constraints.apply_modifications(&modifications).unwrap();
		assert_eq!(new_constraints.hrmp_inbound.valid_watermarks, vec![6, 8]);

		modifications.hrmp_watermark = Some(HrmpWatermarkUpdate::Head(7));
		assert!(constraints.check_modifications(&modifications).is_ok());
		let new_constraints = constraints.apply_modifications(&modifications).unwrap();
		assert_eq!(new_constraints.hrmp_inbound.valid_watermarks, vec![8]);
	}

	#[test]
	fn constraints_no_such_hrmp_channel() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		let bad_para = ParaId::from(100u32);
		modifications.outbound_hrmp.insert(
			bad_para,
			OutboundHrmpChannelModification { bytes_submitted: 0, messages_submitted: 0 },
		);

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::NoSuchHrmpChannel(bad_para)),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::NoSuchHrmpChannel(bad_para)),
		);
	}

	#[test]
	fn constraints_hrmp_messages_overflow() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		let para_a = ParaId::from(1u32);
		modifications.outbound_hrmp.insert(
			para_a,
			OutboundHrmpChannelModification { bytes_submitted: 0, messages_submitted: 6 },
		);

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::HrmpMessagesOverflow {
				para_id: para_a,
				messages_remaining: 5,
				messages_submitted: 6,
			}),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::HrmpMessagesOverflow {
				para_id: para_a,
				messages_remaining: 5,
				messages_submitted: 6,
			}),
		);
	}

	#[test]
	fn constraints_hrmp_bytes_overflow() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		let para_a = ParaId::from(1u32);
		modifications.outbound_hrmp.insert(
			para_a,
			OutboundHrmpChannelModification { bytes_submitted: 513, messages_submitted: 1 },
		);

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::HrmpBytesOverflow {
				para_id: para_a,
				bytes_remaining: 512,
				bytes_submitted: 513,
			}),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::HrmpBytesOverflow {
				para_id: para_a,
				bytes_remaining: 512,
				bytes_submitted: 513,
			}),
		);
	}

	#[test]
	fn constraints_ump_messages_overflow() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		modifications.ump_messages_sent = 11;

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::UmpMessagesOverflow {
				messages_remaining: 10,
				messages_submitted: 11,
			}),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::UmpMessagesOverflow {
				messages_remaining: 10,
				messages_submitted: 11,
			}),
		);
	}

	#[test]
	fn constraints_ump_bytes_overflow() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		modifications.ump_bytes_sent = 1025;

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::UmpBytesOverflow {
				bytes_remaining: 1024,
				bytes_submitted: 1025,
			}),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::UmpBytesOverflow {
				bytes_remaining: 1024,
				bytes_submitted: 1025,
			}),
		);
	}

	#[test]
	fn constraints_dmp_messages() {
		let mut constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		assert!(constraints.check_modifications(&modifications).is_ok());
		assert!(constraints.apply_modifications(&modifications).is_ok());

		modifications.dmp_messages_processed = 6;

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::DmpMessagesUnderflow {
				messages_remaining: 0,
				messages_processed: 6,
			}),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::DmpMessagesUnderflow {
				messages_remaining: 0,
				messages_processed: 6,
			}),
		);

		constraints.dmp_remaining_messages = vec![1, 4, 8, 10];
		modifications.dmp_messages_processed = 2;
		assert!(constraints.check_modifications(&modifications).is_ok());
		let constraints = constraints
			.apply_modifications(&modifications)
			.expect("modifications are valid");

		assert_eq!(&constraints.dmp_remaining_messages, &[8, 10]);
	}

	#[test]
	fn constraints_nonexistent_code_upgrade() {
		let constraints = make_constraints();
		let mut modifications = ConstraintModifications::identity();
		modifications.code_upgrade_applied = true;

		assert_eq!(
			constraints.check_modifications(&modifications),
			Err(ModificationError::AppliedNonexistentCodeUpgrade),
		);

		assert_eq!(
			constraints.apply_modifications(&modifications),
			Err(ModificationError::AppliedNonexistentCodeUpgrade),
		);
	}

	fn make_candidate(
		constraints: &Constraints,
		relay_parent: &RelayChainBlockInfo,
	) -> ProspectiveCandidate {
		ProspectiveCandidate {
			commitments: CandidateCommitments {
				upward_messages: Default::default(),
				horizontal_messages: Default::default(),
				new_validation_code: None,
				head_data: HeadData::from(vec![1, 2, 3, 4, 5]),
				processed_downward_messages: 0,
				hrmp_watermark: relay_parent.number,
			},
			persisted_validation_data: PersistedValidationData {
				parent_head: constraints.required_parent.clone(),
				relay_parent_number: relay_parent.number,
				relay_parent_storage_root: relay_parent.storage_root,
				max_pov_size: constraints.max_pov_size as u32,
			},
			pov_hash: Hash::repeat_byte(1),
			validation_code_hash: constraints.validation_code_hash,
		}
	}

	#[test]
	fn fragment_validation_code_mismatch() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		let expected_code = constraints.validation_code_hash;
		let got_code = ValidationCode(vec![9, 9, 9]).hash();

		candidate.validation_code_hash = got_code;

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::ValidationCodeMismatch(expected_code, got_code,)),
		)
	}

	#[test]
	fn fragment_pvd_mismatch() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let relay_parent_b = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0b),
			storage_root: Hash::repeat_byte(0xee),
		};

		let constraints = make_constraints();
		let candidate = make_candidate(&constraints, &relay_parent);

		let expected_pvd = PersistedValidationData {
			parent_head: constraints.required_parent.clone(),
			relay_parent_number: relay_parent_b.number,
			relay_parent_storage_root: relay_parent_b.storage_root,
			max_pov_size: constraints.max_pov_size as u32,
		};

		let got_pvd = candidate.persisted_validation_data.clone();

		assert_eq!(
			Fragment::new(relay_parent_b, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::PersistedValidationDataMismatch(expected_pvd, got_pvd,)),
		);
	}

	#[test]
	fn fragment_code_size_too_large() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		let max_code_size = constraints.max_code_size;
		candidate.commitments.new_validation_code = Some(vec![0; max_code_size + 1].into());

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::CodeSizeTooLarge(max_code_size, max_code_size + 1,)),
		);
	}

	#[test]
	fn ump_signals_ignored() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0xbe),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);
		let max_ump = constraints.max_ump_num_per_candidate;

		// Fill ump queue to the limit.
		candidate
			.commitments
			.upward_messages
			.try_extend((0..max_ump).map(|i| vec![i as u8]))
			.unwrap();

		// Add ump signals.
		candidate.commitments.upward_messages.force_push(UMP_SEPARATOR);
		candidate
			.commitments
			.upward_messages
			.force_push(UMPSignal::SelectCore(CoreSelector(0), ClaimQueueOffset(1)).encode());

		Fragment::new(relay_parent, constraints, Arc::new(candidate)).unwrap();
	}

	#[test]
	fn fragment_relay_parent_too_old() {
		let relay_parent = RelayChainBlockInfo {
			number: 3,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let candidate = make_candidate(&constraints, &relay_parent);

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::RelayParentTooOld(5, 3,)),
		);
	}

	#[test]
	fn fragment_hrmp_messages_overflow() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		let max_hrmp = constraints.max_hrmp_num_per_candidate;

		candidate
			.commitments
			.horizontal_messages
			.try_extend((0..max_hrmp + 1).map(|i| OutboundHrmpMessage {
				recipient: ParaId::from(i as u32),
				data: vec![1, 2, 3],
			}))
			.unwrap();

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::HrmpMessagesPerCandidateOverflow {
				messages_allowed: max_hrmp,
				messages_submitted: max_hrmp + 1,
			}),
		);
	}

	#[test]
	fn fragment_dmp_advancement_rule() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let mut constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		// Empty dmp queue is ok.
		assert!(Fragment::new(
			relay_parent.clone(),
			constraints.clone(),
			Arc::new(candidate.clone())
		)
		.is_ok());
		// Unprocessed message that was sent later is ok.
		constraints.dmp_remaining_messages = vec![relay_parent.number + 1];
		assert!(Fragment::new(
			relay_parent.clone(),
			constraints.clone(),
			Arc::new(candidate.clone())
		)
		.is_ok());

		for block_number in 0..=relay_parent.number {
			constraints.dmp_remaining_messages = vec![block_number];

			assert_eq!(
				Fragment::new(
					relay_parent.clone(),
					constraints.clone(),
					Arc::new(candidate.clone())
				),
				Err(FragmentValidityError::DmpAdvancementRule),
			);
		}

		candidate.commitments.processed_downward_messages = 1;
		assert!(Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())).is_ok());
	}

	#[test]
	fn fragment_ump_messages_overflow() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		let max_ump = constraints.max_ump_num_per_candidate;

		candidate
			.commitments
			.upward_messages
			.try_extend((0..max_ump + 1).map(|i| vec![i as u8]))
			.unwrap();

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::UmpMessagesPerCandidateOverflow {
				messages_allowed: max_ump,
				messages_submitted: max_ump + 1,
			}),
		);
	}

	#[test]
	fn fragment_code_upgrade_restricted() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let mut constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		constraints.upgrade_restriction = Some(UpgradeRestriction::Present);
		candidate.commitments.new_validation_code = Some(ValidationCode(vec![1, 2, 3]));

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::CodeUpgradeRestricted),
		);
	}

	#[test]
	fn fragment_hrmp_messages_descending_or_duplicate() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0x0a),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		candidate.commitments.horizontal_messages = HorizontalMessages::truncate_from(vec![
			OutboundHrmpMessage { recipient: ParaId::from(0 as u32), data: vec![1, 2, 3] },
			OutboundHrmpMessage { recipient: ParaId::from(0 as u32), data: vec![4, 5, 6] },
		]);

		assert_eq!(
			Fragment::new(relay_parent.clone(), constraints.clone(), Arc::new(candidate.clone())),
			Err(FragmentValidityError::HrmpMessagesDescendingOrDuplicate(1)),
		);

		candidate.commitments.horizontal_messages = HorizontalMessages::truncate_from(vec![
			OutboundHrmpMessage { recipient: ParaId::from(1 as u32), data: vec![1, 2, 3] },
			OutboundHrmpMessage { recipient: ParaId::from(0 as u32), data: vec![4, 5, 6] },
		]);

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::HrmpMessagesDescendingOrDuplicate(1)),
		);
	}

	#[test]
	fn head_data_size_too_large() {
		let relay_parent = RelayChainBlockInfo {
			number: 6,
			hash: Hash::repeat_byte(0xcc),
			storage_root: Hash::repeat_byte(0xff),
		};

		let constraints = make_constraints();
		let mut candidate = make_candidate(&constraints, &relay_parent);

		let head_data_size = constraints.max_head_data_size;
		candidate.commitments.head_data = vec![0; head_data_size + 1].into();

		assert_eq!(
			Fragment::new(relay_parent, constraints, Arc::new(candidate.clone())),
			Err(FragmentValidityError::HeadDataTooLarge(head_data_size, head_data_size + 1)),
		);
	}
}
