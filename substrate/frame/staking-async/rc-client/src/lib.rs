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

//! The client for the relay chain, intended to be used in AssetHub.
//!
//! The counter-part for this pallet is `pallet-staking-async-ah-client` on the relay chain.
//!
//! This documentation is divided into the following sections:
//!
//! 1. Incoming messages: the messages that we receive from the relay chian.
//! 2. Outgoing messages: the messaged that we sent to the relay chain.
//! 3. Local interfaces: the interfaces that we expose to other pallets in the runtime.
//!
//! ## Incoming Messages
//!
//! All incoming messages are handled via [`Call`]. They are all gated to be dispatched only by the
//! relay chain origin, as per [`Config::RelayChainOrigin`].
//!
//! After potential queuing, they are passed to pallet-staking-async via [`AHStakingInterface`].
//!
//! The calls are:
//!
//! * [`Call::relay_session_report`]: A report from the relay chain, indicating the end of a
//!   session. We allow ourselves to know an implementation detail: **The ending of session `x`
//!   always implies start of session `x+1` and planning of session `x+2`.** This allows us to have
//!   just one message per session.
//!
//! > Note that in the code, due to historical reasons, planning of a new session is called
//! > `new_session`.
//!
//! * [`Call::relay_new_offence`]: A report of one or more offences on the relay chain.
//!
//! ## Outgoing Messages
//!
//! The outgoing messages are expressed in [`SendToRelayChain`].
//!
//! ## Local Interfaces
//!
//! Within this pallet, we need to talk to the staking-async pallet in AH. This is done via
//! [`AHStakingInterface`] trait.
//!
//! The staking pallet in AH has no communication with session pallet whatsoever, therefore its
//! implementation of `SessionManager`, and it associated type `SessionInterface` no longer exists.
//! Moreover, pallet-staking-async no longer has a notion of timestamp locally, and only relies in
//! the timestamp passed in in the `SessionReport`.
//!
//! ## Shared Types
//!
//! Note that a number of types need to be shared between this crate and `ah-client`. For now, as a
//! convention, they are kept in this crate. This can later be decoupled into a shared crate, or
//! `sp-staking`.
//!
//! TODO: the rest should go to staking-async docs.
//!
//! ## Session Change
//!
//! Further details of how the session change works follows. These details are important to how
//! `pallet-staking-async` should rotate sessions/eras going forward.
//!
//! ### Synchronous Model
//!
//! Let's first consider the old school model, when staking and session lived in the same runtime.
//! Assume 3 sessions is one era.
//!
//! The session pallet issues the following events:
//!
//! end_session / start_session / new_session (plan session)
//!
//! * end 0, start 1, plan 2
//! * end 1, start 2, plan 3 (new validator set returned)
//! * end 2, start 3 (new validator set activated), plan 4
//! * end 3, start 4, plan 5
//! * end 4, start 5, plan 6 (ah-client to already return validator set) and so on.
//!
//! Staking should then do the following:
//!
//! * once a request to plan session 3 comes in, it must return a validator set. This is queued
//!   internally in the session pallet, and is enacted later.
//! * at the same time, staking increases its notion of `current_era` by 1. Yet, `active_era` is
//!   intact. This is because the validator elected for era n+1 are not yet active in the session
//!   pallet.
//! * once a request to _start_ session 3 comes in, staking will rotate its `active_era` to also be
//!   incremented to n+1.
//!
//! ### Asynchronous Model
//!
//! Now, if staking lives in AH and the session pallet lives in the relay chain, how will this look
//! like?
//!
//! Staking knows that by the time the relay-chain session index `3` (and later on `6` and so on) is
//! _planned_, it must have already returned a validator set via XCM.
//!
//! conceptually, staking must:
//!
//! - listen to the [`SessionReport`]s coming in, and start a new staking election such that we can
//!   be sure it is delivered to the RC well before the the message for planning session 3 received.
//! - Staking should know that, regardless of the timing, these validators correspond to session 3,
//!   and an upcoming era.
//! - Staking will keep these pending validators internally within its state.
//! - Once the message to start session 3 is received, staking will act upon it locally.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::{vec, vec::Vec};
use core::fmt::Display;
use frame_support::pallet_prelude::*;
use sp_runtime::{traits::Convert, Perbill};
use sp_staking::SessionIndex;
use xcm::latest::{send_xcm, Location, SendError, SendXcm, Xcm};

/// Export everything needed for the pallet to be used in the runtime.
pub use pallet::*;

const LOG_TARGET: &str = "runtime::staking-async::rc-client";

// syntactic sugar for logging.
#[macro_export]
macro_rules! log {
	($level:tt, $patter:expr $(, $values:expr)* $(,)?) => {
		log::$level!(
			target: $crate::LOG_TARGET,
			concat!("[{:?}] ⬆️ ", $patter), <frame_system::Pallet<T>>::block_number() $(, $values)*
		)
	};
}

/// The communication trait of `pallet-staking-async-rc-client` -> `relay-chain`.
///
/// This trait should only encapsulate our _outgoing_ communication to the RC. Any incoming
/// communication comes it directly via our calls.
///
/// In a real runtime, this is implemented via XCM calls, much like how the core-time pallet works.
/// In a test runtime, it can be wired to direct function calls.
pub trait SendToRelayChain {
	/// The validator account ids.
	type AccountId;

	/// Send a new validator set report to relay chain.
	fn validator_set(report: ValidatorSetReport<Self::AccountId>);
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, TypeInfo)]
/// A report about a new validator set. This is sent from AH -> RC.
pub struct ValidatorSetReport<AccountId> {
	/// The new validator set.
	pub new_validator_set: Vec<AccountId>,
	/// The id of this validator set.
	///
	/// Is an always incrementing identifier for this validator set, the activation of which can be
	/// later pointed to in a `SessionReport`.
	///
	/// Implementation detail: within `pallet-staking-async`, this is always set to the
	/// `planning-era` (aka. `CurrentEra`).
	pub id: u32,
	/// Signal the relay chain that it can prune up to this session, and enough eras have passed.
	///
	/// This can always have a safety buffer. For example, whatever is a sane value, it can be
	/// `value - 5`.
	pub prune_up_to: Option<SessionIndex>,
	/// Same semantics as [`SessionReport::leftover`].
	pub leftover: bool,
}

impl<AccountId: core::fmt::Debug> core::fmt::Debug for ValidatorSetReport<AccountId> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ValidatorSetReport")
			.field("new_validator_set", &self.new_validator_set)
			.field("id", &self.id)
			.field("prune_up_to", &self.prune_up_to)
			.field("leftover", &self.leftover)
			.finish()
	}
}

impl<AccountId> core::fmt::Display for ValidatorSetReport<AccountId> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ValidatorSetReport")
			.field("new_validator_set", &self.new_validator_set.len())
			.field("id", &self.id)
			.field("prune_up_to", &self.prune_up_to)
			.field("leftover", &self.leftover)
			.finish()
	}
}

impl<AccountId> ValidatorSetReport<AccountId> {
	/// A new instance of self that is terminal. This is useful when we want to send everything in
	/// one go.
	pub fn new_terminal(
		new_validator_set: Vec<AccountId>,
		id: u32,
		prune_up_to: Option<SessionIndex>,
	) -> Self {
		Self { new_validator_set, id, prune_up_to, leftover: false }
	}

	/// Merge oneself with another instance.
	pub fn merge(mut self, other: Self) -> Result<Self, UnexpectedKind> {
		if self.id != other.id || self.prune_up_to != other.prune_up_to {
			// Must be some bug -- don't merge.
			return Err(UnexpectedKind::ValidatorSetIntegrityFailed);
		}
		self.new_validator_set.extend(other.new_validator_set);
		self.leftover = other.leftover;
		Ok(self)
	}

	/// Split self into chunks of `chunk_size` element.
	pub fn split(self, chunk_size: usize) -> Vec<Self>
	where
		AccountId: Clone,
	{
		let splitted_points = self.new_validator_set.chunks(chunk_size.max(1)).map(|x| x.to_vec());
		let mut parts = splitted_points
			.into_iter()
			.map(|new_validator_set| Self { new_validator_set, leftover: true, ..self })
			.collect::<Vec<_>>();
		if let Some(x) = parts.last_mut() {
			x.leftover = false
		}
		parts
	}
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, TypeInfo, MaxEncodedLen)]
/// The information that is sent from RC -> AH on session end.
pub struct SessionReport<AccountId> {
	/// The session that is ending.
	///
	/// This always implies start of `end_index + 1`, and planning of `end_index + 2`.
	pub end_index: SessionIndex,
	/// All of the points that validators have accumulated.
	///
	/// This can be either from block authoring, or from parachain consensus, or anything else.
	pub validator_points: Vec<(AccountId, u32)>,
	/// If none, it means no new validator set was activated as a part of this session.
	///
	/// If `Some((timestamp, id))`, it means that the new validator set was activated at the given
	/// timestamp, and the id of the validator set is `id`.
	///
	/// This `id` is what was previously communicated to the RC as a part of
	/// [`ValidatorSetReport::id`].
	pub activation_timestamp: Option<(u64, u32)>,
	/// If this session report is self-contained, then it is false.
	///
	/// If this session report has some leftover, it should not be acted upon until a subsequent
	/// message with `leftover = true` comes in. The client pallets should handle this queuing.
	///
	/// This is in place to future proof us against possibly needing to send multiple rounds of
	/// messages to convey all of the `validator_points`.
	///
	/// Upon processing, this should always be true, and it should be ignored.
	pub leftover: bool,
}

impl<AccountId: core::fmt::Debug> core::fmt::Debug for SessionReport<AccountId> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("SessionReport")
			.field("end_index", &self.end_index)
			.field("validator_points", &self.validator_points)
			.field("activation_timestamp", &self.activation_timestamp)
			.field("leftover", &self.leftover)
			.finish()
	}
}

impl<AccountId> core::fmt::Display for SessionReport<AccountId> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("SessionReport")
			.field("end_index", &self.end_index)
			.field("validator_points", &self.validator_points.len())
			.field("activation_timestamp", &self.activation_timestamp)
			.field("leftover", &self.leftover)
			.finish()
	}
}

impl<AccountId> SessionReport<AccountId> {
	/// A new instance of self that is terminal. This is useful when we want to send everything in
	/// one go.
	pub fn new_terminal(
		end_index: SessionIndex,
		validator_points: Vec<(AccountId, u32)>,
		activation_timestamp: Option<(u64, u32)>,
	) -> Self {
		Self { end_index, validator_points, activation_timestamp, leftover: false }
	}

	/// Merge oneself with another instance.
	pub fn merge(mut self, other: Self) -> Result<Self, UnexpectedKind> {
		if self.end_index != other.end_index ||
			self.activation_timestamp != other.activation_timestamp
		{
			// Must be some bug -- don't merge.
			return Err(UnexpectedKind::SessionReportIntegrityFailed);
		}
		self.validator_points.extend(other.validator_points);
		self.leftover = other.leftover;
		Ok(self)
	}

	/// Split oneself into `count` number of pieces.
	pub fn split(self, chunk_size: usize) -> Vec<Self>
	where
		AccountId: Clone,
	{
		let splitted_points = self.validator_points.chunks(chunk_size.max(1)).map(|x| x.to_vec());
		let mut parts = splitted_points
			.into_iter()
			.map(|validator_points| Self { validator_points, leftover: true, ..self })
			.collect::<Vec<_>>();
		if let Some(x) = parts.last_mut() {
			x.leftover = false
		}
		parts
	}
}

/// A trait to encapsulate messages between RC and AH that can be splitted into smaller chunks.
///
/// Implemented for [`SessionReport`] and [`ValidatorSetReport`].
#[allow(clippy::len_without_is_empty)]
pub trait SplittableMessage: Sized {
	/// Split yourself into pieces of `chunk_size` size.
	fn split_by(self, chunk_size: usize) -> Vec<Self>;

	/// Current length of the message.
	fn len(&self) -> usize;
}

impl<AccountId: Clone> SplittableMessage for SessionReport<AccountId> {
	fn split_by(self, chunk_size: usize) -> Vec<Self> {
		self.split(chunk_size)
	}
	fn len(&self) -> usize {
		self.validator_points.len()
	}
}

impl<AccountId: Clone> SplittableMessage for ValidatorSetReport<AccountId> {
	fn split_by(self, chunk_size: usize) -> Vec<Self> {
		self.split(chunk_size)
	}
	fn len(&self) -> usize {
		self.new_validator_set.len()
	}
}

/// Common utility to send XCM messages that can use [`SplittableMessage`].
///
/// It can be used both in the RC and AH. `Message` is the splittable message type, and `ToXcm`
/// should be configured by the user, converting `message` to a valida `Xcm<()>`. It should utilize
/// the correct call indices, which we only know at the runtime level.
pub struct XCMSender<Sender, Destination, Message, ToXcm>(
	core::marker::PhantomData<(Sender, Destination, Message, ToXcm)>,
);

impl<Sender, Destination, Message, ToXcm> XCMSender<Sender, Destination, Message, ToXcm>
where
	Sender: SendXcm,
	Destination: Get<Location>,
	Message: SplittableMessage + Display + Clone + Encode,
	ToXcm: Convert<Message, Xcm<()>>,
{
	/// Safe send method to send a `message`, while validating it and using [`SplittableMessage`] to
	/// split it into smaller pieces if XCM validation fails with `ExceedsMaxMessageSize`. It will
	/// fail on other errors.
	///
	/// It will only emit some logs, and has no return value. This is used in the runtime, so it
	/// cannot deposit any events at this level.
	pub fn split_then_send(message: Message, maybe_max_steps: Option<u32>) {
		let message_type_name = core::any::type_name::<Message>();
		let dest = Destination::get();
		let xcms = match Self::prepare(message, maybe_max_steps) {
			Ok(x) => x,
			Err(e) => {
				log::error!(target: "runtime::rc-client", "📨 Failed to split message {}: {:?}", message_type_name, e);
				return;
			},
		};

		for (idx, xcm) in xcms.into_iter().enumerate() {
			log::debug!(target: "runtime::rc-client", "📨 sending {} message index {}, size: {:?}", message_type_name, idx, xcm.encoded_size());
			let result = send_xcm::<Sender>(dest.clone(), xcm);
			match result {
				Ok(_) => {
					log::debug!(target: "runtime::rc-client", "📨 Successfully sent {} message part {} to relay chain", message_type_name,  idx)
				},
				Err(e) => {
					log::error!(target: "runtime::rc-client", "📨 Failed to send {} message to relay chain: {:?}", message_type_name, e)
				},
			}
		}
	}

	fn prepare(message: Message, maybe_max_steps: Option<u32>) -> Result<Vec<Xcm<()>>, SendError> {
		// initial chunk size is the entire thing, so it will be a vector of 1 item.
		let mut chunk_size = message.len();
		let mut steps = 0;

		loop {
			let current_messages = message.clone().split_by(chunk_size);

			// the first message is the heaviest, the last one might be smaller.
			let first_message = if let Some(r) = current_messages.first() {
				r
			} else {
				log::debug!(target: "runtime::staking-async::xcm", "📨 unexpected: no messages to send");
				return Ok(vec![]);
			};

			log::debug!(
				target: "runtime::staking-async::xcm",
				"📨 step: {:?}, chunk_size: {:?}, message_size: {:?}",
				steps,
				chunk_size,
				first_message.encoded_size(),
			);

			let first_xcm = ToXcm::convert(first_message.clone());
			match <Sender as SendXcm>::validate(&mut Some(Destination::get()), &mut Some(first_xcm))
			{
				Ok((_ticket, price)) => {
					log::debug!(target: "runtime::staking-async::xcm", "📨 validated, price: {:?}", price);
					return Ok(current_messages.into_iter().map(ToXcm::convert).collect::<Vec<_>>());
				},
				Err(SendError::ExceedsMaxMessageSize) => {
					log::debug!(target: "runtime::staking-async::xcm", "📨 ExceedsMaxMessageSize -- reducing chunk_size");
					chunk_size = chunk_size.saturating_div(2);
					steps += 1;
					if maybe_max_steps.is_some_and(|max_steps| steps > max_steps) ||
						chunk_size.is_zero()
					{
						log::error!(target: "runtime::staking-async::xcm", "📨 Exceeded max steps or chunk_size = 0");
						return Err(SendError::ExceedsMaxMessageSize);
					} else {
						// try again with the new `chunk_size`
						continue;
					}
				},
				Err(other) => {
					log::error!(target: "runtime::staking-async::xcm", "📨 other error -- cannot send XCM: {:?}", other);
					return Err(other);
				},
			}
		}
	}
}

/// Our communication trait of `pallet-staking-async-rc-client` -> `pallet-staking-async`.
///
/// This is merely a shorthand to avoid tightly-coupling the staking pallet to this pallet. It
/// limits what we can say to `pallet-staking-async` to only these functions.
pub trait AHStakingInterface {
	/// The validator account id type.
	type AccountId;
	/// Maximum number of validators that the staking system may have.
	type MaxValidatorSet: Get<u32>;

	/// New session report from the relay chain.
	fn on_relay_session_report(report: SessionReport<Self::AccountId>) -> Weight;

	/// Return the weight of `on_relay_session_report` call without executing it.
	///
	/// This will return the worst case estimate of the weight. The actual execution will return the
	/// accurate amount.
	fn weigh_on_relay_session_report(report: &SessionReport<Self::AccountId>) -> Weight;

	/// Report one or more offences on the relay chain.
	fn on_new_offences(
		slash_session: SessionIndex,
		offences: Vec<Offence<Self::AccountId>>,
	) -> Weight;

	/// Return the weight of `on_new_offences` call without executing it.
	///
	/// This will return the worst case estimate of the weight. The actual execution will return the
	/// accurate amount.
	fn weigh_on_new_offences(
		slash_session: SessionIndex,
		offences: &[Offence<Self::AccountId>],
	) -> Weight;
}

/// The communication trait of `pallet-staking-async` -> `pallet-staking-async-rc-client`.
pub trait RcClientInterface {
	/// The validator account ids.
	type AccountId;

	/// Report a new validator set.
	fn validator_set(new_validator_set: Vec<Self::AccountId>, id: u32, prune_up_tp: Option<u32>);
}

/// An offence on the relay chain. Based on [`sp_staking::offence::OffenceDetails`].
#[derive(Encode, Decode, DecodeWithMemTracking, Debug, Clone, PartialEq, TypeInfo)]
pub struct Offence<AccountId> {
	/// The offender.
	pub offender: AccountId,
	/// Those who have reported this offence.
	pub reporters: Vec<AccountId>,
	/// The amount that they should be slashed.
	pub slash_fraction: Perbill,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec;
	use frame_system::pallet_prelude::*;

	/// The in-code storage version.
	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	/// An incomplete incoming session report that we have not acted upon yet.
	// Note: this can remain unbounded, as the internals of `AHStakingInterface` is benchmarked, and
	// is worst case.
	#[pallet::storage]
	#[pallet::unbounded]
	pub type IncompleteSessionReport<T: Config> =
		StorageValue<_, SessionReport<T::AccountId>, OptionQuery>;

	/// The last session report's `end_index` that we have acted upon.
	///
	/// This allows this pallet to ensure a sequentially increasing sequence of session reports
	/// passed to staking.
	///
	/// Note that with the XCM being the backbone of communication, we have a guarantee on the
	/// ordering of messages. As long as the RC sends session reports in order, we _eventually_
	/// receive them in the same correct order as well.
	#[pallet::storage]
	pub type LastSessionReportEndingIndex<T: Config> = StorageValue<_, SessionIndex, OptionQuery>;

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// An origin type that allows us to be sure a call is being dispatched by the relay chain.
		///
		/// It be can be configured to something like `Root` or relay chain or similar.
		type RelayChainOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Our communication handle to the local staking pallet.
		type AHStakingInterface: AHStakingInterface<AccountId = Self::AccountId>;

		/// Our communication handle to the relay chain.
		type SendToRelayChain: SendToRelayChain<AccountId = Self::AccountId>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A said session report was received.
		SessionReportReceived {
			end_index: SessionIndex,
			activation_timestamp: Option<(u64, u32)>,
			validator_points_counts: u32,
			leftover: bool,
		},
		/// A new offence was reported.
		OffenceReceived { slash_session: SessionIndex, offences_count: u32 },
		/// Something occurred that should never happen under normal operation.
		/// Logged as an event for fail-safe observability.
		Unexpected(UnexpectedKind),
	}

	/// Represents unexpected or invariant-breaking conditions encountered during execution.
	///
	/// These variants are emitted as [`Event::Unexpected`] and indicate a defensive check has
	/// failed. While these should never occur under normal operation, they are useful for
	/// diagnosing issues in production or test environments.
	#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, TypeInfo, RuntimeDebug)]
	pub enum UnexpectedKind {
		/// We could not merge the chunks, and therefore dropped the session report.
		SessionReportIntegrityFailed,
		/// We could not merge the chunks, and therefore dropped the validator set.
		ValidatorSetIntegrityFailed,
		/// The received session index is more than what we expected.
		SessionSkipped,
		/// A session in the past was received. This will not raise any errors, just emit an event
		/// and stop processing the report.
		SessionAlreadyProcessed,
	}

	impl<T: Config> RcClientInterface for Pallet<T> {
		type AccountId = T::AccountId;

		fn validator_set(
			new_validator_set: Vec<Self::AccountId>,
			id: u32,
			prune_up_tp: Option<u32>,
		) {
			let report = ValidatorSetReport::new_terminal(new_validator_set, id, prune_up_tp);
			T::SendToRelayChain::validator_set(report);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Called to indicate the start of a new session on the relay chain.
		#[pallet::call_index(0)]
		#[pallet::weight(
			// `LastSessionReportEndingIndex`: rw
			// `IncompleteSessionReport`: rw
			T::DbWeight::get().reads_writes(2, 2) + T::AHStakingInterface::weigh_on_relay_session_report(report)
		)]
		pub fn relay_session_report(
			origin: OriginFor<T>,
			report: SessionReport<T::AccountId>,
		) -> DispatchResultWithPostInfo {
			log!(debug, "Received session report: {}", report);
			T::RelayChainOrigin::ensure_origin_or_root(origin)?;
			let local_weight = T::DbWeight::get().reads_writes(2, 2);

			match LastSessionReportEndingIndex::<T>::get() {
				None => {
					// first session report post genesis, okay.
				},
				Some(last) if report.end_index == last + 1 => {
					// incremental -- good
				},
				Some(last) if report.end_index > last + 1 => {
					// deposit a warning event, but proceed
					Self::deposit_event(Event::Unexpected(UnexpectedKind::SessionSkipped));
					log!(
						warn,
						"Session report end index is more than expected. last_index={:?}, report.index={:?}",
						last,
						report.end_index
					);
				},
				Some(past) => {
					log!(
						error,
						"Session report end index is not valid. last_index={:?}, report.index={:?}",
						past,
						report.end_index
					);
					Self::deposit_event(Event::Unexpected(UnexpectedKind::SessionAlreadyProcessed));
					IncompleteSessionReport::<T>::kill();
					return Ok(Some(local_weight).into());
				},
			}

			Self::deposit_event(Event::SessionReportReceived {
				end_index: report.end_index,
				activation_timestamp: report.activation_timestamp,
				validator_points_counts: report.validator_points.len() as u32,
				leftover: report.leftover,
			});

			// If we have anything previously buffered, then merge it.
			let maybe_new_session_report = match IncompleteSessionReport::<T>::take() {
				Some(old) => old.merge(report.clone()),
				None => Ok(report),
			};

			if let Err(e) = maybe_new_session_report {
				Self::deposit_event(Event::Unexpected(e));
				debug_assert!(
					IncompleteSessionReport::<T>::get().is_none(),
					"we have ::take() it above, we don't want to keep the old data"
				);
				return Ok(().into());
			}
			let new_session_report = maybe_new_session_report.expect("checked above; qed");

			if new_session_report.leftover {
				// this is still not final -- buffer it.
				IncompleteSessionReport::<T>::put(new_session_report);
				Ok(().into())
			} else {
				// this is final, report it.
				LastSessionReportEndingIndex::<T>::put(new_session_report.end_index);
				let weight = T::AHStakingInterface::on_relay_session_report(new_session_report);
				Ok((Some(local_weight + weight)).into())
			}
		}

		/// Called to report one or more new offenses on the relay chain.
		#[pallet::call_index(1)]
		#[pallet::weight(
			// events are free
			// origin check is negligible.
			T::AHStakingInterface::weigh_on_new_offences(*slash_session, offences)
		)]
		pub fn relay_new_offence(
			origin: OriginFor<T>,
			slash_session: SessionIndex,
			offences: Vec<Offence<T::AccountId>>,
		) -> DispatchResultWithPostInfo {
			log!(info, "Received new offence at slash_session: {:?}", slash_session);
			T::RelayChainOrigin::ensure_origin_or_root(origin)?;

			Self::deposit_event(Event::OffenceReceived {
				slash_session,
				offences_count: offences.len() as u32,
			});

			let weight = T::AHStakingInterface::on_new_offences(slash_session, offences);
			Ok(Some(weight).into())
		}
	}
}
