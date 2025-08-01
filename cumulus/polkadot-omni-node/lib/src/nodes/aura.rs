// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Cumulus.
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

use crate::{
	cli::AuthoringPolicy,
	common::{
		aura::{AuraIdT, AuraRuntimeApi},
		rpc::BuildParachainRpcExtensions,
		spec::{
			BaseNodeSpec, BuildImportQueue, ClientBlockImport, InitBlockImport, NodeSpec,
			StartConsensus,
		},
		types::{
			AccountId, Balance, Hash, Nonce, ParachainBackend, ParachainBlockImport,
			ParachainClient,
		},
		ConstructNodeRuntimeApi, NodeBlock, NodeExtraArgs,
	},
	nodes::DynNodeSpecExt,
};
use cumulus_client_collator::service::{
	CollatorService, ServiceInterface as CollatorServiceInterface,
};
#[docify::export(slot_based_colator_import)]
use cumulus_client_consensus_aura::collators::slot_based::{
	self as slot_based, Params as SlotBasedParams,
};
use cumulus_client_consensus_aura::{
	collators::{
		lookahead::{self as aura, Params as AuraParams},
		slot_based::{SlotBasedBlockImport, SlotBasedBlockImportHandle},
	},
	equivocation_import_queue::Verifier as EquivocationVerifier,
};
use cumulus_client_consensus_proposer::ProposerInterface;
use cumulus_client_consensus_relay_chain::Verifier as RelayChainVerifier;
#[allow(deprecated)]
use cumulus_client_service::CollatorSybilResistance;
use cumulus_primitives_core::{relay_chain::ValidationCode, GetParachainInfo, ParaId};
use cumulus_relay_chain_interface::{OverseerHandle, RelayChainInterface};
use futures::prelude::*;
use polkadot_primitives::CollatorPair;
use prometheus_endpoint::Registry;
use sc_client_api::BlockchainEvents;
use sc_client_db::DbHash;
use sc_consensus::{
	import_queue::{BasicQueue, Verifier as VerifierT},
	BlockImportParams, DefaultImportQueue,
};
use sc_service::{Configuration, Error, TaskManager};
use sc_telemetry::TelemetryHandle;
use sc_transaction_pool::TransactionPoolHandle;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::KeystorePtr;
use sp_runtime::{
	app_crypto::AppCrypto,
	traits::{Block as BlockT, Header as HeaderT},
};
use std::{marker::PhantomData, sync::Arc, time::Duration};

struct Verifier<Block, Client, AuraId> {
	client: Arc<Client>,
	aura_verifier: Box<dyn VerifierT<Block>>,
	relay_chain_verifier: Box<dyn VerifierT<Block>>,
	_phantom: PhantomData<AuraId>,
}

#[async_trait::async_trait]
impl<Block: BlockT, Client, AuraId> VerifierT<Block> for Verifier<Block, Client, AuraId>
where
	Client: ProvideRuntimeApi<Block> + Send + Sync,
	Client::Api: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
{
	async fn verify(
		&self,
		block_import: BlockImportParams<Block>,
	) -> Result<BlockImportParams<Block>, String> {
		if self.client.runtime_api().has_aura_api(*block_import.header.parent_hash()) {
			self.aura_verifier.verify(block_import).await
		} else {
			self.relay_chain_verifier.verify(block_import).await
		}
	}
}

/// Build the import queue for parachain runtimes that started with relay chain consensus and
/// switched to aura.
pub(crate) struct BuildRelayToAuraImportQueue<Block, RuntimeApi, AuraId, BlockImport>(
	PhantomData<(Block, RuntimeApi, AuraId, BlockImport)>,
);

impl<Block: BlockT, RuntimeApi, AuraId, BlockImport>
	BuildImportQueue<Block, RuntimeApi, BlockImport>
	for BuildRelayToAuraImportQueue<Block, RuntimeApi, AuraId, BlockImport>
where
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
	BlockImport:
		sc_consensus::BlockImport<Block, Error = sp_consensus::Error> + Send + Sync + 'static,
{
	fn build_import_queue(
		client: Arc<ParachainClient<Block, RuntimeApi>>,
		block_import: ParachainBlockImport<Block, BlockImport>,
		config: &Configuration,
		telemetry_handle: Option<TelemetryHandle>,
		task_manager: &TaskManager,
	) -> sc_service::error::Result<DefaultImportQueue<Block>> {
		let inherent_data_providers =
			move |_, _| async move { Ok(sp_timestamp::InherentDataProvider::from_system_time()) };
		let registry = config.prometheus_registry();
		let spawner = task_manager.spawn_essential_handle();

		let relay_chain_verifier =
			Box::new(RelayChainVerifier::new(client.clone(), inherent_data_providers));

		let equivocation_aura_verifier =
			EquivocationVerifier::<<AuraId as AppCrypto>::Pair, _, _, _>::new(
				client.clone(),
				inherent_data_providers,
				telemetry_handle,
			);

		let verifier = Verifier {
			client,
			aura_verifier: Box::new(equivocation_aura_verifier),
			relay_chain_verifier,
			_phantom: Default::default(),
		};

		Ok(BasicQueue::new(verifier, Box::new(block_import), None, &spawner, registry))
	}
}

/// Uses the lookahead collator to support async backing.
///
/// Start an aura powered parachain node. Some system chains use this.
pub(crate) struct AuraNode<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport>(
	pub PhantomData<(Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport)>,
);

impl<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport> Default
	for AuraNode<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport>
{
	fn default() -> Self {
		Self(Default::default())
	}
}

impl<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport> BaseNodeSpec
	for AuraNode<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport>
where
	Block: NodeBlock,
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>
		+ pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
		+ substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
	AuraId: AuraIdT + Sync,
	InitBlockImport: self::InitBlockImport<Block, RuntimeApi> + Send,
	InitBlockImport::BlockImport:
		sc_consensus::BlockImport<Block, Error = sp_consensus::Error> + 'static,
{
	type Block = Block;
	type RuntimeApi = RuntimeApi;
	type BuildImportQueue =
		BuildRelayToAuraImportQueue<Block, RuntimeApi, AuraId, InitBlockImport::BlockImport>;
	type InitBlockImport = InitBlockImport;
}

impl<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport> NodeSpec
	for AuraNode<Block, RuntimeApi, AuraId, StartConsensus, InitBlockImport>
where
	Block: NodeBlock,
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>
		+ pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
		+ substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
	AuraId: AuraIdT + Sync,
	StartConsensus: self::StartConsensus<
			Block,
			RuntimeApi,
			InitBlockImport::BlockImport,
			InitBlockImport::BlockImportAuxiliaryData,
		> + 'static,
	InitBlockImport: self::InitBlockImport<Block, RuntimeApi> + Send,
	InitBlockImport::BlockImport:
		sc_consensus::BlockImport<Block, Error = sp_consensus::Error> + 'static,
{
	type BuildRpcExtensions = BuildParachainRpcExtensions<Block, RuntimeApi>;
	type StartConsensus = StartConsensus;
	const SYBIL_RESISTANCE: CollatorSybilResistance = CollatorSybilResistance::Resistant;
}

pub fn new_aura_node_spec<Block, RuntimeApi, AuraId>(
	extra_args: &NodeExtraArgs,
) -> Box<dyn DynNodeSpecExt>
where
	Block: NodeBlock,
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>
		+ pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
		+ substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>
		+ GetParachainInfo<Block>,
	AuraId: AuraIdT + Sync,
{
	if extra_args.authoring_policy == AuthoringPolicy::SlotBased {
		Box::new(AuraNode::<
			Block,
			RuntimeApi,
			AuraId,
			StartSlotBasedAuraConsensus<Block, RuntimeApi, AuraId>,
			StartSlotBasedAuraConsensus<Block, RuntimeApi, AuraId>,
		>::default())
	} else {
		Box::new(AuraNode::<
			Block,
			RuntimeApi,
			AuraId,
			StartLookaheadAuraConsensus<Block, RuntimeApi, AuraId>,
			ClientBlockImport,
		>::default())
	}
}

/// Start consensus using the lookahead aura collator.
pub(crate) struct StartSlotBasedAuraConsensus<Block, RuntimeApi, AuraId>(
	PhantomData<(Block, RuntimeApi, AuraId)>,
);

impl<Block: BlockT<Hash = DbHash>, RuntimeApi, AuraId>
	StartSlotBasedAuraConsensus<Block, RuntimeApi, AuraId>
where
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
{
	#[docify::export_content]
	fn launch_slot_based_collator<CIDP, CHP, Proposer, CS, Spawner>(
		params_with_export: SlotBasedParams<
			Block,
			ParachainBlockImport<
				Block,
				SlotBasedBlockImport<
					Block,
					Arc<ParachainClient<Block, RuntimeApi>>,
					ParachainClient<Block, RuntimeApi>,
				>,
			>,
			CIDP,
			ParachainClient<Block, RuntimeApi>,
			ParachainBackend<Block>,
			Arc<dyn RelayChainInterface>,
			CHP,
			Proposer,
			CS,
			Spawner,
		>,
	) where
		CIDP: CreateInherentDataProviders<Block, ()> + 'static,
		CIDP::InherentDataProviders: Send,
		CHP: cumulus_client_consensus_common::ValidationCodeHashProvider<Hash> + Send + 'static,
		Proposer: ProposerInterface<Block> + Send + Sync + 'static,
		CS: CollatorServiceInterface<Block> + Send + Sync + Clone + 'static,
		Spawner: SpawnNamed,
	{
		slot_based::run::<Block, <AuraId as AppCrypto>::Pair, _, _, _, _, _, _, _, _, _>(
			params_with_export,
		);
	}
}

impl<Block: BlockT<Hash = DbHash>, RuntimeApi, AuraId>
	StartConsensus<
		Block,
		RuntimeApi,
		SlotBasedBlockImport<
			Block,
			Arc<ParachainClient<Block, RuntimeApi>>,
			ParachainClient<Block, RuntimeApi>,
		>,
		SlotBasedBlockImportHandle<Block>,
	> for StartSlotBasedAuraConsensus<Block, RuntimeApi, AuraId>
where
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
{
	fn start_consensus(
		client: Arc<ParachainClient<Block, RuntimeApi>>,
		block_import: ParachainBlockImport<
			Block,
			SlotBasedBlockImport<
				Block,
				Arc<ParachainClient<Block, RuntimeApi>>,
				ParachainClient<Block, RuntimeApi>,
			>,
		>,
		prometheus_registry: Option<&Registry>,
		telemetry: Option<TelemetryHandle>,
		task_manager: &TaskManager,
		relay_chain_interface: Arc<dyn RelayChainInterface>,
		transaction_pool: Arc<TransactionPoolHandle<Block, ParachainClient<Block, RuntimeApi>>>,
		keystore: KeystorePtr,
		relay_chain_slot_duration: Duration,
		para_id: ParaId,
		collator_key: CollatorPair,
		_overseer_handle: OverseerHandle,
		announce_block: Arc<dyn Fn(Hash, Option<Vec<u8>>) + Send + Sync>,
		backend: Arc<ParachainBackend<Block>>,
		node_extra_args: NodeExtraArgs,
		block_import_handle: SlotBasedBlockImportHandle<Block>,
	) -> Result<(), Error> {
		let proposer = sc_basic_authorship::ProposerFactory::with_proof_recording(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool,
			prometheus_registry,
			telemetry.clone(),
		);

		let collator_service = CollatorService::new(
			client.clone(),
			Arc::new(task_manager.spawn_handle()),
			announce_block,
			client.clone(),
		);

		let client_for_aura = client.clone();
		let params = SlotBasedParams {
			create_inherent_data_providers: move |_, ()| async move { Ok(()) },
			block_import,
			para_client: client.clone(),
			para_backend: backend.clone(),
			relay_client: relay_chain_interface,
			relay_chain_slot_duration,
			code_hash_provider: move |block_hash| {
				client_for_aura.code_at(block_hash).ok().map(|c| ValidationCode::from(c).hash())
			},
			keystore,
			collator_key,
			para_id,
			proposer,
			collator_service,
			authoring_duration: Duration::from_millis(2000),
			reinitialize: false,
			slot_offset: Duration::from_secs(1),
			block_import_handle,
			spawner: task_manager.spawn_handle(),
			export_pov: node_extra_args.export_pov,
			max_pov_percentage: node_extra_args.max_pov_percentage,
		};

		// We have a separate function only to be able to use `docify::export` on this piece of
		// code.

		Self::launch_slot_based_collator(params);

		Ok(())
	}
}

impl<Block: BlockT<Hash = DbHash>, RuntimeApi, AuraId> InitBlockImport<Block, RuntimeApi>
	for StartSlotBasedAuraConsensus<Block, RuntimeApi, AuraId>
where
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
{
	type BlockImport = SlotBasedBlockImport<
		Block,
		Arc<ParachainClient<Block, RuntimeApi>>,
		ParachainClient<Block, RuntimeApi>,
	>;
	type BlockImportAuxiliaryData = SlotBasedBlockImportHandle<Block>;

	fn init_block_import(
		client: Arc<ParachainClient<Block, RuntimeApi>>,
	) -> sc_service::error::Result<(Self::BlockImport, Self::BlockImportAuxiliaryData)> {
		Ok(SlotBasedBlockImport::new(client.clone(), client))
	}
}

/// Wait for the Aura runtime API to appear on chain.
/// This is useful for chains that started out without Aura. Components that
/// are depending on Aura functionality will wait until Aura appears in the runtime.
async fn wait_for_aura<Block: BlockT, RuntimeApi, AuraId>(
	client: Arc<ParachainClient<Block, RuntimeApi>>,
) where
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
{
	let finalized_hash = client.chain_info().finalized_hash;
	if client.runtime_api().has_aura_api(finalized_hash) {
		return;
	};

	let mut stream = client.finality_notification_stream();
	while let Some(notification) = stream.next().await {
		if client.runtime_api().has_aura_api(notification.hash) {
			return;
		}
	}
}

/// Start consensus using the lookahead aura collator.
pub(crate) struct StartLookaheadAuraConsensus<Block, RuntimeApi, AuraId>(
	PhantomData<(Block, RuntimeApi, AuraId)>,
);

impl<Block: BlockT<Hash = DbHash>, RuntimeApi, AuraId>
	StartConsensus<Block, RuntimeApi, Arc<ParachainClient<Block, RuntimeApi>>, ()>
	for StartLookaheadAuraConsensus<Block, RuntimeApi, AuraId>
where
	RuntimeApi: ConstructNodeRuntimeApi<Block, ParachainClient<Block, RuntimeApi>>,
	RuntimeApi::RuntimeApi: AuraRuntimeApi<Block, AuraId>,
	AuraId: AuraIdT + Sync,
{
	fn start_consensus(
		client: Arc<ParachainClient<Block, RuntimeApi>>,
		block_import: ParachainBlockImport<Block, Arc<ParachainClient<Block, RuntimeApi>>>,
		prometheus_registry: Option<&Registry>,
		telemetry: Option<TelemetryHandle>,
		task_manager: &TaskManager,
		relay_chain_interface: Arc<dyn RelayChainInterface>,
		transaction_pool: Arc<TransactionPoolHandle<Block, ParachainClient<Block, RuntimeApi>>>,
		keystore: KeystorePtr,
		relay_chain_slot_duration: Duration,
		para_id: ParaId,
		collator_key: CollatorPair,
		overseer_handle: OverseerHandle,
		announce_block: Arc<dyn Fn(Hash, Option<Vec<u8>>) + Send + Sync>,
		backend: Arc<ParachainBackend<Block>>,
		node_extra_args: NodeExtraArgs,
		_: (),
	) -> Result<(), Error> {
		let proposer = sc_basic_authorship::ProposerFactory::with_proof_recording(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool,
			prometheus_registry,
			telemetry.clone(),
		);

		let collator_service = CollatorService::new(
			client.clone(),
			Arc::new(task_manager.spawn_handle()),
			announce_block,
			client.clone(),
		);

		let params = aura::ParamsWithExport {
			export_pov: node_extra_args.export_pov,
			params: AuraParams {
				create_inherent_data_providers: move |_, ()| async move { Ok(()) },
				block_import,
				para_client: client.clone(),
				para_backend: backend,
				relay_client: relay_chain_interface,
				code_hash_provider: {
					let client = client.clone();
					move |block_hash| {
						client.code_at(block_hash).ok().map(|c| ValidationCode::from(c).hash())
					}
				},
				keystore,
				collator_key,
				para_id,
				overseer_handle,
				relay_chain_slot_duration,
				proposer,
				collator_service,
				authoring_duration: Duration::from_millis(2000),
				reinitialize: false,
				max_pov_percentage: node_extra_args.max_pov_percentage,
			},
		};

		let fut = async move {
			wait_for_aura(client).await;
			aura::run_with_export::<Block, <AuraId as AppCrypto>::Pair, _, _, _, _, _, _, _, _>(
				params,
			)
			.await;
		};
		task_manager.spawn_essential_handle().spawn("aura", None, fut);

		Ok(())
	}
}
