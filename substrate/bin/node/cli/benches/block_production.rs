// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use polkadot_sdk::*;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use kitchensink_runtime::{constants::currency::*, BalancesCall};
use node_cli::service::{create_extrinsic, FullClient};
use polkadot_sdk::sc_service::config::{ExecutorConfiguration, RpcConfiguration};
use sc_block_builder::{BlockBuilderBuilder, BuiltBlock};
use sc_consensus::{
	block_import::{BlockImportParams, ForkChoiceStrategy},
	BlockImport, StateAction,
};
use sc_service::{
	config::{
		BlocksPruning, DatabaseSource, KeystoreConfig, NetworkConfiguration, OffchainWorkerConfig,
		PruningMode, RpcBatchRequestConfig, WasmExecutionMethod, WasmtimeInstantiationStrategy,
	},
	BasePath, Configuration, Role,
};
use sp_blockchain::{ApplyExtrinsicFailed::Validity, Error::ApplyExtrinsicFailed};
use sp_consensus::BlockOrigin;
use sp_keyring::Sr25519Keyring;
use sp_runtime::{
	generic,
	transaction_validity::{InvalidTransaction, TransactionValidityError},
	AccountId32, MultiAddress, OpaqueExtrinsic,
};
use staging_node_cli as node_cli;
use tokio::runtime::Handle;

fn new_node(tokio_handle: Handle) -> node_cli::service::NewFullBase {
	let base_path = BasePath::new_temp_dir()
		.expect("getting the base path of a temporary path doesn't fail; qed");
	let root = base_path.path().to_path_buf();

	let network_config = NetworkConfiguration::new(
		Sr25519Keyring::Alice.to_seed(),
		"network/test/0.1",
		Default::default(),
		None,
	);

	let spec = Box::new(node_cli::chain_spec::development_config());

	let config = Configuration {
		impl_name: "BenchmarkImpl".into(),
		impl_version: "1.0".into(),
		// We don't use the authority role since that would start producing blocks
		// in the background which would mess with our benchmark.
		role: Role::Full,
		tokio_handle,
		transaction_pool: Default::default(),
		network: network_config,
		keystore: KeystoreConfig::InMemory,
		database: DatabaseSource::RocksDb { path: root.join("db"), cache_size: 128 },
		trie_cache_maximum_size: Some(64 * 1024 * 1024),
		warm_up_trie_cache: None,
		state_pruning: Some(PruningMode::ArchiveAll),
		blocks_pruning: BlocksPruning::KeepAll,
		chain_spec: spec,
		executor: ExecutorConfiguration {
			wasm_method: WasmExecutionMethod::Compiled {
				instantiation_strategy: WasmtimeInstantiationStrategy::PoolingCopyOnWrite,
			},
			..ExecutorConfiguration::default()
		},
		rpc: RpcConfiguration {
			addr: None,
			max_connections: Default::default(),
			cors: None,
			methods: Default::default(),
			max_request_size: Default::default(),
			max_response_size: Default::default(),
			id_provider: Default::default(),
			max_subs_per_conn: Default::default(),
			port: 9944,
			message_buffer_capacity: Default::default(),
			batch_config: RpcBatchRequestConfig::Unlimited,
			rate_limit: None,
			rate_limit_whitelisted_ips: Default::default(),
			rate_limit_trust_proxy_headers: Default::default(),
		},
		prometheus_config: None,
		telemetry_endpoints: None,
		offchain_worker: OffchainWorkerConfig { enabled: true, indexing_enabled: false },
		force_authoring: false,
		disable_grandpa: false,
		dev_key_seed: Some(Sr25519Keyring::Alice.to_seed()),
		tracing_targets: None,
		tracing_receiver: Default::default(),
		announce_block: true,
		data_path: base_path.path().into(),
		base_path,
		wasm_runtime_overrides: None,
	};

	node_cli::service::new_full_base::<sc_network::NetworkWorker<_, _>>(
		config,
		None,
		false,
		|_, _| (),
	)
	.expect("creating a full node doesn't fail")
}

fn extrinsic_set_time(now: u64) -> OpaqueExtrinsic {
	let utx: kitchensink_runtime::UncheckedExtrinsic = generic::UncheckedExtrinsic::new_bare(
		kitchensink_runtime::RuntimeCall::Timestamp(pallet_timestamp::Call::set { now }),
	)
	.into();
	utx.into()
}

fn import_block(client: &FullClient, built: BuiltBlock<node_primitives::Block>) {
	let mut params = BlockImportParams::new(BlockOrigin::File, built.block.header);
	params.state_action =
		StateAction::ApplyChanges(sc_consensus::StorageChanges::Changes(built.storage_changes));
	params.fork_choice = Some(ForkChoiceStrategy::LongestChain);
	futures::executor::block_on(client.import_block(params))
		.expect("importing a block doesn't fail");
}

fn prepare_benchmark(client: &FullClient) -> (usize, Vec<OpaqueExtrinsic>) {
	const MINIMUM_PERIOD_FOR_BLOCKS: u64 = 1500;

	let mut max_transfer_count = 0;
	let mut extrinsics = Vec::new();
	let mut block_builder = BlockBuilderBuilder::new(client)
		.on_parent_block(client.chain_info().best_hash)
		.with_parent_block_number(client.chain_info().best_number)
		.build()
		.unwrap();

	// Every block needs one timestamp extrinsic.
	let extrinsic_set_time = extrinsic_set_time(1 + MINIMUM_PERIOD_FOR_BLOCKS);
	block_builder.push(extrinsic_set_time.clone()).unwrap();
	extrinsics.push(extrinsic_set_time);

	// Creating those is surprisingly costly, so let's only do it once and later just `clone` them.
	let src = Sr25519Keyring::Alice.pair();
	let dst: MultiAddress<AccountId32, u32> = Sr25519Keyring::Bob.to_account_id().into();

	// Add as many transfer extrinsics as possible into a single block.
	for nonce in 0.. {
		let extrinsic: OpaqueExtrinsic = create_extrinsic(
			client,
			src.clone(),
			BalancesCall::transfer_allow_death { dest: dst.clone(), value: 1 * DOLLARS },
			Some(nonce),
		)
		.into();

		match block_builder.push(extrinsic.clone()) {
			Ok(_) => {},
			Err(ApplyExtrinsicFailed(Validity(TransactionValidityError::Invalid(
				InvalidTransaction::ExhaustsResources,
			)))) => break,
			Err(error) => panic!("{}", error),
		}

		extrinsics.push(extrinsic);
		max_transfer_count += 1;
	}

	(max_transfer_count, extrinsics)
}

fn block_production(c: &mut Criterion) {
	sp_tracing::try_init_simple();

	let runtime = tokio::runtime::Runtime::new().expect("creating tokio runtime doesn't fail; qed");
	let tokio_handle = runtime.handle().clone();

	let node = new_node(tokio_handle.clone());
	let client = &*node.client;

	// Building the very first block is around ~30x slower than any subsequent one,
	// so let's make sure it's built and imported before we benchmark anything.
	let mut block_builder = BlockBuilderBuilder::new(client)
		.on_parent_block(client.chain_info().best_hash)
		.with_parent_block_number(client.chain_info().best_number)
		.build()
		.unwrap();
	block_builder.push(extrinsic_set_time(1)).unwrap();
	import_block(client, block_builder.build().unwrap());

	let (max_transfer_count, extrinsics) = prepare_benchmark(&client);
	log::info!("Maximum transfer count: {}", max_transfer_count);

	let mut group = c.benchmark_group("Block production");

	group.sample_size(10);
	group.throughput(Throughput::Elements(max_transfer_count as u64));

	let chain = client.chain_info();
	let best_hash = chain.best_hash;
	let best_number = chain.best_number;

	group.bench_function(format!("{} transfers (no proof)", max_transfer_count), |b| {
		b.iter_batched(
			|| extrinsics.clone(),
			|extrinsics| {
				let mut block_builder = BlockBuilderBuilder::new(client)
					.on_parent_block(best_hash)
					.with_parent_block_number(best_number)
					.build()
					.unwrap();
				for extrinsic in extrinsics {
					block_builder.push(extrinsic).unwrap();
				}
				block_builder.build().unwrap()
			},
			BatchSize::SmallInput,
		)
	});

	group.bench_function(format!("{} transfers (with proof)", max_transfer_count), |b| {
		b.iter_batched(
			|| extrinsics.clone(),
			|extrinsics| {
				let mut block_builder = BlockBuilderBuilder::new(client)
					.on_parent_block(best_hash)
					.with_parent_block_number(best_number)
					.build()
					.unwrap();
				for extrinsic in extrinsics {
					block_builder.push(extrinsic).unwrap();
				}
				block_builder.build().unwrap()
			},
			BatchSize::SmallInput,
		)
	});
}

criterion_group!(benches, block_production);
criterion_main!(benches);
