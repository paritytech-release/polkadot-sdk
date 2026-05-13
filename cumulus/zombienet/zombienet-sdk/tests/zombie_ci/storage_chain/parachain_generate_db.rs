// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot builder for the storage-chain tip-sync test.
//!
//! Drives `TransactionStorage::store_with_cid_config` extrinsics against alice,
//! then archives the parachain DB / relay DB / snapshot metadata tarballs into
//! `STORAGE_CHAIN_DB_OUTPUT_DIR` for downstream tests to consume.
//!
//! Gated by the `generate-snapshots` cargo feature.

use super::utils::{
	algorithm, content_hash, get_alice_nonce, initialize_network, payload,
	snapshot_metadata_path, verify_parachain_binaries, wait_for_block_height,
	wait_for_finalized_height, wait_for_session_change_on_node, HashingAlgorithm,
	SnapshotMetadata, FIXTURE_RETENTION_PERIOD, N_STORES, NETWORK_READY_TIMEOUT_SECS,
	NODE_LOG_CONFIG, PARACHAIN_BINARY, PARACHAIN_CHAIN_SPEC, PARA_ID, PAYLOAD_SIZE_MAX,
	PAYLOAD_SIZE_MIN, RELAY_BINARY, RELAY_CHAIN, SYNC_TIMEOUT_SECS, TIP_SYNC_TARGET_BLOCKS,
};
use crate::test_log;
use anyhow::{anyhow, Context, Result};
use env_logger::Env;
use flate2::{write::GzEncoder, Compression};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zombienet_sdk::{
	subxt::{
		config::substrate::{SubstrateConfig, SubstrateExtrinsicParamsBuilder},
		dynamic::Value,
		ext::scale_value::value,
		OnlineClient,
	},
	subxt_signer::sr25519::dev,
	NetworkConfig, NetworkConfigBuilder,
};

const SESSION_CHANGE_TIMEOUT_SECS: u64 = 300;
const DB_OUTPUT_DIR_ENV: &str = "DB_OUTPUT_DIR";
const DEFAULT_DB_OUTPUT_DIR: &str = "./zombienet/test-databases";

/// First chain block at which we may begin submitting stores. Stores below this
/// would risk being on a chain that has not yet reached steady-state block
/// production, and stops the snapshot from exercising a real warp-sync.
const STORE_START_BLOCK: u64 = 50;

/// Wall-clock cap for waiting for a target block height. Parachain blocks are
/// ~6s in local testnet, so a 100-block target should complete in ~10 minutes
/// even with generous slack. We allow much more for safety.
const GEN_TIMEOUT_SECS: u64 = 1800;

fn get_db_output_dir() -> PathBuf {
	let dir = std::env::var(DB_OUTPUT_DIR_ENV).unwrap_or_else(|_| DEFAULT_DB_OUTPUT_DIR.into());
	PathBuf::from(dir)
}

fn build_gendb_network_config(pruning_blocks: u32) -> Result<NetworkConfig> {
	let relay_binary = RELAY_BINARY.to_string();
	let para_binary = PARACHAIN_BINARY.to_string();
	let para_chain_spec = PARACHAIN_CHAIN_SPEC.to_string();
	let relay_chain = RELAY_CHAIN.to_string();
	let para_id = PARA_ID;

	let relay_args: Vec<_> = vec!["-lruntime=debug"].into_iter().map(|s| s.into()).collect();
	let relay_args2 = relay_args.clone();

	let collator_args: Vec<_> =
		vec!["--ipfs-server", NODE_LOG_CONFIG].into_iter().map(|s| s.into()).collect();

	let pruning_flag = format!("--blocks-pruning={}", pruning_blocks);
	let pruned_args: Vec<_> =
		vec!["--sync=full", "--ipfs-server", pruning_flag.as_str(), NODE_LOG_CONFIG]
			.into_iter()
			.map(|s| s.into())
			.collect();

	NetworkConfigBuilder::new()
		.with_relaychain(|relaychain| {
			relaychain
				.with_chain(relay_chain.as_str())
				.with_default_command(relay_binary.as_str())
				.with_validator(|node| {
					node.with_name("alice").validator(true).with_args(relay_args)
				})
				.with_validator(|node| node.with_name("bob").validator(true).with_args(relay_args2))
		})
		.with_parachain(|parachain| {
			parachain
				.with_id(para_id)
				.with_chain_spec_path(para_chain_spec.as_str())
				.cumulus_based(true)
				.with_collator(|c| {
					c.with_name("collator-1")
						.validator(true)
						.with_command(para_binary.as_str())
						.with_args(collator_args)
				})
				.with_collator(|c| {
					c.with_name("pruned-node")
						.validator(false)
						.with_command(para_binary.as_str())
						.with_args(pruned_args)
				})
		})
		.with_global_settings(|gs| match std::env::var("ZOMBIENET_SDK_BASE_DIR") {
			Ok(val) => gs.with_base_dir(val),
			_ => gs,
		})
		.build()
		.map_err(|errs| {
			let message = errs.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join(", ");
			anyhow!("config errs: {message}")
		})
}

async fn authorize_account(
	client: &OnlineClient<SubstrateConfig>,
	who: &zombienet_sdk::subxt_signer::sr25519::Keypair,
	transactions: u32,
	bytes: u64,
	signer_nonce: u64,
	label: &str,
) -> Result<()> {
	let signer = dev::alice();
	let authorize_call = zombienet_sdk::subxt::tx::dynamic(
		"Sudo",
		"sudo",
		vec![value! {
			TransactionStorage(authorize_account {
				who: Value::from_bytes(who.public_key().0),
				transactions: transactions,
				bytes: bytes
			})
		}],
	);
	let params = SubstrateExtrinsicParamsBuilder::new().nonce(signer_nonce).build();
	let timeout = std::time::Duration::from_secs(60);

	tokio::time::timeout(timeout, async {
		let progress =
			client.tx().sign_and_submit_then_watch(&authorize_call, &signer, params).await?;
		super::utils::tx::wait_for_in_best_block(progress).await?;
		Ok::<_, anyhow::Error>(())
	})
	.await
	.map_err(|_| anyhow!("{} authorization timed out", label))??;

	log::info!("Authorized {} for {} transactions / {} bytes", label, transactions, bytes);
	Ok(())
}

struct StoreOutcome {
	included_at_block: u64,
}

async fn store_data(
	client: &OnlineClient<SubstrateConfig>,
	data: &[u8],
	nonce: u64,
	algo: HashingAlgorithm,
) -> Result<StoreOutcome> {
	let signer = dev::alice();

	let algo_name = match algo {
		HashingAlgorithm::Blake2b256 => "Blake2b256",
		HashingAlgorithm::Sha2_256 => "Sha2_256",
		HashingAlgorithm::Keccak256 => "Keccak256",
	};
	let cid_config = Value::named_composite(vec![
		("codec", Value::u128(0x55)),
		("hashing", Value::unnamed_variant(algo_name, vec![])),
	]);
	let store_call = zombienet_sdk::subxt::tx::dynamic(
		"TransactionStorage",
		"store_with_cid_config",
		vec![cid_config, Value::from_bytes(data)],
	);
	let params = SubstrateExtrinsicParamsBuilder::new().nonce(nonce).build();
	let timeout = std::time::Duration::from_secs(120);

	let (block_hash, _events) = tokio::time::timeout(timeout, async {
		let progress = client.tx().sign_and_submit_then_watch(&store_call, &signer, params).await?;
		super::utils::tx::wait_for_in_best_block(progress).await
	})
	.await
	.map_err(|_| anyhow!("store transaction timed out (nonce={})", nonce))??;

	let block = client.blocks().at(block_hash).await?;
	Ok(StoreOutcome { included_at_block: block.number() as u64 })
}

/// Directories to exclude from snapshots. Zombienet injects its own keystore and
/// network identity per node; including the original keys would conflict.
const SNAPSHOT_EXCLUDE_DIRS: &[&str] = &["keystore", "network"];

fn create_db_snapshot_tgz(
	node_base_dir: &Path,
	output_path: &Path,
	extra_dirs: &[&str],
) -> Result<u64> {
	let data_dir = node_base_dir.join("data");
	anyhow::ensure!(data_dir.exists(), "data dir does not exist: {}", data_dir.display());

	if let Some(parent) = output_path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	let file = std::fs::File::create(output_path)
		.with_context(|| format!("Failed to create {}", output_path.display()))?;
	let enc = GzEncoder::new(file, Compression::fast());
	let mut tar = tar::Builder::new(enc);
	tar.mode(tar::HeaderMode::Deterministic);

	fn add_dir_filtered(
		tar: &mut tar::Builder<GzEncoder<std::fs::File>>,
		src_dir: &Path,
		archive_prefix: &Path,
	) -> Result<()> {
		tar.append_dir(archive_prefix, src_dir)
			.with_context(|| format!("Failed to add dir {}", src_dir.display()))?;

		for entry in std::fs::read_dir(src_dir)
			.with_context(|| format!("Failed to read dir {}", src_dir.display()))?
		{
			let entry = entry?;
			let file_name = entry.file_name();
			let file_name_str = file_name.to_string_lossy();
			let src_path = entry.path();
			let archive_path = archive_prefix.join(&file_name);

			if entry.file_type()?.is_dir() {
				if SNAPSHOT_EXCLUDE_DIRS.iter().any(|d| *d == file_name_str) {
					log::info!("Snapshot: skipping {}", src_path.display());
					continue;
				}
				add_dir_filtered(tar, &src_path, &archive_path)?;
			} else {
				tar.append_path_with_name(&src_path, &archive_path)
					.with_context(|| format!("Failed to add {}", src_path.display()))?;
			}
		}
		Ok(())
	}

	add_dir_filtered(&mut tar, &data_dir, Path::new("data"))?;

	for dir_name in extra_dirs {
		let extra_dir = node_base_dir.join(dir_name);
		if extra_dir.exists() {
			log::info!("Snapshot: including extra dir {}/", dir_name);
			add_dir_filtered(&mut tar, &extra_dir, Path::new(dir_name))?;
		} else {
			log::warn!("Snapshot: extra dir {} does not exist, skipping", extra_dir.display());
		}
	}

	tar.finish()?;
	drop(tar);

	let size = std::fs::metadata(output_path)?.len();
	Ok(size)
}

#[tokio::test(flavor = "multi_thread")]
async fn parachain_generate_databases() -> Result<()> {
	const TEST: &str = "para_gen_db";
	let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

	test_log!(TEST, "=== Parachain Database Generation ===");
	log::info!(
		"Config: target_blocks={}, retention_period={}, n_stores={}, store_start_block={}, payload_size=[{}, {}]",
		TIP_SYNC_TARGET_BLOCKS,
		FIXTURE_RETENTION_PERIOD,
		N_STORES,
		STORE_START_BLOCK,
		PAYLOAD_SIZE_MIN,
		PAYLOAD_SIZE_MAX,
	);

	// Sanity-check the payload functions before we spin up a network, so failures
	// fast-fail instead of after 30+ minutes of generation.
	let mut hashes_seen: HashSet<[u8; 32]> = HashSet::new();
	let mut total_payload_bytes: u64 = 0;
	for i in 0..N_STORES {
		let p = payload(i);
		anyhow::ensure!(
			(PAYLOAD_SIZE_MIN..=PAYLOAD_SIZE_MAX).contains(&p.len()),
			"payload({i}).len()={} out of bounds",
			p.len(),
		);
		let h = content_hash(i);
		anyhow::ensure!(
			h == algorithm(i).hash(&p),
			"content_hash({i}) inconsistent with algorithm({i}).hash(&payload({i}))",
		);
		anyhow::ensure!(hashes_seen.insert(h), "duplicate content_hash at i={i}");
		total_payload_bytes += p.len() as u64;
	}
	log::info!(
		"Payload sanity OK: {} unique hashes, {} total bytes",
		hashes_seen.len(),
		total_payload_bytes,
	);

	verify_parachain_binaries()?;

	let output_dir = get_db_output_dir();
	std::fs::create_dir_all(&output_dir)
		.with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;
	log::info!("Output directory: {}", output_dir.display());

	// === Phase 1: Spawn network ===
	test_log!(
		TEST,
		"Phase 1: Spawning network (collator + pruned-node with --blocks-pruning={})",
		FIXTURE_RETENTION_PERIOD,
	);

	let config = build_gendb_network_config(FIXTURE_RETENTION_PERIOD)?;
	let network = initialize_network(config).await?;
	network.wait_until_is_up(NETWORK_READY_TIMEOUT_SECS).await?;

	let relay_alice = network.get_node("alice").context("Failed to get relay alice node")?;
	log::info!("Waiting for relay chain session change...");
	wait_for_session_change_on_node(relay_alice, SESSION_CHANGE_TIMEOUT_SECS)
		.await
		.context("Failed to detect session change on relay chain")?;

	// === Phase 2: Authorize Alice and Bob ===
	let collator1 = network.get_node("collator-1").context("Failed to get collator-1 node")?;
	let collator_client: OnlineClient<SubstrateConfig> = collator1.wait_client().await?;

	// Authorize with enough budget for all stores + all renewals during the live test.
	let authorize_transactions = (N_STORES + 10) as u32;
	let authorize_bytes = total_payload_bytes.saturating_mul(2).saturating_add(1024 * 1024);
	log::info!(
		"Authorization budget: {} txs / {} bytes (2x payload total + 1 MiB margin)",
		authorize_transactions,
		authorize_bytes,
	);

	let mut nonce = get_alice_nonce(collator1).await?;
	authorize_account(
		&collator_client,
		&dev::alice(),
		authorize_transactions,
		authorize_bytes,
		nonce,
		"alice",
	)
	.await?;
	nonce += 1;

	authorize_account(
		&collator_client,
		&dev::bob(),
		authorize_transactions,
		authorize_bytes,
		nonce,
		"bob",
	)
	.await?;
	nonce += 1;

	// === Phase 3: Wait for STORE_START_BLOCK then submit N_STORES stores ===
	wait_for_block_height(collator1, STORE_START_BLOCK, GEN_TIMEOUT_SECS)
		.await
		.with_context(|| format!("Did not reach store-start block {}", STORE_START_BLOCK))?;

	test_log!(
		TEST,
		"Phase 3: Submitting {} stores starting at block {}",
		N_STORES,
		STORE_START_BLOCK,
	);

	let mut first_store_block: u64 = u64::MAX;
	let mut last_store_block: u64 = 0;
	for i in 0..N_STORES {
		let data = payload(i);
		let algo = algorithm(i);
		let outcome = store_data(&collator_client, &data, nonce, algo).await?;
		nonce += 1;
		first_store_block = first_store_block.min(outcome.included_at_block);
		last_store_block = last_store_block.max(outcome.included_at_block);
		log::info!(
			"Store {}/{}: algo={:?}, size={} bytes, included at block {}",
			i + 1,
			N_STORES,
			algo,
			data.len(),
			outcome.included_at_block,
		);
	}
	test_log!(
		TEST,
		"All {} stores submitted: first_block={}, last_block={}",
		N_STORES,
		first_store_block,
		last_store_block,
	);

	anyhow::ensure!(
		last_store_block <= TIP_SYNC_TARGET_BLOCKS,
		"last store landed at block {} but target_blocks is {}; stores spilled past target",
		last_store_block,
		TIP_SYNC_TARGET_BLOCKS,
	);

	// === Phase 4: Wait for finalization ===
	let finalize_target = TIP_SYNC_TARGET_BLOCKS.max(last_store_block);
	test_log!(TEST, "Phase 4: Waiting for block {} finalized on both nodes", finalize_target);

	wait_for_finalized_height(collator1, finalize_target, GEN_TIMEOUT_SECS)
		.await
		.context("Collator did not finalize target block")?;
	log::info!("✓ Collator finalized block {}", finalize_target);

	let pruned_node = network.get_node("pruned-node").context("Failed to get pruned-node")?;
	wait_for_block_height(pruned_node, finalize_target, SYNC_TIMEOUT_SECS)
		.await
		.context("Pruned node did not reach target block")?;
	wait_for_finalized_height(pruned_node, finalize_target, GEN_TIMEOUT_SECS)
		.await
		.context("Pruned node did not finalize target block")?;
	log::info!("✓ Pruned node finalized block {}", finalize_target);

	let snapshot_height = finalize_target;

	// === Phase 5: Archive ===
	test_log!(TEST, "Phase 5: Archiving databases to {}", output_dir.display());

	let base_dir = network
		.base_dir()
		.ok_or_else(|| anyhow!("Failed to get network base directory"))?
		.to_string();

	let collator_base = Path::new(&base_dir).join("collator-1");
	let pruned_base = Path::new(&base_dir).join("pruned-node");
	let relay_alice_base = Path::new(&base_dir).join("alice");

	let archive_tgz = output_dir.join("archive.tgz");
	let pruned_tgz = output_dir.join("pruned.tgz");
	let relay_tgz = output_dir.join("relay.tgz");

	// Save raw chainspecs — zombienet customizes genesis (collators, validators).
	let raw_chain_spec_src = collator_base.join("cfg").join(format!("{}.json", PARA_ID));
	let raw_chain_spec_dst = output_dir.join("raw-chain-spec.json");
	std::fs::copy(&raw_chain_spec_src, &raw_chain_spec_dst).with_context(|| {
		format!(
			"Failed to copy raw chain spec from {} to {}",
			raw_chain_spec_src.display(),
			raw_chain_spec_dst.display()
		)
	})?;
	log::info!("Saved raw parachain chain spec: {}", raw_chain_spec_dst.display());

	let raw_relay_spec_src = relay_alice_base.join("cfg").join("westend-local.json");
	let raw_relay_spec_dst = output_dir.join("raw-relay-chain-spec.json");
	std::fs::copy(&raw_relay_spec_src, &raw_relay_spec_dst).with_context(|| {
		format!(
			"Failed to copy relay chain spec from {} to {}",
			raw_relay_spec_src.display(),
			raw_relay_spec_dst.display()
		)
	})?;
	log::info!("Saved raw relay chain spec: {}", raw_relay_spec_dst.display());

	let metadata = SnapshotMetadata {
		total_blocks: TIP_SYNC_TARGET_BLOCKS,
		retention_period: FIXTURE_RETENTION_PERIOD,
		n_stores: N_STORES,
		payload_size_min: PAYLOAD_SIZE_MIN,
		payload_size_max: PAYLOAD_SIZE_MAX,
		snapshot_height,
		first_store_block,
		last_store_block,
	};
	let metadata_path = snapshot_metadata_path(&output_dir);
	let metadata_file = std::fs::File::create(&metadata_path)
		.with_context(|| format!("Failed to create {}", metadata_path.display()))?;
	serde_json::to_writer_pretty(metadata_file, &metadata)
		.with_context(|| format!("Failed to write {}", metadata_path.display()))?;
	log::info!("Saved snapshot metadata: {}", metadata_path.display());

	log::info!("Creating archive snapshot (with relay-data): {}", archive_tgz.display());
	let archive_size = create_db_snapshot_tgz(&collator_base, &archive_tgz, &["relay-data"])
		.context("Failed to archive collator DB")?;

	log::info!("Creating pruned snapshot: {}", pruned_tgz.display());
	let pruned_size = create_db_snapshot_tgz(&pruned_base, &pruned_tgz, &[])
		.context("Failed to archive pruned DB")?;

	log::info!("Creating relay chain snapshot: {}", relay_tgz.display());
	let relay_size = create_db_snapshot_tgz(&relay_alice_base, &relay_tgz, &[])
		.context("Failed to archive relay chain DB")?;

	log::info!(
		"✓ Archive snapshot: {} ({:.1} MB)",
		archive_tgz.display(),
		archive_size as f64 / 1_048_576.0
	);
	log::info!(
		"✓ Pruned snapshot: {} ({:.1} MB)",
		pruned_tgz.display(),
		pruned_size as f64 / 1_048_576.0
	);
	log::info!(
		"✓ Relay snapshot: {} ({:.1} MB)",
		relay_tgz.display(),
		relay_size as f64 / 1_048_576.0
	);

	test_log!(
		TEST,
		"=== Database generation complete: target={}, snapshot_height={}, stores={} ({}..{}), archive={:.1}MB, pruned={:.1}MB, relay={:.1}MB ===",
		TIP_SYNC_TARGET_BLOCKS,
		snapshot_height,
		N_STORES,
		first_store_block,
		last_store_block,
		archive_size as f64 / 1_048_576.0,
		pruned_size as f64 / 1_048_576.0,
		relay_size as f64 / 1_048_576.0,
	);

	network.destroy().await?;
	Ok(())
}
