// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Tip-sync-with-renewals integration test.
//!
//! Proves a node that warp-synced to the tip with an empty TRANSACTION column,
//! then sees a renew block for a pre-warp entry, fetches the missing bytes via
//! bitswap and serves the blob via `bitswap_v1_get`.
//!
//! Reads snapshot paths from STORAGE_CHAIN_* env vars; see `utils/fixture.rs`.

use super::utils::{
	algorithm, bitswap_v1_get,
	build_parachain_network_config_three_relay_validators_with_snapshots, content_hash,
	expect_dont_have, expect_no_log_line, get_best_block_height, hash_to_cid, initialize_network,
	payload, renew_data_with_content_hash, verify_parachain_binaries,
	verify_warp_sync_completed, wait_for_block_height, wait_for_finalized_height,
	wait_for_fullnode, wait_for_new_block_beyond, wait_for_relay_chain_to_sync,
	wait_for_session_change_on_node, HashingAlgorithm, ResolvedSnapshots,
	BLOCK_PRODUCTION_TIMEOUT_SECS, FIXTURE_RETENTION_PERIOD, N_STORES,
	NETWORK_READY_TIMEOUT_SECS, NODE_LOG_CONFIG, PARACHAIN_BINARY, PARA_ID, SYNC_TIMEOUT_SECS,
	TIP_SYNC_TARGET_BLOCKS,
};
use crate::test_log;
use anyhow::{anyhow, Context, Result};
use env_logger::Env;
use std::time::Duration;
use zombienet_orchestrator::AddCollatorOptions;
use zombienet_sdk::subxt::{config::substrate::SubstrateConfig, OnlineClient};

const N_RENEW_EXERCISES: u32 = N_STORES;
const WARP_PRUNING_BLOCKS: u32 = 100;
const SESSION_CHANGE_TIMEOUT_SECS: u64 = 300;
const BITSWAP_RPC_POLL_TIMEOUT_SECS: u64 = 600;

// Sync-node block-import latency for renew blocks is dominated by per-blob
// bitswap fetch (up to 1.5 MiB per entry) and multi-hash verification.
// The shared SYNC_TIMEOUT_SECS (180s) is too tight; allow more headroom.
const RENEW_BLOCK_SYNC_TIMEOUT_SECS: u64 = 600;

#[tokio::test(flavor = "multi_thread")]
async fn parachain_tip_sync_with_renewals_test() -> Result<()> {
	const TEST: &str = "para_tip_sync_renewals";
	let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();

	verify_parachain_binaries()?;
	let snaps = ResolvedSnapshots::load()?;
	let metadata = snaps.load_metadata()?;
	anyhow::ensure!(
		metadata.total_blocks == TIP_SYNC_TARGET_BLOCKS,
		"unexpected metadata.total_blocks: got {}, expected {}",
		metadata.total_blocks,
		TIP_SYNC_TARGET_BLOCKS,
	);
	anyhow::ensure!(
		metadata.retention_period == FIXTURE_RETENTION_PERIOD,
		"unexpected metadata.retention_period: got {}, expected {}",
		metadata.retention_period,
		FIXTURE_RETENTION_PERIOD,
	);
	anyhow::ensure!(
		metadata.n_stores == N_STORES,
		"unexpected metadata.n_stores: got {}, expected {}",
		metadata.n_stores,
		N_STORES,
	);
	anyhow::ensure!(
		N_RENEW_EXERCISES <= metadata.n_stores,
		"N_RENEW_EXERCISES ({}) must be <= metadata.n_stores ({})",
		N_RENEW_EXERCISES,
		metadata.n_stores,
	);
	test_log!(
		TEST,
		"Loaded snapshot metadata: target={}, snapshot_height={}, stores={} ({}..{})",
		metadata.total_blocks,
		metadata.snapshot_height,
		metadata.n_stores,
		metadata.first_store_block,
		metadata.last_store_block,
	);

	let config = build_parachain_network_config_three_relay_validators_with_snapshots(
		vec!["--ipfs-server".into(), NODE_LOG_CONFIG.into()],
		Some(snaps.as_parachain_snapshots()),
	)?;
	let mut network = initialize_network(config).await?;
	network.wait_until_is_up(NETWORK_READY_TIMEOUT_SECS).await?;

	{
		let alice = network.get_node("alice")?;
		wait_for_session_change_on_node(alice, SESSION_CHANGE_TIMEOUT_SECS).await?;

		let collator1 = network.get_node("collator-1")?;
		let snapshot_height = get_best_block_height(collator1).await?;
		test_log!(TEST, "Collator booted at block {} (from snapshot)", snapshot_height);
		wait_for_new_block_beyond(collator1, snapshot_height, BLOCK_PRODUCTION_TIMEOUT_SECS)
			.await?;
		test_log!(TEST, "Collator extended chain past snapshot tip");
	}

	network
		.add_collator(
			"sync-node",
			AddCollatorOptions {
				command: Some(PARACHAIN_BINARY.try_into()?),
				args: vec![
					"--sync=warp".into(),
					"--ipfs-server".into(),
					format!("--blocks-pruning={WARP_PRUNING_BLOCKS}").as_str().into(),
					NODE_LOG_CONFIG.into(),
				],
				is_validator: false,
				..Default::default()
			},
			PARA_ID,
		)
		.await?;

	let collator1 = network.get_node("collator-1")?;
	let sync_node = network.get_node("sync-node")?;
	wait_for_fullnode(sync_node).await?;
	wait_for_relay_chain_to_sync(sync_node, SYNC_TIMEOUT_SECS).await?;

	let warp_target = get_best_block_height(collator1).await?;
	wait_for_block_height(sync_node, warp_target, SYNC_TIMEOUT_SECS).await?;
	verify_warp_sync_completed(sync_node).await?;
	test_log!(TEST, "Sync-node warp-synced to block {}", warp_target);

	for i in 0..N_RENEW_EXERCISES {
		let h = content_hash(i);
		let cid = hash_to_cid(&h, algorithm(i));
		expect_dont_have(sync_node, &cid, Duration::from_secs(BITSWAP_RPC_POLL_TIMEOUT_SECS))
			.await
			.with_context(|| {
				format!("pre-renewal: sync-node should not have entry {i} ({cid})")
			})?;
	}
	test_log!(
		TEST,
		"Confirmed sync-node lacks all {N_RENEW_EXERCISES} pre-warp entries (DontHave)"
	);

	let collator_client: OnlineClient<SubstrateConfig> = collator1.wait_client().await?;
	let mut bob_nonce = collator_client
		.tx()
		.account_nonce(
			&zombienet_sdk::subxt_signer::sr25519::dev::bob().public_key().to_account_id(),
		)
		.await?;

	let mut renewed: Vec<([u8; 32], HashingAlgorithm)> = Vec::new();
	for i in 0..N_RENEW_EXERCISES {
		let expected_hash = content_hash(i);
		let algo = algorithm(i);
		let outcome = renew_data_with_content_hash(&collator_client, expected_hash, bob_nonce)
			.await
			.with_context(|| {
				format!("renewing entry {i} (hash={})", hex::encode(expected_hash))
			})?;
		bob_nonce += 1;
		test_log!(
			TEST,
			"✓ Renew {}/{}: entry={}, hash={}, algo={:?} → block {} index {}",
			i + 1,
			N_RENEW_EXERCISES,
			i,
			hex::encode(expected_hash),
			algo,
			outcome.renewed_at_block,
			outcome.renewed_index,
		);
		renewed.push((expected_hash, algo));
		wait_for_finalized_height(collator1, outcome.renewed_at_block, BLOCK_PRODUCTION_TIMEOUT_SECS)
			.await?;
		wait_for_block_height(sync_node, outcome.renewed_at_block, RENEW_BLOCK_SYNC_TIMEOUT_SECS)
			.await?;
	}

	let deadline = std::time::Instant::now() + Duration::from_secs(BITSWAP_RPC_POLL_TIMEOUT_SECS);
	let served = loop {
		let mut served = 0usize;
		for (h, algo) in &renewed {
			let cid = hash_to_cid(h, *algo);
			if matches!(
				bitswap_v1_get(sync_node, &cid).await,
				Ok(Some(bytes)) if algo.hash(&bytes) == *h
			) {
				served += 1;
			}
		}

		if served >= renewed.len() {
			break served;
		}

		if std::time::Instant::now() >= deadline {
			return Err(anyhow!(
				"post-renewal: sync-node served only {} of {} renewed entries within {}s",
				served,
				renewed.len(),
				BITSWAP_RPC_POLL_TIMEOUT_SECS,
			));
		}

		tokio::time::sleep(Duration::from_secs(1)).await;
	};
	test_log!(
		TEST,
		"✓ Sync-node serves {} renewed pre-warp entries via bitswap_v1_get",
		served,
	);

	// Sanity-check bytes returned by bitswap actually hash to the expected hash.
	// (Already done in the poll loop above for the algo-specific hash, but assert
	// payload(i) decodes correctly too — guarding against the deterministic
	// payload function drifting between generator and test.)
	for i in 0..N_RENEW_EXERCISES {
		let cid = hash_to_cid(&content_hash(i), algorithm(i));
		match bitswap_v1_get(sync_node, &cid).await? {
			Some(bytes) => {
				anyhow::ensure!(
					bytes == payload(i),
					"bitswap returned bytes do not match payload({i})",
				);
			},
			None => anyhow::bail!("bitswap_v1_get returned None for entry {i} after successful poll loop"),
		}
	}

	expect_no_log_line(
		collator1,
		"(?i)bitswap.*hash.mismatch",
		10,
		"collator logged a bitswap hash mismatch",
	)
	.await?;
	expect_no_log_line(
		sync_node,
		"(?i)bitswap.*hash.mismatch",
		10,
		"sync-node logged a bitswap hash mismatch",
	)
	.await?;

	test_log!(TEST, "=== parachain_tip_sync_with_renewals PASSED ===");
	network.destroy().await?;
	Ok(())
}
