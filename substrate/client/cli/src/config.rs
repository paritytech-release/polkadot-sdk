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

//! Configuration trait for a CLI based on substrate

use crate::{
	arg_enums::Database, error::Result, DatabaseParams, ImportParams, KeystoreParams,
	NetworkParams, NodeKeyParams, OffchainWorkerParams, PruningParams, RpcEndpoint, SharedParams,
	SubstrateCli,
};
use log::warn;
use names::{Generator, Name};
use sc_service::{
	config::{
		BasePath, Configuration, DatabaseSource, ExecutorConfiguration, IpNetwork, KeystoreConfig,
		NetworkConfiguration, NodeKeyConfig, OffchainWorkerConfig, PrometheusConfig, PruningMode,
		Role, RpcBatchRequestConfig, RpcConfiguration, RpcMethods, TelemetryEndpoints,
		TransactionPoolOptions, WasmExecutionMethod,
	},
	BlocksPruning, ChainSpec, TracingReceiver,
};
use sc_tracing::logging::LoggerBuilder;
use std::{num::NonZeroU32, path::PathBuf};

/// The maximum number of characters for a node name.
pub(crate) const NODE_NAME_MAX_LENGTH: usize = 64;

/// Default sub directory to store network config.
pub(crate) const DEFAULT_NETWORK_CONFIG_PATH: &str = "network";

/// The recommended open file descriptor limit to be configured for the process.
const RECOMMENDED_OPEN_FILE_DESCRIPTOR_LIMIT: u64 = 10_000;

/// The default port.
pub const RPC_DEFAULT_PORT: u16 = 9944;
/// The default max number of subscriptions per connection.
pub const RPC_DEFAULT_MAX_SUBS_PER_CONN: u32 = 1024;
/// The default max request size in MB.
pub const RPC_DEFAULT_MAX_REQUEST_SIZE_MB: u32 = 15;
/// The default max response size in MB.
pub const RPC_DEFAULT_MAX_RESPONSE_SIZE_MB: u32 = 15;
/// The default concurrent connection limit.
pub const RPC_DEFAULT_MAX_CONNECTIONS: u32 = 100;
/// The default number of messages the RPC server
/// is allowed to keep in memory per connection.
pub const RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN: u32 = 64;

/// Default configuration values used by Substrate
///
/// These values will be used by [`CliConfiguration`] to set
/// default values for e.g. the listen port or the RPC port.
pub trait DefaultConfigurationValues {
	/// The port Substrate should listen on for p2p connections.
	///
	/// By default this is `30333`.
	fn p2p_listen_port() -> u16 {
		30333
	}

	/// The port Substrate should listen on for JSON-RPC connections.
	///
	/// By default this is `9944`.
	fn rpc_listen_port() -> u16 {
		RPC_DEFAULT_PORT
	}

	/// The port Substrate should listen on for prometheus connections.
	///
	/// By default this is `9615`.
	fn prometheus_listen_port() -> u16 {
		9615
	}
}

impl DefaultConfigurationValues for () {}

/// A trait that allows converting an object to a Configuration
pub trait CliConfiguration<DCV: DefaultConfigurationValues = ()>: Sized {
	/// Get the SharedParams for this object
	fn shared_params(&self) -> &SharedParams;

	/// Get the ImportParams for this object
	fn import_params(&self) -> Option<&ImportParams> {
		None
	}

	/// Get the PruningParams for this object
	fn pruning_params(&self) -> Option<&PruningParams> {
		self.import_params().map(|x| &x.pruning_params)
	}

	/// Get the KeystoreParams for this object
	fn keystore_params(&self) -> Option<&KeystoreParams> {
		None
	}

	/// Get the NetworkParams for this object
	fn network_params(&self) -> Option<&NetworkParams> {
		None
	}

	/// Get a reference to `OffchainWorkerParams` for this object.
	fn offchain_worker_params(&self) -> Option<&OffchainWorkerParams> {
		None
	}

	/// Get the NodeKeyParams for this object
	fn node_key_params(&self) -> Option<&NodeKeyParams> {
		self.network_params().map(|x| &x.node_key_params)
	}

	/// Get the DatabaseParams for this object
	fn database_params(&self) -> Option<&DatabaseParams> {
		self.import_params().map(|x| &x.database_params)
	}

	/// Get the base path of the configuration (if any)
	///
	/// By default this is retrieved from `SharedParams`.
	fn base_path(&self) -> Result<Option<BasePath>> {
		self.shared_params().base_path()
	}

	/// Returns `true` if the node is for development or not
	///
	/// By default this is retrieved from `SharedParams`.
	fn is_dev(&self) -> Result<bool> {
		Ok(self.shared_params().is_dev())
	}

	/// Gets the role
	///
	/// By default this is `Role::Full`.
	fn role(&self, _is_dev: bool) -> Result<Role> {
		Ok(Role::Full)
	}

	/// Get the transaction pool options
	///
	/// By default this is `TransactionPoolOptions::default()`.
	fn transaction_pool(&self, _is_dev: bool) -> Result<TransactionPoolOptions> {
		Ok(Default::default())
	}

	/// Get the network configuration
	///
	/// By default this is retrieved from `NetworkParams` if it is available otherwise it creates
	/// a default `NetworkConfiguration` based on `node_name`, `client_id`, `node_key` and
	/// `net_config_dir`.
	fn network_config(
		&self,
		chain_spec: &Box<dyn ChainSpec>,
		is_dev: bool,
		is_validator: bool,
		net_config_dir: PathBuf,
		client_id: &str,
		node_name: &str,
		node_key: NodeKeyConfig,
		default_listen_port: u16,
	) -> Result<NetworkConfiguration> {
		let network_config = if let Some(network_params) = self.network_params() {
			network_params.network_config(
				chain_spec,
				is_dev,
				is_validator,
				Some(net_config_dir),
				client_id,
				node_name,
				node_key,
				default_listen_port,
			)
		} else {
			NetworkConfiguration::new(node_name, client_id, node_key, Some(net_config_dir))
		};

		// TODO: Return error here in the next release:
		// https://github.com/paritytech/polkadot-sdk/issues/5266
		// if is_validator && network_config.public_addresses.is_empty() {}

		Ok(network_config)
	}

	/// Get the keystore configuration.
	///
	/// By default this is retrieved from `KeystoreParams` if it is available. Otherwise it uses
	/// `KeystoreConfig::InMemory`.
	fn keystore_config(&self, config_dir: &PathBuf) -> Result<KeystoreConfig> {
		self.keystore_params()
			.map(|x| x.keystore_config(config_dir))
			.unwrap_or_else(|| Ok(KeystoreConfig::InMemory))
	}

	/// Get the database cache size.
	///
	/// By default this is retrieved from `DatabaseParams` if it is available. Otherwise its `None`.
	fn database_cache_size(&self) -> Result<Option<usize>> {
		Ok(self.database_params().map(|x| x.database_cache_size()).unwrap_or_default())
	}

	/// Get the database backend variant.
	///
	/// By default this is retrieved from `DatabaseParams` if it is available. Otherwise its `None`.
	fn database(&self) -> Result<Option<Database>> {
		Ok(self.database_params().and_then(|x| x.database()))
	}

	/// Get the database configuration object for the parameters provided
	fn database_config(
		&self,
		base_path: &PathBuf,
		cache_size: usize,
		database: Database,
	) -> Result<DatabaseSource> {
		let role_dir = "full";
		let rocksdb_path = base_path.join("db").join(role_dir);
		let paritydb_path = base_path.join("paritydb").join(role_dir);
		Ok(match database {
			#[cfg(feature = "rocksdb")]
			Database::RocksDb => DatabaseSource::RocksDb { path: rocksdb_path, cache_size },
			Database::ParityDb => DatabaseSource::ParityDb { path: paritydb_path },
			Database::ParityDbDeprecated => {
				eprintln!(
					"WARNING: \"paritydb-experimental\" database setting is deprecated and will be removed in future releases. \
				Please update your setup to use the new value: \"paritydb\"."
				);
				DatabaseSource::ParityDb { path: paritydb_path }
			},
			Database::Auto => DatabaseSource::Auto { paritydb_path, rocksdb_path, cache_size },
		})
	}

	/// Get the trie cache maximum size.
	///
	/// By default this is retrieved from `ImportParams` if it is available. Otherwise its `0`.
	/// If `None` is returned the trie cache is disabled.
	fn trie_cache_maximum_size(&self) -> Result<Option<usize>> {
		Ok(self.import_params().map(|x| x.trie_cache_maximum_size()).unwrap_or_default())
	}

	/// Get if we should warm up the trie cache.
	///
	/// By default this is retrieved from `ImportParams` if it is available. Otherwise its `None`.
	fn warm_up_trie_cache(&self) -> Result<Option<sc_service::config::TrieCacheWarmUpStrategy>> {
		Ok(self
			.import_params()
			.map(|x| x.warm_up_trie_cache().map(|x| x.into()))
			.unwrap_or_default())
	}

	/// Get the state pruning mode.
	///
	/// By default this is retrieved from `PruningMode` if it is available. Otherwise its
	/// `PruningMode::default()`.
	fn state_pruning(&self) -> Result<Option<PruningMode>> {
		self.pruning_params()
			.map(|x| x.state_pruning())
			.unwrap_or_else(|| Ok(Default::default()))
	}

	/// Get the block pruning mode.
	///
	/// By default this is retrieved from `block_pruning` if it is available. Otherwise its
	/// `BlocksPruning::KeepFinalized`.
	fn blocks_pruning(&self) -> Result<BlocksPruning> {
		self.pruning_params()
			.map(|x| x.blocks_pruning())
			.unwrap_or_else(|| Ok(BlocksPruning::KeepFinalized))
	}

	/// Get the chain ID (string).
	///
	/// By default this is retrieved from `SharedParams`.
	fn chain_id(&self, is_dev: bool) -> Result<String> {
		Ok(self.shared_params().chain_id(is_dev))
	}

	/// Get the name of the node.
	///
	/// By default a random name is generated.
	fn node_name(&self) -> Result<String> {
		Ok(generate_node_name())
	}

	/// Get the WASM execution method.
	///
	/// By default this is retrieved from `ImportParams` if it is available. Otherwise its
	/// `WasmExecutionMethod::default()`.
	fn wasm_method(&self) -> Result<WasmExecutionMethod> {
		Ok(self.import_params().map(|x| x.wasm_method()).unwrap_or_default())
	}

	/// Get the path where WASM overrides live.
	///
	/// By default this is `None`.
	fn wasm_runtime_overrides(&self) -> Option<PathBuf> {
		self.import_params().map(|x| x.wasm_runtime_overrides()).unwrap_or_default()
	}

	/// Get the RPC address.
	fn rpc_addr(&self, _default_listen_port: u16) -> Result<Option<Vec<RpcEndpoint>>> {
		Ok(None)
	}

	/// Returns the RPC method set to expose.
	///
	/// By default this is `RpcMethods::Auto` (unsafe RPCs are denied iff
	/// `rpc_external` returns true, respectively).
	fn rpc_methods(&self) -> Result<RpcMethods> {
		Ok(Default::default())
	}

	/// Get the maximum number of RPC server connections.
	fn rpc_max_connections(&self) -> Result<u32> {
		Ok(RPC_DEFAULT_MAX_CONNECTIONS)
	}

	/// Get the RPC cors (`None` if disabled)
	///
	/// By default this is `Some(Vec::new())`.
	fn rpc_cors(&self, _is_dev: bool) -> Result<Option<Vec<String>>> {
		Ok(Some(Vec::new()))
	}

	/// Get maximum RPC request payload size.
	fn rpc_max_request_size(&self) -> Result<u32> {
		Ok(RPC_DEFAULT_MAX_REQUEST_SIZE_MB)
	}

	/// Get maximum RPC response payload size.
	fn rpc_max_response_size(&self) -> Result<u32> {
		Ok(RPC_DEFAULT_MAX_RESPONSE_SIZE_MB)
	}

	/// Get maximum number of subscriptions per connection.
	fn rpc_max_subscriptions_per_connection(&self) -> Result<u32> {
		Ok(RPC_DEFAULT_MAX_SUBS_PER_CONN)
	}

	/// The number of messages the RPC server is allowed to keep in memory per connection.
	fn rpc_buffer_capacity_per_connection(&self) -> Result<u32> {
		Ok(RPC_DEFAULT_MESSAGE_CAPACITY_PER_CONN)
	}

	/// RPC server batch request configuration.
	fn rpc_batch_config(&self) -> Result<RpcBatchRequestConfig> {
		Ok(RpcBatchRequestConfig::Unlimited)
	}

	/// RPC rate limit configuration.
	fn rpc_rate_limit(&self) -> Result<Option<NonZeroU32>> {
		Ok(None)
	}

	/// RPC rate limit whitelisted ip addresses.
	fn rpc_rate_limit_whitelisted_ips(&self) -> Result<Vec<IpNetwork>> {
		Ok(vec![])
	}

	/// RPC rate limit trust proxy headers.
	fn rpc_rate_limit_trust_proxy_headers(&self) -> Result<bool> {
		Ok(false)
	}

	/// Get the prometheus configuration (`None` if disabled)
	///
	/// By default this is `None`.
	fn prometheus_config(
		&self,
		_default_listen_port: u16,
		_chain_spec: &Box<dyn ChainSpec>,
	) -> Result<Option<PrometheusConfig>> {
		Ok(None)
	}

	/// Get the telemetry endpoints (if any)
	///
	/// By default this is retrieved from the chain spec loaded by `load_spec`.
	fn telemetry_endpoints(
		&self,
		chain_spec: &Box<dyn ChainSpec>,
	) -> Result<Option<TelemetryEndpoints>> {
		Ok(chain_spec.telemetry_endpoints().clone())
	}

	/// Get the default value for heap pages
	///
	/// By default this is `None`.
	fn default_heap_pages(&self) -> Result<Option<u64>> {
		Ok(None)
	}

	/// Returns an offchain worker config wrapped in `Ok(_)`
	///
	/// By default offchain workers are disabled.
	fn offchain_worker(&self, role: &Role) -> Result<OffchainWorkerConfig> {
		self.offchain_worker_params()
			.map(|x| x.offchain_worker(role))
			.unwrap_or_else(|| Ok(OffchainWorkerConfig::default()))
	}

	/// Returns `Ok(true)` if authoring should be forced
	///
	/// By default this is `false`.
	fn force_authoring(&self) -> Result<bool> {
		Ok(Default::default())
	}

	/// Returns `Ok(true)` if grandpa should be disabled
	///
	/// By default this is `false`.
	fn disable_grandpa(&self) -> Result<bool> {
		Ok(Default::default())
	}

	/// Get the development key seed from the current object
	///
	/// By default this is `None`.
	fn dev_key_seed(&self, _is_dev: bool) -> Result<Option<String>> {
		Ok(Default::default())
	}

	/// Get the tracing targets from the current object (if any)
	///
	/// By default this is retrieved from [`SharedParams`] if it is available. Otherwise its
	/// `None`.
	fn tracing_targets(&self) -> Result<Option<String>> {
		Ok(self.shared_params().tracing_targets())
	}

	/// Get the TracingReceiver value from the current object
	///
	/// By default this is retrieved from [`SharedParams`] if it is available. Otherwise its
	/// `TracingReceiver::default()`.
	fn tracing_receiver(&self) -> Result<TracingReceiver> {
		Ok(self.shared_params().tracing_receiver())
	}

	/// Get the node key from the current object
	///
	/// By default this is retrieved from `NodeKeyParams` if it is available. Otherwise its
	/// `NodeKeyConfig::default()`.
	fn node_key(&self, net_config_dir: &PathBuf) -> Result<NodeKeyConfig> {
		let is_dev = self.is_dev()?;
		let role = self.role(is_dev)?;
		self.node_key_params()
			.map(|x| x.node_key(net_config_dir, role, is_dev))
			.unwrap_or_else(|| Ok(Default::default()))
	}

	/// Get maximum runtime instances
	///
	/// By default this is `None`.
	fn max_runtime_instances(&self) -> Result<Option<usize>> {
		Ok(Default::default())
	}

	/// Get maximum different runtimes in cache
	///
	/// By default this is `2`.
	fn runtime_cache_size(&self) -> Result<u8> {
		Ok(2)
	}

	/// Activate or not the automatic announcing of blocks after import
	///
	/// By default this is `false`.
	fn announce_block(&self) -> Result<bool> {
		Ok(true)
	}

	/// Create a Configuration object from the current object
	fn create_configuration<C: SubstrateCli>(
		&self,
		cli: &C,
		tokio_handle: tokio::runtime::Handle,
	) -> Result<Configuration> {
		let is_dev = self.is_dev()?;
		let chain_id = self.chain_id(is_dev)?;
		let chain_spec = cli.load_spec(&chain_id)?;
		let base_path = base_path_or_default(self.base_path()?, &C::executable_name());
		let config_dir = build_config_dir(&base_path, chain_spec.id());
		let net_config_dir = build_net_config_dir(&config_dir);
		let client_id = C::client_id();
		let database_cache_size = self.database_cache_size()?.unwrap_or(1024);
		let database = self.database()?.unwrap_or(
			#[cfg(feature = "rocksdb")]
			{
				Database::RocksDb
			},
			#[cfg(not(feature = "rocksdb"))]
			{
				Database::ParityDb
			},
		);
		let node_key = self.node_key(&net_config_dir)?;
		let role = self.role(is_dev)?;
		let max_runtime_instances = self.max_runtime_instances()?.unwrap_or(8);
		let is_validator = role.is_authority();
		let keystore = self.keystore_config(&config_dir)?;
		let telemetry_endpoints = self.telemetry_endpoints(&chain_spec)?;
		let runtime_cache_size = self.runtime_cache_size()?;

		let rpc_addrs: Option<Vec<sc_service::config::RpcEndpoint>> = self
			.rpc_addr(DCV::rpc_listen_port())?
			.map(|addrs| addrs.into_iter().map(Into::into).collect());

		Ok(Configuration {
			impl_name: C::impl_name(),
			impl_version: C::impl_version(),
			tokio_handle,
			transaction_pool: self.transaction_pool(is_dev)?,
			network: self.network_config(
				&chain_spec,
				is_dev,
				is_validator,
				net_config_dir,
				client_id.as_str(),
				self.node_name()?.as_str(),
				node_key,
				DCV::p2p_listen_port(),
			)?,
			keystore,
			database: self.database_config(&config_dir, database_cache_size, database)?,
			data_path: config_dir,
			trie_cache_maximum_size: self.trie_cache_maximum_size()?,
			warm_up_trie_cache: self.warm_up_trie_cache()?,
			state_pruning: self.state_pruning()?,
			blocks_pruning: self.blocks_pruning()?,
			executor: ExecutorConfiguration {
				wasm_method: self.wasm_method()?,
				default_heap_pages: self.default_heap_pages()?,
				max_runtime_instances,
				runtime_cache_size,
			},
			wasm_runtime_overrides: self.wasm_runtime_overrides(),
			rpc: RpcConfiguration {
				addr: rpc_addrs,
				methods: self.rpc_methods()?,
				max_connections: self.rpc_max_connections()?,
				cors: self.rpc_cors(is_dev)?,
				max_request_size: self.rpc_max_request_size()?,
				max_response_size: self.rpc_max_response_size()?,
				id_provider: None,
				max_subs_per_conn: self.rpc_max_subscriptions_per_connection()?,
				port: DCV::rpc_listen_port(),
				message_buffer_capacity: self.rpc_buffer_capacity_per_connection()?,
				batch_config: self.rpc_batch_config()?,
				rate_limit: self.rpc_rate_limit()?,
				rate_limit_whitelisted_ips: self.rpc_rate_limit_whitelisted_ips()?,
				rate_limit_trust_proxy_headers: self.rpc_rate_limit_trust_proxy_headers()?,
			},
			prometheus_config: self
				.prometheus_config(DCV::prometheus_listen_port(), &chain_spec)?,
			telemetry_endpoints,
			offchain_worker: self.offchain_worker(&role)?,
			force_authoring: self.force_authoring()?,
			disable_grandpa: self.disable_grandpa()?,
			dev_key_seed: self.dev_key_seed(is_dev)?,
			tracing_targets: self.tracing_targets()?,
			tracing_receiver: self.tracing_receiver()?,
			chain_spec,
			announce_block: self.announce_block()?,
			role,
			base_path,
		})
	}

	/// Get the filters for the logging.
	///
	/// This should be a list of comma-separated values.
	/// Example: `foo=trace,bar=debug,baz=info`
	///
	/// By default this is retrieved from `SharedParams`.
	fn log_filters(&self) -> Result<String> {
		Ok(self.shared_params().log_filters().join(","))
	}

	/// Should the detailed log output be enabled.
	fn detailed_log_output(&self) -> Result<bool> {
		Ok(self.shared_params().detailed_log_output())
	}

	/// Is log reloading enabled?
	fn enable_log_reloading(&self) -> Result<bool> {
		Ok(self.shared_params().enable_log_reloading())
	}

	/// Should the log color output be disabled?
	fn disable_log_color(&self) -> Result<bool> {
		Ok(self.shared_params().disable_log_color())
	}

	/// Initialize substrate. This must be done only once per process.
	///
	/// This method:
	///
	/// 1. Sets the panic handler
	/// 2. Optionally customize logger/profiling
	/// 2. Initializes the logger
	/// 3. Raises the FD limit
	///
	/// The `logger_hook` closure is executed before the logger is constructed
	/// and initialized. It is useful for setting up a custom profiler.
	///
	/// Example:
	/// ```
	/// use sc_tracing::{SpanDatum, TraceEvent};
	/// struct TestProfiler;
	///
	/// impl sc_tracing::TraceHandler for TestProfiler {
	///  	fn handle_span(&self, sd: &SpanDatum) {}
	/// 		fn handle_event(&self, _event: &TraceEvent) {}
	/// };
	///
	/// fn logger_hook() -> impl FnOnce(&mut sc_cli::LoggerBuilder, &sc_service::Configuration) -> () {
	/// 	|logger_builder, config| {
	/// 			logger_builder.with_custom_profiling(Box::new(TestProfiler{}));
	/// 	}
	/// }
	/// ```
	fn init<F>(&self, support_url: &String, impl_version: &String, logger_hook: F) -> Result<()>
	where
		F: FnOnce(&mut LoggerBuilder),
	{
		sp_panic_handler::set(support_url, impl_version);

		let mut logger = LoggerBuilder::new(self.log_filters()?);
		logger
			.with_log_reloading(self.enable_log_reloading()?)
			.with_detailed_output(self.detailed_log_output()?);

		if let Some(tracing_targets) = self.tracing_targets()? {
			let tracing_receiver = self.tracing_receiver()?;
			logger.with_profiling(tracing_receiver, tracing_targets);
		}

		if self.disable_log_color()? {
			logger.with_colors(false);
		}

		// Call hook for custom profiling setup.
		logger_hook(&mut logger);

		logger.init()?;

		match fdlimit::raise_fd_limit() {
			Ok(fdlimit::Outcome::LimitRaised { to, .. }) =>
				if to < RECOMMENDED_OPEN_FILE_DESCRIPTOR_LIMIT {
					warn!(
						"Low open file descriptor limit configured for the process. \
						Current value: {:?}, recommended value: {:?}.",
						to, RECOMMENDED_OPEN_FILE_DESCRIPTOR_LIMIT,
					);
				},
			Ok(fdlimit::Outcome::Unsupported) => {
				// Unsupported platform (non-Linux)
			},
			Err(error) => {
				warn!(
					"Failed to configure file descriptor limit for the process: \
					{}, recommended value: {:?}.",
					error, RECOMMENDED_OPEN_FILE_DESCRIPTOR_LIMIT,
				);
			},
		}

		Ok(())
	}
}

/// Generate a valid random name for the node
pub fn generate_node_name() -> String {
	loop {
		let node_name = Generator::with_naming(Name::Numbered)
			.next()
			.expect("RNG is available on all supported platforms; qed");
		let count = node_name.chars().count();

		if count < NODE_NAME_MAX_LENGTH {
			return node_name
		}
	}
}

/// Returns the value of `base_path` or the default_path if it is None
pub(crate) fn base_path_or_default(
	base_path: Option<BasePath>,
	executable_name: &String,
) -> BasePath {
	base_path.unwrap_or_else(|| BasePath::from_project("", "", executable_name))
}

/// Returns the default path for configuration  directory based on the chain_spec
pub(crate) fn build_config_dir(base_path: &BasePath, chain_spec_id: &str) -> PathBuf {
	base_path.config_dir(chain_spec_id)
}

/// Returns the default path for the network configuration inside the configuration dir
pub(crate) fn build_net_config_dir(config_dir: &PathBuf) -> PathBuf {
	config_dir.join(DEFAULT_NETWORK_CONFIG_PATH)
}

/// Returns the default path for the network directory starting from the provided base_path
/// or from the default base_path.
pub(crate) fn build_network_key_dir_or_default(
	base_path: Option<BasePath>,
	chain_spec_id: &str,
	executable_name: &String,
) -> PathBuf {
	let config_dir =
		build_config_dir(&base_path_or_default(base_path, executable_name), chain_spec_id);
	build_net_config_dir(&config_dir)
}
