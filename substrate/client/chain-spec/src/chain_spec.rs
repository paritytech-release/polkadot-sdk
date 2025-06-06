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

//! Substrate chain configurations.
#![warn(missing_docs)]
use crate::{
	extension::GetExtension, genesis_config_builder::HostFunctions, json_merge, ChainType,
	GenesisConfigBuilderRuntimeCaller as RuntimeCaller, Properties,
};
use sc_network::config::MultiaddrWithPeerId;
use sc_telemetry::TelemetryEndpoints;
use serde::{Deserialize, Serialize};
use serde_json as json;
use sp_core::{
	storage::{ChildInfo, Storage, StorageChild, StorageData, StorageKey},
	Bytes,
};
use sp_runtime::BuildStorage;
use std::{
	borrow::Cow,
	collections::{BTreeMap, VecDeque},
	fs::File,
	marker::PhantomData,
	path::PathBuf,
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum GenesisBuildAction<EHF> {
	/// Gets the default config (aka PresetId=None) and patches it.
	Patch(json::Value),
	/// Assumes that the full `RuntimeGenesisConfig` is supplied.
	Full(json::Value),
	/// Gets the named preset and applies an optional patch.
	NamedPreset(String, json::Value, PhantomData<EHF>),
}

impl<EHF> GenesisBuildAction<EHF> {
	pub fn merge_patch(&mut self, patch: json::Value) {
		match self {
			GenesisBuildAction::Patch(value) |
			GenesisBuildAction::Full(value) |
			GenesisBuildAction::NamedPreset(_, value, _) => json_merge(value, patch),
		}
	}
}

impl<EHF> Clone for GenesisBuildAction<EHF> {
	fn clone(&self) -> Self {
		match self {
			Self::Patch(ref p) => Self::Patch(p.clone()),
			Self::Full(ref f) => Self::Full(f.clone()),
			Self::NamedPreset(ref p, patch, _) =>
				Self::NamedPreset(p.clone(), patch.clone(), Default::default()),
		}
	}
}

enum GenesisSource<EHF> {
	File(PathBuf),
	Binary(Cow<'static, [u8]>),
	/// factory function + code
	Storage(Storage),
	/// build action + code
	GenesisBuilderApi(GenesisBuildAction<EHF>, Vec<u8>),
}

impl<EHF> Clone for GenesisSource<EHF> {
	fn clone(&self) -> Self {
		match *self {
			Self::File(ref path) => Self::File(path.clone()),
			Self::Binary(ref d) => Self::Binary(d.clone()),
			Self::Storage(ref s) => Self::Storage(s.clone()),
			Self::GenesisBuilderApi(ref s, ref c) => Self::GenesisBuilderApi(s.clone(), c.clone()),
		}
	}
}

impl<EHF: HostFunctions> GenesisSource<EHF> {
	fn resolve(&self) -> Result<Genesis, String> {
		/// helper container for deserializing genesis from the JSON file (ChainSpec JSON file is
		/// also supported here)
		#[derive(Serialize, Deserialize)]
		struct GenesisContainer {
			genesis: Genesis,
		}

		match self {
			Self::File(path) => {
				let file = File::open(path).map_err(|e| {
					format!("Error opening spec file at `{}`: {}", path.display(), e)
				})?;
				// SAFETY: `mmap` is fundamentally unsafe since technically the file can change
				//         underneath us while it is mapped; in practice it's unlikely to be a
				//         problem
				let bytes = unsafe {
					memmap2::Mmap::map(&file).map_err(|e| {
						format!("Error mmaping spec file `{}`: {}", path.display(), e)
					})?
				};

				let genesis: GenesisContainer = json::from_slice(&bytes)
					.map_err(|e| format!("Error parsing spec file: {}", e))?;
				Ok(genesis.genesis)
			},
			Self::Binary(buf) => {
				let genesis: GenesisContainer = json::from_reader(buf.as_ref())
					.map_err(|e| format!("Error parsing embedded file: {}", e))?;
				Ok(genesis.genesis)
			},
			Self::Storage(storage) => Ok(Genesis::Raw(RawGenesis::from(storage.clone()))),
			Self::GenesisBuilderApi(GenesisBuildAction::Full(config), code) =>
				Ok(Genesis::RuntimeGenesis(RuntimeGenesisInner {
					json_blob: RuntimeGenesisConfigJson::Config(config.clone()),
					code: code.clone(),
				})),
			Self::GenesisBuilderApi(GenesisBuildAction::Patch(patch), code) =>
				Ok(Genesis::RuntimeGenesis(RuntimeGenesisInner {
					json_blob: RuntimeGenesisConfigJson::Patch(patch.clone()),
					code: code.clone(),
				})),
			Self::GenesisBuilderApi(GenesisBuildAction::NamedPreset(name, patch, _), code) => {
				let mut preset =
					RuntimeCaller::<EHF>::new(&code[..]).get_named_preset(Some(name))?;
				json_merge(&mut preset, patch.clone());
				Ok(Genesis::RuntimeGenesis(RuntimeGenesisInner {
					json_blob: RuntimeGenesisConfigJson::Patch(preset),
					code: code.clone(),
				}))
			},
		}
	}
}

impl<E, EHF> BuildStorage for ChainSpec<E, EHF>
where
	EHF: HostFunctions,
{
	fn assimilate_storage(&self, storage: &mut Storage) -> Result<(), String> {
		match self.genesis.resolve()? {
			Genesis::Raw(RawGenesis { top: map, children_default: children_map }) => {
				storage.top.extend(map.into_iter().map(|(k, v)| (k.0, v.0)));
				children_map.into_iter().for_each(|(k, v)| {
					let child_info = ChildInfo::new_default(k.0.as_slice());
					storage
						.children_default
						.entry(k.0)
						.or_insert_with(|| StorageChild { data: Default::default(), child_info })
						.data
						.extend(v.into_iter().map(|(k, v)| (k.0, v.0)));
				});
			},
			// The `StateRootHash` variant exists as a way to keep note that other clients support
			// it, but Substrate itself isn't capable of loading chain specs with just a hash at the
			// moment.
			Genesis::StateRootHash(_) =>
				return Err("Genesis storage in hash format not supported".into()),
			Genesis::RuntimeGenesis(RuntimeGenesisInner {
				json_blob: RuntimeGenesisConfigJson::Config(config),
				code,
			}) => {
				RuntimeCaller::<EHF>::new(&code[..])
					.get_storage_for_config(config)?
					.assimilate_storage(storage)?;
				storage
					.top
					.insert(sp_core::storage::well_known_keys::CODE.to_vec(), code.clone());
			},
			Genesis::RuntimeGenesis(RuntimeGenesisInner {
				json_blob: RuntimeGenesisConfigJson::Patch(patch),
				code,
			}) => {
				RuntimeCaller::<EHF>::new(&code[..])
					.get_storage_for_patch(patch)?
					.assimilate_storage(storage)?;
				storage
					.top
					.insert(sp_core::storage::well_known_keys::CODE.to_vec(), code.clone());
			},
		};

		Ok(())
	}
}

pub type GenesisStorage = BTreeMap<StorageKey, StorageData>;

/// Raw storage content for genesis block.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RawGenesis {
	pub top: GenesisStorage,
	pub children_default: BTreeMap<StorageKey, GenesisStorage>,
}

impl From<sp_core::storage::Storage> for RawGenesis {
	fn from(value: sp_core::storage::Storage) -> Self {
		Self {
			top: value.top.into_iter().map(|(k, v)| (StorageKey(k), StorageData(v))).collect(),
			children_default: value
				.children_default
				.into_iter()
				.map(|(sk, child)| {
					(
						StorageKey(sk),
						child
							.data
							.into_iter()
							.map(|(k, v)| (StorageKey(k), StorageData(v)))
							.collect(),
					)
				})
				.collect(),
		}
	}
}

/// Inner representation of [`Genesis::RuntimeGenesis`] format
#[derive(Serialize, Deserialize, Debug)]
struct RuntimeGenesisInner {
	/// Runtime wasm code, expected to be hex-encoded in JSON.
	/// The code shall be capable of parsing `json_blob`.
	#[serde(default, with = "sp_core::bytes")]
	code: Vec<u8>,
	/// The patch or full representation of runtime's `RuntimeGenesisConfig` struct.
	#[serde(flatten)]
	json_blob: RuntimeGenesisConfigJson,
}

/// Represents two possible variants of the contained JSON blob for the
/// [`Genesis::RuntimeGenesis`] format.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
enum RuntimeGenesisConfigJson {
	/// Represents the explicit and comprehensive runtime genesis config in JSON format.
	/// The contained object is a JSON blob that can be parsed by a compatible runtime.
	///
	/// Using a full config is useful for when someone wants to ensure that a change in the runtime
	/// makes the deserialization fail and not silently add some default values.
	Config(json::Value),
	/// Represents a patch for the default runtime genesis config in JSON format which is
	/// essentially a list of keys that are to be customized in runtime genesis config.
	/// The contained value is a JSON blob that can be parsed by a compatible runtime.
	Patch(json::Value),
}

/// Represents the different formats of the genesis state within chain spec JSON blob.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
enum Genesis {
	/// The genesis storage as raw data. Typically raw key-value entries in state.
	Raw(RawGenesis),
	/// State root hash of the genesis storage.
	StateRootHash(StorageData),
	/// Represents the runtime genesis config in JSON format together with runtime code.
	RuntimeGenesis(RuntimeGenesisInner),
}

/// A configuration of a client. Does not include runtime storage initialization.
/// Note: `genesis` field is ignored due to way how the chain specification is serialized into
/// JSON file. Refer to [`ChainSpecJsonContainer`], which flattens [`ClientSpec`] and denies unknown
/// fields.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
// we cannot #[serde(deny_unknown_fields)]. Otherwise chain-spec-builder will fail on any
// non-standard spec
struct ClientSpec<E> {
	name: String,
	id: String,
	#[serde(default)]
	chain_type: ChainType,
	boot_nodes: Vec<MultiaddrWithPeerId>,
	telemetry_endpoints: Option<TelemetryEndpoints>,
	protocol_id: Option<String>,
	/// Arbitrary string. Nodes will only synchronize with other nodes that have the same value
	/// in their `fork_id`. This can be used in order to segregate nodes in cases when multiple
	/// chains have the same genesis hash.
	#[serde(default = "Default::default", skip_serializing_if = "Option::is_none")]
	fork_id: Option<String>,
	properties: Option<Properties>,
	#[serde(flatten)]
	extensions: E,
	// Never used, left only for backward compatibility.
	#[serde(default, skip_serializing)]
	#[allow(unused)]
	consensus_engine: (),
	#[serde(skip_serializing)]
	#[allow(unused)]
	genesis: serde::de::IgnoredAny,
	/// Mapping from `block_number` to `wasm_code`.
	///
	/// The given `wasm_code` will be used to substitute the on-chain wasm code starting with the
	/// given block number until the `spec_version` on chain changes.
	#[serde(default)]
	code_substitutes: BTreeMap<String, Bytes>,
}

/// A type denoting empty extensions.
///
/// We use `Option` here since `()` is not flattenable by serde.
pub type NoExtension = Option<()>;

/// Builder for creating [`ChainSpec`] instances.
pub struct ChainSpecBuilder<E = NoExtension, EHF = ()> {
	code: Vec<u8>,
	extensions: E,
	name: String,
	id: String,
	chain_type: ChainType,
	genesis_build_action: GenesisBuildAction<EHF>,
	boot_nodes: Option<Vec<MultiaddrWithPeerId>>,
	telemetry_endpoints: Option<TelemetryEndpoints>,
	protocol_id: Option<String>,
	fork_id: Option<String>,
	properties: Option<Properties>,
}

impl<E, EHF> ChainSpecBuilder<E, EHF> {
	/// Creates a new builder instance with no defaults.
	pub fn new(code: &[u8], extensions: E) -> Self {
		Self {
			code: code.into(),
			extensions,
			name: "Development".to_string(),
			id: "dev".to_string(),
			chain_type: ChainType::Local,
			genesis_build_action: GenesisBuildAction::Patch(json::json!({})),
			boot_nodes: None,
			telemetry_endpoints: None,
			protocol_id: None,
			fork_id: None,
			properties: None,
		}
	}

	/// Sets the spec name.
	pub fn with_name(mut self, name: &str) -> Self {
		self.name = name.into();
		self
	}

	/// Sets the spec ID.
	pub fn with_id(mut self, id: &str) -> Self {
		self.id = id.into();
		self
	}

	/// Sets the type of the chain.
	pub fn with_chain_type(mut self, chain_type: ChainType) -> Self {
		self.chain_type = chain_type;
		self
	}

	/// Sets a list of bootnode addresses.
	pub fn with_boot_nodes(mut self, boot_nodes: Vec<MultiaddrWithPeerId>) -> Self {
		self.boot_nodes = Some(boot_nodes);
		self
	}

	/// Sets telemetry endpoints.
	pub fn with_telemetry_endpoints(mut self, telemetry_endpoints: TelemetryEndpoints) -> Self {
		self.telemetry_endpoints = Some(telemetry_endpoints);
		self
	}

	/// Sets the network protocol ID.
	pub fn with_protocol_id(mut self, protocol_id: &str) -> Self {
		self.protocol_id = Some(protocol_id.into());
		self
	}

	/// Sets an optional network fork identifier.
	pub fn with_fork_id(mut self, fork_id: &str) -> Self {
		self.fork_id = Some(fork_id.into());
		self
	}

	/// Sets additional loosely-typed properties of the chain.
	pub fn with_properties(mut self, properties: Properties) -> Self {
		self.properties = Some(properties);
		self
	}

	/// Sets chain spec extensions.
	pub fn with_extensions(mut self, extensions: E) -> Self {
		self.extensions = extensions;
		self
	}

	/// Sets the code.
	pub fn with_code(mut self, code: &[u8]) -> Self {
		self.code = code.into();
		self
	}

	/// Applies a patch to whatever genesis build action is set.
	pub fn with_genesis_config_patch(mut self, patch: json::Value) -> Self {
		self.genesis_build_action.merge_patch(patch);
		self
	}

	/// Sets the name of runtime-provided JSON patch for runtime's GenesisConfig.
	pub fn with_genesis_config_preset_name(mut self, name: &str) -> Self {
		self.genesis_build_action =
			GenesisBuildAction::NamedPreset(name.to_string(), json::json!({}), Default::default());
		self
	}

	/// Sets the full runtime's GenesisConfig JSON.
	pub fn with_genesis_config(mut self, config: json::Value) -> Self {
		self.genesis_build_action = GenesisBuildAction::Full(config);
		self
	}

	/// Builds a [`ChainSpec`] instance using the provided settings.
	pub fn build(self) -> ChainSpec<E, EHF> {
		let client_spec = ClientSpec {
			name: self.name,
			id: self.id,
			chain_type: self.chain_type,
			boot_nodes: self.boot_nodes.unwrap_or_default(),
			telemetry_endpoints: self.telemetry_endpoints,
			protocol_id: self.protocol_id,
			fork_id: self.fork_id,
			properties: self.properties,
			extensions: self.extensions,
			consensus_engine: (),
			genesis: Default::default(),
			code_substitutes: BTreeMap::new(),
		};

		ChainSpec {
			client_spec,
			genesis: GenesisSource::GenesisBuilderApi(self.genesis_build_action, self.code.into()),
			_host_functions: Default::default(),
		}
	}
}

/// A configuration of a chain. Can be used to build a genesis block.
///
/// The chain spec is generic over the native `RuntimeGenesisConfig` struct (`G`). It is also
/// possible to parametrize chain spec over the extended host functions (EHF). It should be use if
/// runtime is using the non-standard host function during genesis state creation.
pub struct ChainSpec<E = NoExtension, EHF = ()> {
	client_spec: ClientSpec<E>,
	genesis: GenesisSource<EHF>,
	_host_functions: PhantomData<EHF>,
}

impl<E: Clone, EHF> Clone for ChainSpec<E, EHF> {
	fn clone(&self) -> Self {
		ChainSpec {
			client_spec: self.client_spec.clone(),
			genesis: self.genesis.clone(),
			_host_functions: self._host_functions,
		}
	}
}

impl<E, EHF> ChainSpec<E, EHF> {
	/// A list of bootnode addresses.
	pub fn boot_nodes(&self) -> &[MultiaddrWithPeerId] {
		&self.client_spec.boot_nodes
	}

	/// Spec name.
	pub fn name(&self) -> &str {
		&self.client_spec.name
	}

	/// Spec id.
	pub fn id(&self) -> &str {
		&self.client_spec.id
	}

	/// Telemetry endpoints (if any)
	pub fn telemetry_endpoints(&self) -> &Option<TelemetryEndpoints> {
		&self.client_spec.telemetry_endpoints
	}

	/// Network protocol id.
	pub fn protocol_id(&self) -> Option<&str> {
		self.client_spec.protocol_id.as_deref()
	}

	/// Optional network fork identifier.
	pub fn fork_id(&self) -> Option<&str> {
		self.client_spec.fork_id.as_deref()
	}

	/// Additional loosely-typed properties of the chain.
	///
	/// Returns an empty JSON object if 'properties' not defined in config
	pub fn properties(&self) -> Properties {
		self.client_spec.properties.as_ref().unwrap_or(&json::map::Map::new()).clone()
	}

	/// Add a bootnode to the list.
	pub fn add_boot_node(&mut self, addr: MultiaddrWithPeerId) {
		self.client_spec.boot_nodes.push(addr)
	}

	/// Returns a reference to the defined chain spec extensions.
	pub fn extensions(&self) -> &E {
		&self.client_spec.extensions
	}

	/// Returns a mutable reference to the defined chain spec extensions.
	pub fn extensions_mut(&mut self) -> &mut E {
		&mut self.client_spec.extensions
	}

	/// Type of the chain.
	fn chain_type(&self) -> ChainType {
		self.client_spec.chain_type.clone()
	}

	/// Provides a `ChainSpec` builder.
	pub fn builder(code: &[u8], extensions: E) -> ChainSpecBuilder<E, EHF> {
		ChainSpecBuilder::new(code, extensions)
	}
}

impl<E: serde::de::DeserializeOwned, EHF> ChainSpec<E, EHF> {
	/// Parse json content into a `ChainSpec`
	pub fn from_json_bytes(json: impl Into<Cow<'static, [u8]>>) -> Result<Self, String> {
		let json = json.into();
		let client_spec = json::from_slice(json.as_ref())
			.map_err(|e| format!("Error parsing spec file: {}", e))?;

		Ok(ChainSpec {
			client_spec,
			genesis: GenesisSource::Binary(json),
			_host_functions: Default::default(),
		})
	}

	/// Parse json file into a `ChainSpec`
	pub fn from_json_file(path: PathBuf) -> Result<Self, String> {
		// We mmap the file into memory first, as this is *a lot* faster than using
		// `serde_json::from_reader`. See https://github.com/serde-rs/json/issues/160
		let file = File::open(&path)
			.map_err(|e| format!("Error opening spec file `{}`: {}", path.display(), e))?;

		// SAFETY: `mmap` is fundamentally unsafe since technically the file can change
		//         underneath us while it is mapped; in practice it's unlikely to be a problem
		let bytes = unsafe {
			memmap2::Mmap::map(&file)
				.map_err(|e| format!("Error mmaping spec file `{}`: {}", path.display(), e))?
		};
		let client_spec =
			json::from_slice(&bytes).map_err(|e| format!("Error parsing spec file: {}", e))?;

		Ok(ChainSpec {
			client_spec,
			genesis: GenesisSource::File(path),
			_host_functions: Default::default(),
		})
	}
}

/// Helper structure for serializing (and only serializing) the ChainSpec into JSON file. It
/// represents the layout of `ChainSpec` JSON file.
#[derive(Serialize, Deserialize)]
// we cannot #[serde(deny_unknown_fields)]. Otherwise chain-spec-builder will fail on any
// non-standard spec.
struct ChainSpecJsonContainer<E> {
	#[serde(flatten)]
	client_spec: ClientSpec<E>,
	genesis: Genesis,
}

impl<E: serde::Serialize + Clone + 'static, EHF> ChainSpec<E, EHF>
where
	EHF: HostFunctions,
{
	fn json_container(&self, raw: bool) -> Result<ChainSpecJsonContainer<E>, String> {
		let raw_genesis = match (raw, self.genesis.resolve()?) {
			(
				true,
				Genesis::RuntimeGenesis(RuntimeGenesisInner {
					json_blob: RuntimeGenesisConfigJson::Config(config),
					code,
				}),
			) => {
				let mut storage =
					RuntimeCaller::<EHF>::new(&code[..]).get_storage_for_config(config)?;
				storage.top.insert(sp_core::storage::well_known_keys::CODE.to_vec(), code);
				RawGenesis::from(storage)
			},
			(
				true,
				Genesis::RuntimeGenesis(RuntimeGenesisInner {
					json_blob: RuntimeGenesisConfigJson::Patch(patch),
					code,
				}),
			) => {
				let mut storage =
					RuntimeCaller::<EHF>::new(&code[..]).get_storage_for_patch(patch)?;
				storage.top.insert(sp_core::storage::well_known_keys::CODE.to_vec(), code);
				RawGenesis::from(storage)
			},
			(true, Genesis::Raw(raw)) => raw,
			(_, genesis) =>
				return Ok(ChainSpecJsonContainer { client_spec: self.client_spec.clone(), genesis }),
		};

		Ok(ChainSpecJsonContainer {
			client_spec: self.client_spec.clone(),
			genesis: Genesis::Raw(raw_genesis),
		})
	}

	/// Dump the chain specification to JSON string.
	pub fn as_json(&self, raw: bool) -> Result<String, String> {
		let container = self.json_container(raw)?;
		json::to_string_pretty(&container).map_err(|e| format!("Error generating spec json: {}", e))
	}
}

impl<E, EHF> crate::ChainSpec for ChainSpec<E, EHF>
where
	E: GetExtension + serde::Serialize + Clone + Send + Sync + 'static,
	EHF: HostFunctions,
{
	fn boot_nodes(&self) -> &[MultiaddrWithPeerId] {
		ChainSpec::boot_nodes(self)
	}

	fn name(&self) -> &str {
		ChainSpec::name(self)
	}

	fn id(&self) -> &str {
		ChainSpec::id(self)
	}

	fn chain_type(&self) -> ChainType {
		ChainSpec::chain_type(self)
	}

	fn telemetry_endpoints(&self) -> &Option<TelemetryEndpoints> {
		ChainSpec::telemetry_endpoints(self)
	}

	fn protocol_id(&self) -> Option<&str> {
		ChainSpec::protocol_id(self)
	}

	fn fork_id(&self) -> Option<&str> {
		ChainSpec::fork_id(self)
	}

	fn properties(&self) -> Properties {
		ChainSpec::properties(self)
	}

	fn add_boot_node(&mut self, addr: MultiaddrWithPeerId) {
		ChainSpec::add_boot_node(self, addr)
	}

	fn extensions(&self) -> &dyn GetExtension {
		ChainSpec::extensions(self) as &dyn GetExtension
	}

	fn extensions_mut(&mut self) -> &mut dyn GetExtension {
		ChainSpec::extensions_mut(self) as &mut dyn GetExtension
	}

	fn as_json(&self, raw: bool) -> Result<String, String> {
		ChainSpec::as_json(self, raw)
	}

	fn as_storage_builder(&self) -> &dyn BuildStorage {
		self
	}

	fn cloned_box(&self) -> Box<dyn crate::ChainSpec> {
		Box::new(self.clone())
	}

	fn set_storage(&mut self, storage: Storage) {
		self.genesis = GenesisSource::Storage(storage);
	}

	fn code_substitutes(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
		self.client_spec
			.code_substitutes
			.iter()
			.map(|(h, c)| (h.clone(), c.0.clone()))
			.collect()
	}
}

/// The `fun` will be called with the value at `path`.
///
/// If exists, the value at given `path` will be passed to the `fun` and the result of `fun`
/// call will be returned. Otherwise false is returned.
/// `path` will be modified.
///
/// # Examples
/// ```ignore
/// use serde_json::{from_str, json, Value};
/// let doc = json!({"a":{"b":{"c":"5"}}});
/// let mut path = ["a", "b", "c"].into();
/// assert!(json_eval_value_at_key(&doc, &mut path, &|v| { assert_eq!(v,"5"); true }));
/// ```
fn json_eval_value_at_key(
	doc: &json::Value,
	path: &mut VecDeque<&str>,
	fun: &dyn Fn(&json::Value) -> bool,
) -> bool {
	let Some(key) = path.pop_front() else { return false };

	if path.is_empty() {
		doc.as_object().map_or(false, |o| o.get(key).map_or(false, |v| fun(v)))
	} else {
		doc.as_object()
			.map_or(false, |o| o.get(key).map_or(false, |v| json_eval_value_at_key(v, path, fun)))
	}
}

macro_rules! json_path {
	[ $($x:expr),+ ] => {
		VecDeque::<&str>::from([$($x),+])
	};
}

fn json_contains_path(doc: &json::Value, path: &mut VecDeque<&str>) -> bool {
	json_eval_value_at_key(doc, path, &|_| true)
}

/// This function updates the code in given chain spec.
///
/// Function support updating the runtime code in provided JSON chain spec blob. `Genesis::Raw`
/// and `Genesis::RuntimeGenesis` formats are supported.
///
/// If update was successful `true` is returned, otherwise `false`. Chain spec JSON is modified in
/// place.
pub fn update_code_in_json_chain_spec(chain_spec: &mut json::Value, code: &[u8]) -> bool {
	let mut path = json_path!["genesis", "runtimeGenesis", "code"];
	let mut raw_path = json_path!["genesis", "raw", "top"];

	if json_contains_path(&chain_spec, &mut path) {
		#[derive(Serialize)]
		struct Container<'a> {
			#[serde(with = "sp_core::bytes")]
			code: &'a [u8],
		}
		let code_patch = json::json!({"genesis":{"runtimeGenesis": Container { code }}});
		crate::json_patch::merge(chain_spec, code_patch);
		true
	} else if json_contains_path(&chain_spec, &mut raw_path) {
		#[derive(Serialize)]
		struct Container<'a> {
			#[serde(with = "sp_core::bytes", rename = "0x3a636f6465")]
			code: &'a [u8],
		}
		let code_patch = json::json!({"genesis":{"raw":{"top": Container { code }}}});
		crate::json_patch::merge(chain_spec, code_patch);
		true
	} else {
		false
	}
}

/// This function sets a codeSubstitute in the chain spec.
pub fn set_code_substitute_in_json_chain_spec(
	chain_spec: &mut json::Value,
	code: &[u8],
	block_height: u64,
) {
	let substitutes = json::json!({"codeSubstitutes":{ &block_height.to_string(): sp_core::bytes::to_hex(code, false) }});
	crate::json_patch::merge(chain_spec, substitutes);
}

#[cfg(test)]
mod tests {
	use super::*;
	use pretty_assertions::assert_eq;
	use serde_json::{from_str, json, Value};
	use sp_application_crypto::Ss58Codec;
	use sp_core::storage::well_known_keys;
	use sp_keyring::Sr25519Keyring;

	type TestSpec = ChainSpec;

	#[test]
	fn should_deserialize_example_chain_spec() {
		let spec1 = TestSpec::from_json_bytes(Cow::Owned(
			include_bytes!("../res/chain_spec.json").to_vec(),
		))
		.unwrap();
		let spec2 = TestSpec::from_json_file(PathBuf::from("./res/chain_spec.json")).unwrap();

		assert_eq!(spec1.as_json(false), spec2.as_json(false));
		assert_eq!(spec2.chain_type(), ChainType::Live)
	}

	#[derive(Debug, Serialize, Deserialize, Clone)]
	#[serde(rename_all = "camelCase")]
	struct Extension1 {
		my_property: String,
	}

	impl crate::Extension for Extension1 {
		type Forks = Option<()>;

		fn get<T: 'static>(&self) -> Option<&T> {
			None
		}

		fn get_any(&self, _: std::any::TypeId) -> &dyn std::any::Any {
			self
		}

		fn get_any_mut(&mut self, _: std::any::TypeId) -> &mut dyn std::any::Any {
			self
		}
	}

	type TestSpec2 = ChainSpec<Extension1>;

	#[test]
	fn should_deserialize_chain_spec_with_extensions() {
		let spec = TestSpec2::from_json_bytes(Cow::Owned(
			include_bytes!("../res/chain_spec2.json").to_vec(),
		))
		.unwrap();

		assert_eq!(spec.extensions().my_property, "Test Extension");
	}

	#[test]
	fn chain_spec_raw_output_should_be_deterministic() {
		let mut spec = TestSpec2::from_json_bytes(Cow::Owned(
			include_bytes!("../res/chain_spec2.json").to_vec(),
		))
		.unwrap();

		let mut storage = spec.build_storage().unwrap();

		// Add some extra data, so that storage "sorting" is tested.
		let extra_data = &[("random_key", "val"), ("r@nd0m_key", "val"), ("aaarandom_key", "val")];
		storage
			.top
			.extend(extra_data.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec())));
		crate::ChainSpec::set_storage(&mut spec, storage);

		let json = spec.as_json(true).unwrap();

		// Check multiple times that decoding and encoding the chain spec leads always to the same
		// output.
		for _ in 0..10 {
			assert_eq!(
				json,
				TestSpec2::from_json_bytes(json.as_bytes().to_vec())
					.unwrap()
					.as_json(true)
					.unwrap()
			);
		}
	}

	#[test]
	// some tests for json path utils
	fn test_json_eval_value_at_key() {
		let doc = json!({"a":{"b1":"20","b":{"c":{"d":"10"}}}});

		assert!(json_eval_value_at_key(&doc, &mut json_path!["a", "b1"], &|v| { *v == "20" }));
		assert!(json_eval_value_at_key(&doc, &mut json_path!["a", "b", "c", "d"], &|v| {
			*v == "10"
		}));
		assert!(!json_eval_value_at_key(&doc, &mut json_path!["a", "c", "d"], &|_| { true }));
		assert!(!json_eval_value_at_key(&doc, &mut json_path!["d"], &|_| { true }));

		assert!(json_contains_path(&doc, &mut json_path!["a", "b1"]));
		assert!(json_contains_path(&doc, &mut json_path!["a", "b"]));
		assert!(json_contains_path(&doc, &mut json_path!["a", "b", "c"]));
		assert!(json_contains_path(&doc, &mut json_path!["a", "b", "c", "d"]));
		assert!(!json_contains_path(&doc, &mut json_path!["a", "b", "c", "d", "e"]));
		assert!(!json_contains_path(&doc, &mut json_path!["a", "b", "b1"]));
		assert!(!json_contains_path(&doc, &mut json_path!["d"]));
	}

	fn zeroize_code_key_in_json(encoded: bool, json: &str) -> Value {
		let mut json = from_str::<Value>(json).unwrap();
		let (zeroing_patch, mut path) = if encoded {
			(
				json!({"genesis":{"raw":{"top":{"0x3a636f6465":"0x0"}}}}),
				json_path!["genesis", "raw", "top", "0x3a636f6465"],
			)
		} else {
			(
				json!({"genesis":{"runtimeGenesis":{"code":"0x0"}}}),
				json_path!["genesis", "runtimeGenesis", "code"],
			)
		};
		assert!(json_contains_path(&json, &mut path));
		crate::json_patch::merge(&mut json, zeroing_patch);
		json
	}

	#[docify::export]
	#[test]
	fn build_chain_spec_with_patch_works() {
		let output = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config_patch(json!({
			"babe": {
				"epochConfig": {
					"c": [
						7,
						10
					],
					"allowed_slots": "PrimaryAndSecondaryPlainSlots"
				}
			},
			"substrateTest": {
				"authorities": [
					Sr25519Keyring::Ferdie.public().to_ss58check(),
					Sr25519Keyring::Alice.public().to_ss58check()
				],
			}
		}))
		.build();

		let raw_chain_spec = output.as_json(true);
		assert!(raw_chain_spec.is_ok());
	}

	#[test]
	fn generate_chain_spec_with_named_preset_works() {
		sp_tracing::try_init_simple();
		let output: ChainSpec<()> = ChainSpec::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config_preset_name("staging")
		.build();

		let actual = output.as_json(false).unwrap();
		let expected =
			from_str::<Value>(include_str!("../res/substrate_test_runtime_from_named_preset.json"))
				.unwrap();

		//wasm blob may change overtime so let's zero it. Also ensure it is there:
		let actual = zeroize_code_key_in_json(false, actual.as_str());

		assert_eq!(actual, expected);
	}

	#[test]
	fn generate_chain_spec_with_patch_works() {
		let output = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config_patch(json!({
			"babe": {
				"epochConfig": {
					"c": [
						7,
						10
					],
					"allowed_slots": "PrimaryAndSecondaryPlainSlots"
				}
			},
			"substrateTest": {
				"authorities": [
					Sr25519Keyring::Ferdie.public().to_ss58check(),
					Sr25519Keyring::Alice.public().to_ss58check()
				],
			}
		}))
		.build();

		let actual = output.as_json(false).unwrap();
		let actual_raw = output.as_json(true).unwrap();

		let expected =
			from_str::<Value>(include_str!("../res/substrate_test_runtime_from_patch.json"))
				.unwrap();
		let expected_raw =
			from_str::<Value>(include_str!("../res/substrate_test_runtime_from_patch_raw.json"))
				.unwrap();

		//wasm blob may change overtime so let's zero it. Also ensure it is there:
		let actual = zeroize_code_key_in_json(false, actual.as_str());
		let actual_raw = zeroize_code_key_in_json(true, actual_raw.as_str());

		assert_eq!(actual, expected);
		assert_eq!(expected_raw, actual_raw);
	}

	#[test]
	fn generate_chain_spec_with_full_config_works() {
		let j = include_str!("../../../test-utils/runtime/res/default_genesis_config.json");
		let output = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config(from_str(j).unwrap())
		.build();

		let actual = output.as_json(false).unwrap();
		let actual_raw = output.as_json(true).unwrap();

		let expected =
			from_str::<Value>(include_str!("../res/substrate_test_runtime_from_config.json"))
				.unwrap();
		let expected_raw =
			from_str::<Value>(include_str!("../res/substrate_test_runtime_from_config_raw.json"))
				.unwrap();

		//wasm blob may change overtime so let's zero it. Also ensure it is there:
		let actual = zeroize_code_key_in_json(false, actual.as_str());
		let actual_raw = zeroize_code_key_in_json(true, actual_raw.as_str());

		assert_eq!(actual, expected);
		assert_eq!(expected_raw, actual_raw);
	}

	#[test]
	fn chain_spec_as_json_fails_with_invalid_config() {
		let invalid_genesis_config = from_str::<Value>(include_str!(
			"../../../test-utils/runtime/res/default_genesis_config_invalid_2.json"
		))
		.unwrap();
		let output = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config(invalid_genesis_config.clone())
		.build();

		let result = output.as_json(true).unwrap_err();
		let mut result = result.lines();

		let result_header = result.next().unwrap();
		let result_body = result.collect::<Vec<&str>>().join("\n");
		let result_body: Value = serde_json::from_str(&result_body).unwrap();

		let re = regex::Regex::new(concat!(
			r"^Invalid JSON blob: unknown field `babex`, expected one of `system`, `babe`, ",
			r"`substrateTest`, `balances` at line \d+ column \d+ for blob:$"
		))
		.unwrap();

		assert_eq!(json!({"a":1,"b":2}), json!({"b":2,"a":1}));
		assert!(re.is_match(result_header));
		assert_eq!(invalid_genesis_config, result_body);
	}

	#[test]
	fn chain_spec_as_json_fails_with_invalid_patch() {
		let output = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config_patch(json!({
			"invalid_pallet": {},
			"substrateTest": {
				"authorities": [
					Sr25519Keyring::Ferdie.public().to_ss58check(),
					Sr25519Keyring::Alice.public().to_ss58check()
				],
			}
		}))
		.build();

		assert!(output.as_json(true).unwrap_err().contains("Invalid JSON blob: unknown field `invalid_pallet`, expected one of `system`, `babe`, `substrateTest`, `balances`"));
	}

	#[test]
	fn check_if_code_is_valid_for_raw_without_code() {
		let spec = ChainSpec::<()>::from_json_bytes(Cow::Owned(
			include_bytes!("../res/raw_no_code.json").to_vec(),
		))
		.unwrap();

		let j = from_str::<Value>(&spec.as_json(true).unwrap()).unwrap();

		assert!(json_eval_value_at_key(
			&j,
			&mut json_path!["genesis", "raw", "top", "0x3a636f6465"],
			&|v| { *v == "0x010101" }
		));
		assert!(!json_contains_path(&j, &mut json_path!["code"]));
	}

	#[test]
	fn check_code_in_assimilated_storage_for_raw_without_code() {
		let spec = ChainSpec::<()>::from_json_bytes(Cow::Owned(
			include_bytes!("../res/raw_no_code.json").to_vec(),
		))
		.unwrap();

		let storage = spec.build_storage().unwrap();
		assert!(storage
			.top
			.get(&well_known_keys::CODE.to_vec())
			.map(|v| *v == vec![1, 1, 1])
			.unwrap())
	}

	#[test]
	fn update_code_works_with_runtime_genesis_config() {
		let j = include_str!("../../../test-utils/runtime/res/default_genesis_config.json");
		let chain_spec = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config(from_str(j).unwrap())
		.build();

		let mut chain_spec_json = from_str::<Value>(&chain_spec.as_json(false).unwrap()).unwrap();
		assert!(update_code_in_json_chain_spec(&mut chain_spec_json, &[0, 1, 2, 4, 5, 6]));

		assert!(json_eval_value_at_key(
			&chain_spec_json,
			&mut json_path!["genesis", "runtimeGenesis", "code"],
			&|v| { *v == "0x000102040506" }
		));
	}

	#[test]
	fn update_code_works_for_raw() {
		let j = include_str!("../../../test-utils/runtime/res/default_genesis_config.json");
		let chain_spec = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config(from_str(j).unwrap())
		.build();

		let mut chain_spec_json = from_str::<Value>(&chain_spec.as_json(true).unwrap()).unwrap();
		assert!(update_code_in_json_chain_spec(&mut chain_spec_json, &[0, 1, 2, 4, 5, 6]));

		assert!(json_eval_value_at_key(
			&chain_spec_json,
			&mut json_path!["genesis", "raw", "top", "0x3a636f6465"],
			&|v| { *v == "0x000102040506" }
		));
	}

	#[test]
	fn update_code_works_with_runtime_genesis_patch() {
		let chain_spec = ChainSpec::<()>::builder(
			substrate_test_runtime::wasm_binary_unwrap().into(),
			Default::default(),
		)
		.with_name("TestName")
		.with_id("test_id")
		.with_chain_type(ChainType::Local)
		.with_genesis_config_patch(json!({}))
		.build();

		let mut chain_spec_json = from_str::<Value>(&chain_spec.as_json(false).unwrap()).unwrap();
		assert!(update_code_in_json_chain_spec(&mut chain_spec_json, &[0, 1, 2, 4, 5, 6]));

		assert!(json_eval_value_at_key(
			&chain_spec_json,
			&mut json_path!["genesis", "runtimeGenesis", "code"],
			&|v| { *v == "0x000102040506" }
		));
	}
}
