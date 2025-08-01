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

mod command;
mod logging;
mod types;
mod writer;

use crate::shared::HostInfoParams;
use clap::ValueEnum;
use frame_support::Serialize;
use sc_cli::{
	WasmExecutionMethod, WasmtimeInstantiationStrategy, DEFAULT_WASMTIME_INSTANTIATION_STRATEGY,
	DEFAULT_WASM_EXECUTION_METHOD,
};
use std::{fmt::Debug, path::PathBuf};

/// Logging target
const LOG_TARGET: &'static str = "frame::benchmark::pallet";

// Add a more relaxed parsing for pallet names by allowing pallet directory names with `-` to be
// used like crate names with `_`
fn parse_pallet_name(pallet: &str) -> std::result::Result<String, String> {
	Ok(pallet.replace("-", "_"))
}

/// List options for available benchmarks.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ListOutput {
	/// List all available pallets and extrinsics.
	All,
	/// List all available pallets only.
	Pallets,
}

/// Benchmark the extrinsic weight of FRAME Pallets.
#[derive(Debug, clap::Parser)]
pub struct PalletCmd {
	/// Select a FRAME Pallets to benchmark, or `*` for all (in which case `extrinsic` must be
	/// `*`).
	#[arg(short, long, alias = "pallet", num_args = 1.., value_delimiter = ',', value_parser = parse_pallet_name, required_unless_present_any = ["list", "json_input", "all"], default_value_if("all", "true", Some("*".into())))]
	pub pallets: Vec<String>,

	/// Select an extrinsic inside the pallet to benchmark, or `*` or 'all' for all.
	#[arg(short, long, required_unless_present_any = ["list", "json_input", "all"], default_value_if("all", "true", Some("*".into())))]
	pub extrinsic: Option<String>,

	/// Comma separated list of pallets that should be excluded from the benchmark.
	#[arg(long, value_parser, num_args = 1.., value_delimiter = ',')]
	pub exclude_pallets: Vec<String>,

	/// Comma separated list of `pallet::extrinsic` combinations that should not be run.
	///
	/// Example: `frame_system::remark,pallet_balances::transfer_keep_alive`
	#[arg(long, value_parser, num_args = 1.., value_delimiter = ',')]
	pub exclude_extrinsics: Vec<String>,

	/// Run benchmarks for all pallets and extrinsics.
	///
	/// This is equivalent to running `--pallet * --extrinsic *`.
	#[arg(long)]
	pub all: bool,

	/// Select how many samples we should take across the variable components.
	#[arg(short, long, default_value_t = 50)]
	pub steps: u32,

	/// Indicates lowest values for each of the component ranges.
	#[arg(long = "low", value_delimiter = ',')]
	pub lowest_range_values: Vec<u32>,

	/// Indicates highest values for each of the component ranges.
	#[arg(long = "high", value_delimiter = ',')]
	pub highest_range_values: Vec<u32>,

	/// Select how many repetitions of this benchmark should run from within the wasm.
	#[arg(short, long, default_value_t = 20)]
	pub repeat: u32,

	/// Select how many repetitions of this benchmark should run from the client.
	///
	/// NOTE: Using this alone may give slower results, but will afford you maximum Wasm memory.
	#[arg(long, default_value_t = 1)]
	pub external_repeat: u32,

	/// Print the raw results in JSON format.
	#[arg(long = "json")]
	pub json_output: bool,

	/// Write the raw results in JSON format into the given file.
	#[arg(long, conflicts_with = "json_output")]
	pub json_file: Option<PathBuf>,

	/// Don't print the median-slopes linear regression analysis.
	#[arg(long)]
	pub no_median_slopes: bool,

	/// Don't print the min-squares linear regression analysis.
	#[arg(long)]
	pub no_min_squares: bool,

	/// Output the benchmarks to a Rust file at the given path.
	#[arg(long)]
	pub output: Option<PathBuf>,

	/// Add a header file to your outputted benchmarks.
	#[arg(long)]
	pub header: Option<PathBuf>,

	/// Path to Handlebars template file used for outputting benchmark results. (Optional)
	#[arg(long)]
	pub template: Option<PathBuf>,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub hostinfo_params: HostInfoParams,

	/// Which analysis function to use when outputting benchmarks:
	/// * min-squares (default)
	/// * median-slopes
	/// * max (max of min squares and median slopes for each value)
	#[arg(long)]
	pub output_analysis: Option<String>,

	/// Which analysis function to use when analyzing measured proof sizes.
	#[arg(long, default_value("median-slopes"))]
	pub output_pov_analysis: Option<String>,

	/// The PoV estimation mode of a benchmark if no `pov_mode` attribute is present.
	#[arg(long, default_value("max-encoded-len"), value_enum)]
	pub default_pov_mode: command::PovEstimationMode,

	/// Ignore the error when PoV modes reference unknown storage items or pallets.
	#[arg(long)]
	pub ignore_unknown_pov_mode: bool,

	/// Set the heap pages while running benchmarks. If not set, the default value from the client
	/// is used.
	#[arg(long)]
	pub heap_pages: Option<u64>,

	/// Disable verification logic when running benchmarks.
	#[arg(long)]
	pub no_verify: bool,

	/// Display and run extra benchmarks that would otherwise not be needed for weight
	/// construction.
	#[arg(long)]
	pub extra: bool,

	#[allow(missing_docs)]
	#[clap(flatten)]
	pub shared_params: sc_cli::SharedParams,

	/// Method for executing Wasm runtime code.
	#[arg(
		long = "wasm-execution",
		value_name = "METHOD",
		value_enum,
		ignore_case = true,
		default_value_t = DEFAULT_WASM_EXECUTION_METHOD,
	)]
	pub wasm_method: WasmExecutionMethod,

	/// The WASM instantiation method to use.
	///
	/// Only has an effect when `wasm-execution` is set to `compiled`.
	#[arg(
		long = "wasm-instantiation-strategy",
		value_name = "STRATEGY",
		default_value_t = DEFAULT_WASMTIME_INSTANTIATION_STRATEGY,
		value_enum,
	)]
	pub wasmtime_instantiation_strategy: WasmtimeInstantiationStrategy,

	/// Optional runtime blob to use instead of the one from the genesis config.
	#[arg(long, conflicts_with = "chain", required_if_eq("genesis_builder", "runtime"))]
	pub runtime: Option<PathBuf>,

	/// Set the runtime log level.
	///
	/// This will overwrite the `RUNTIME_LOG` environment variable. If neither is set, the CLI
	/// default set by `RUST_LOG` setting is used.
	#[arg(long)]
	pub runtime_log: Option<String>,

	/// Do not fail if there are unknown but also unused host functions in the runtime.
	#[arg(long)]
	pub allow_missing_host_functions: bool,

	/// How to construct the genesis state.
	///
	/// Uses `GenesisBuilderPolicy::Spec` by default.
	#[arg(long, value_enum, alias = "genesis-builder-policy")]
	pub genesis_builder: Option<GenesisBuilderPolicy>,

	/// The preset that we expect to find in the GenesisBuilder runtime API.
	///
	/// This can be useful when a runtime has a dedicated benchmarking preset instead of using the
	/// default one.
	#[arg(long, default_value = sp_genesis_builder::DEV_RUNTIME_PRESET)]
	pub genesis_builder_preset: String,

	/// DEPRECATED: This argument has no effect.
	#[arg(long = "execution")]
	pub execution: Option<String>,

	/// Limit the memory the database cache can use.
	#[arg(long = "db-cache", value_name = "MiB", default_value_t = 1024)]
	pub database_cache_size: u32,

	/// List and print available benchmarks in a csv-friendly format.
	///
	/// NOTE: `num_args` and `require_equals` are required to allow `--list`
	#[arg(long, value_enum, ignore_case = true, num_args = 0..=1, require_equals = true, default_missing_value("All"))]
	pub list: Option<ListOutput>,

	/// Don't include csv header when listing benchmarks.
	#[arg(long, requires("list"))]
	pub no_csv_header: bool,

	/// If enabled, the storage info is not displayed in the output next to the analysis.
	///
	/// This is independent of the storage info appearing in the *output file*. Use a Handlebar
	/// template for that purpose.
	#[arg(long)]
	pub no_storage_info: bool,

	/// The assumed default maximum size of any `StorageMap`.
	///
	/// When the maximum size of a map is not defined by the runtime developer,
	/// this value is used as a worst case scenario. It will affect the calculated worst case
	/// PoV size for accessing a value in a map, since the PoV will need to include the trie
	/// nodes down to the underlying value.
	#[clap(long = "map-size", default_value = "1000000")]
	pub worst_case_map_values: u32,

	/// Adjust the PoV estimation by adding additional trie layers to it.
	///
	/// This should be set to `log16(n)` where `n` is the number of top-level storage items in the
	/// runtime, eg. `StorageMap`s and `StorageValue`s. A value of 2 to 3 is usually sufficient.
	/// Each layer will result in an additional 495 bytes PoV per distinct top-level access.
	/// Therefore multiple `StorageMap` accesses only suffer from this increase once. The exact
	/// number of storage items depends on the runtime and the deployed pallets.
	#[clap(long, default_value = "2")]
	pub additional_trie_layers: u8,

	/// A path to a `.json` file with existing benchmark results generated with `--json` or
	/// `--json-file`. When specified the benchmarks are not actually executed, and the data for
	/// the analysis is read from this file.
	#[arg(long)]
	pub json_input: Option<PathBuf>,

	/// Allow overwriting a single file with multiple results.
	///
	/// This exists only to restore legacy behaviour. It should never actually be needed.
	#[arg(long)]
	pub unsafe_overwrite_results: bool,

	/// Do not print a summary at the end of the run.
	///
	/// These summaries can be very long when benchmarking multiple pallets at once. For CI
	/// use-cases, this option reduces the noise.
	#[arg(long)]
	quiet: bool,

	/// Do not enable proof recording during time benchmarking.
	///
	/// By default, proof recording is enabled during benchmark execution. This can slightly
	/// inflate the resulting time weights. For parachains using PoV-reclaim, this is typically the
	/// correct setting. Chains that ignore the proof size dimension of weight (e.g. relay chain,
	/// solo-chains) can disable proof recording to get more accurate results.
	#[arg(long)]
	disable_proof_recording: bool,
}

/// How the genesis state for benchmarking should be built.
#[derive(clap::ValueEnum, Debug, Eq, PartialEq, Clone, Copy, Serialize)]
#[clap(rename_all = "kebab-case")]
pub enum GenesisBuilderPolicy {
	/// Do not provide any genesis state.
	///
	/// Benchmarks are advised to function with this, since they should setup their own required
	/// state. However, to keep backwards compatibility, this is not the default.
	None,
	/// Let the runtime build the genesis state through its `BuildGenesisConfig` runtime API.
	/// This will use the `development` preset by default.
	Runtime,
	/// Use the runtime from the Spec file to build the genesis state.
	SpecRuntime,
	/// Use the spec file to build the genesis state. This fails when there is no spec.
	#[value(alias = "spec")]
	SpecGenesis,
}
