//! GPU以太坊靓号地址搜索系统 - Rust + OpenCL 实现
//!
//! 本库提供了一个基于 GPU 加速的以太坊靓号地址搜索工具。
//! 使用 OpenCL 在 GPU 上并行搜索符合条件的以太坊地址。

pub mod config;
pub mod kernel_loader;
pub mod mnemonic;
pub mod opencl;

pub use config::{SearchConfig, SearchResult, PatternConfig, ConditionType, SourceMode, TargetChain, parse_prefix_condition, parse_suffix_condition, parse_leading_zeros_condition, parse_pattern_condition};
pub use kernel_loader::load_kernel_source;
pub use mnemonic::Mnemonic;
pub use opencl::{OpenCLContext, SearchKernel};
