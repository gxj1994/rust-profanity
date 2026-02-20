//! OpenCL GPU 计算模块

pub mod context;
pub mod kernel;

pub use context::OpenCLContext;
pub use kernel::SearchKernel;
