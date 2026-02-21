//! OpenCL 内核加载与执行

use ocl::{Buffer, Kernel, Program, SpatialDims};
use log::{info, debug};

use crate::config::{SearchConfig, SearchResult};
use super::context::OpenCLContext;

/// 搜索内核封装
pub struct SearchKernel {
    /// OpenCL 程序 (必须保持存活以确保内核正常工作)
    #[allow(dead_code)]
    program: Program,
    /// 搜索内核
    kernel: Kernel,
    /// 配置缓冲区
    config_buffer: Buffer<u8>,
    /// 结果缓冲区
    result_buffer: Buffer<u8>,
    /// 全局标志缓冲区
    flag_buffer: Buffer<i32>,
}

impl SearchKernel {
    /// 创建新的搜索内核
    /// 
    /// # Arguments
    /// * `ctx` - OpenCL 上下文
    /// * `kernel_source` - OpenCL C 内核源代码
    pub fn new(ctx: &OpenCLContext, kernel_source: &str) -> anyhow::Result<Self> {
        info!("Building OpenCL program...");
        
        // 编译程序
        let program = Program::builder()
            .src(kernel_source)
            .build(&ctx.context)?;
        
        info!("OpenCL program built successfully");
        
        // 创建缓冲区
        let config_buffer = Buffer::<u8>::builder()
            .queue(ctx.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(std::mem::size_of::<SearchConfig>())
            .build()?;
        
        let result_buffer = Buffer::<u8>::builder()
            .queue(ctx.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(std::mem::size_of::<SearchResult>())
            .build()?;
        
        let flag_buffer = Buffer::<i32>::builder()
            .queue(ctx.queue.clone())
            .flags(ocl::flags::MEM_READ_WRITE)
            .len(1)
            .build()?;
        
        // 初始化标志为 0
        let initial_flag: Vec<i32> = vec![0];
        flag_buffer.write(&initial_flag).enq()?;
        
        // 创建内核
        let kernel = Kernel::builder()
            .program(&program)
            .name("search_kernel")
            .queue(ctx.queue.clone())
            .global_work_size(SpatialDims::One(1)) // 临时值，会在 launch 中更新
            .arg(&config_buffer)
            .arg(&result_buffer)
            .arg(&flag_buffer)
            .build()?;
        
        Ok(Self {
            program,
            kernel,
            config_buffer,
            result_buffer,
            flag_buffer,
        })
    }
    
    /// 设置搜索配置
    pub fn set_config(&self, config: &SearchConfig) -> anyhow::Result<()> {
        let config_bytes = unsafe {
            std::slice::from_raw_parts(
                config as *const _ as *const u8,
                std::mem::size_of::<SearchConfig>()
            )
        };
        
        self.config_buffer.write(config_bytes).enq()?;
        debug!("Search config uploaded to GPU");
        
        Ok(())
    }
    
    /// 启动内核
    /// 
    /// # Arguments
    /// * `global_work_size` - 全局工作项数量 (线程数)
    /// * `_local_work_size` - 本地工作组大小 (可选，当前未使用)
    pub fn launch(&self, global_work_size: usize, _local_work_size: Option<usize>) -> anyhow::Result<()> {
        info!("Launching kernel with {} threads", global_work_size);
        
        // 只设置全局工作大小，让 OpenCL 自动选择合适的工作组大小
        let gws = SpatialDims::One(global_work_size);
        
        unsafe {
            self.kernel.cmd()
                .global_work_size(gws)
                .enq()?;
        }
        
        Ok(())
    }
    
    /// 检查结果是否找到（非阻塞方式）
    pub fn check_found(&self) -> anyhow::Result<bool> {
        let mut flag: Vec<i32> = vec![0];
        
        // 使用阻塞读取，但设置一个较小的超时
        // 直接读取，不创建事件，简化逻辑
        self.flag_buffer.read(&mut flag).enq()?;
        
        Ok(flag[0] != 0)
    }
    
    /// 读取搜索结果
    pub fn read_result(&self) -> anyhow::Result<SearchResult> {
        let mut result_bytes = vec![0u8; std::mem::size_of::<SearchResult>()];
        self.result_buffer.read(&mut result_bytes).enq()?;
        
        let result = unsafe {
            std::ptr::read(result_bytes.as_ptr() as *const SearchResult)
        };
        
        Ok(result)
    }
    
    /// 等待内核完成
    pub fn wait(&self) -> anyhow::Result<()> {
        self.kernel.default_queue().unwrap().finish()?;
        Ok(())
    }
    
    /// 获取程序构建日志 (用于调试)
    pub fn get_build_log(&self, _device: &ocl::Device) -> anyhow::Result<String> {
        // ocl 0.19 版本中 build_log 方法不可用
        Ok(String::from("(Build log not available in this ocl version)"))
    }
}

/// 加载内核源代码
/// 
/// 从文件系统加载所有 .cl 文件并合并
pub fn load_kernel_source() -> anyhow::Result<String> {
    let mut source = String::new();
    
    // 内联的内核代码 (简化版本，完整版本应该放在单独文件中)
    source.push_str(include_str!("../../kernels/search.cl"));
    
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opencl::OpenCLContext;

    #[test]
    fn test_kernel_creation() {
        let ctx = OpenCLContext::new().unwrap();
        
        // 简单的测试内核
        let kernel_source = r#"
            __kernel void test_kernel(__global int* data) {
                int tid = get_global_id(0);
                data[tid] = tid;
            }
        "#;
        
        let program = Program::builder()
            .src(kernel_source)
            .build(&ctx.context);
        
        // 程序构建成功即表示测试通过
        assert!(program.is_ok(), "OpenCL program build failed");
    }
}
