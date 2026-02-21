//! OpenCL 内核加载与执行

use ocl::{Buffer, Event, Kernel, Program, SpatialDims};
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
    /// 每线程最终检查次数缓冲区
    thread_checked_buffer: Buffer<u64>,
    /// 每线程缓冲区长度
    thread_checked_len: usize,
    /// 非阻塞读取 found 标志的主机缓冲
    flag_read_buf: Vec<i32>,
    /// 非阻塞读取 found 标志的事件
    flag_read_event: Option<Event>,
}

impl SearchKernel {
    /// 创建新的搜索内核
    /// 
    /// # Arguments
    /// * `ctx` - OpenCL 上下文
    /// * `kernel_source` - OpenCL C 内核源代码
    pub fn new(ctx: &OpenCLContext, kernel_source: &str, thread_checked_len: usize) -> anyhow::Result<Self> {
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

        let thread_checked_buffer = Buffer::<u64>::builder()
            .queue(ctx.queue.clone())
            .flags(ocl::flags::MEM_READ_WRITE)
            .len(thread_checked_len)
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
            .arg(&thread_checked_buffer)
            .build()?;
        
        Ok(Self {
            program,
            kernel,
            config_buffer,
            result_buffer,
            flag_buffer,
            thread_checked_buffer,
            thread_checked_len,
            flag_read_buf: vec![0],
            flag_read_event: None,
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
        
        // 清空每线程计数缓冲区，避免残留
        let zero_counts = vec![0u64; self.thread_checked_len];
        self.thread_checked_buffer.write(&zero_counts).enq()?;

        unsafe {
            self.kernel.cmd()
                .global_work_size(gws)
                .enq()?;
        }
        
        Ok(())
    }

    /// 读取总检查次数（主机侧对每线程计数求和）
    pub fn read_total_checked(&self, active_threads: usize) -> anyhow::Result<u64> {
        let n = active_threads.min(self.thread_checked_len);
        let mut counts = vec![0u64; n];
        self.thread_checked_buffer.read(&mut counts).enq()?;
        let total: u128 = counts.into_iter().map(|v| v as u128).sum();
        Ok(total.min(u64::MAX as u128) as u64)
    }
    
    /// 非阻塞轮询 found 标志
    /// - Ok(Some(bool)): 读取完成，返回 found 状态
    /// - Ok(None): 读取尚未完成
    pub fn poll_found(&mut self) -> anyhow::Result<Option<bool>> {
        if self.flag_read_event.is_none() {
            let mut evt = Event::empty();
            unsafe {
                self.flag_buffer
                    .cmd()
                    .read(&mut self.flag_read_buf)
                    .block(false)
                    .enew(&mut evt)
                    .enq()?;
            }
            self.flag_read_event = Some(evt);
            return Ok(None);
        }

        if let Some(ref evt) = self.flag_read_event {
            if evt.is_complete()? {
                let found = self.flag_read_buf[0] != 0;
                self.flag_read_event = None;
                return Ok(Some(found));
            }
        }

        Ok(None)
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
