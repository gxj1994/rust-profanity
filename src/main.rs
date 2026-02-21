//! GPU以太坊靓号地址搜索系统 - 主程序
//!
//! 使用方式:
//!   cargo run -- --prefix 8888 --threads 1024
//!   cargo run -- --suffix dead --threads 2048
//!   cargo run -- --leading-zeros 4 --threads 4096

use clap::Parser;
use log::info;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{self, Write};
use std::thread::sleep;
use std::time::{Duration, Instant};

use rust_profanity::{
    config::{*, PatternConfig},
    load_kernel_source,
    mnemonic::Mnemonic,
    opencl::{OpenCLContext, SearchKernel},
};

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum SourceModeArg {
    Mnemonic,
    PrivateKey,
}

impl From<SourceModeArg> for SourceMode {
    fn from(value: SourceModeArg) -> Self {
        match value {
            SourceModeArg::Mnemonic => SourceMode::MnemonicEntropy,
            SourceModeArg::PrivateKey => SourceMode::PrivateKey,
        }
    }
}

/// 命令行参数
#[derive(Parser, Debug)]
#[command(name = "rust-profanity")]
#[command(about = "GPU以太坊靓号地址搜索系统")]
#[command(version = "0.1.0")]
struct Args {
    /// 前缀匹配 (十六进制，如 8888)
    #[arg(long, group = "condition")]
    prefix: Option<String>,
    
    /// 后缀匹配 (十六进制，如 dead)
    #[arg(long, group = "condition")]
    suffix: Option<String>,
    
    /// 前导零个数 (至少)
    #[arg(long, group = "condition")]
    leading_zeros: Option<u32>,
    
    /// 模式匹配 (完整地址模式，如 0xXXXXXXXXXXXXdeadXXXXXXXXXXXXXXXXXXXXXXXX)
    /// X/*/? 表示通配符，其他字符表示需要匹配的值
    #[arg(long, group = "condition")]
    pattern: Option<String>,
    
    /// GPU 线程数
    #[arg(short, long, default_value = "1024")]
    threads: u32,
    
    /// 本地工作组大小
    #[arg(short, long, default_value = "128")]
    work_group_size: usize,
    
    /// 轮询间隔 (毫秒)
    #[arg(long, default_value = "250")]
    poll_interval: u64,
    
    /// 超时时间 (秒，0表示无超时)
    #[arg(long, default_value = "0")]
    timeout: u64,

    /// 地址搜索来源模式: mnemonic(助记词) / private-key(直接私钥)
    #[arg(long, value_enum, default_value = "mnemonic")]
    source_mode: SourceModeArg,

    /// 启用多 GPU 并行 (自动使用全部可用 GPU)
    #[arg(long, default_value_t = false)]
    multi_gpu: bool,
}

/// 解析搜索条件
fn parse_condition(args: &Args) -> anyhow::Result<(u64, Option<PatternConfig>)> {
    if let Some(prefix) = &args.prefix {
        info!("搜索条件: 前缀匹配 {}", prefix);
        Ok((parse_prefix_condition(prefix)?, None))
    } else if let Some(suffix) = &args.suffix {
        info!("搜索条件: 后缀匹配 {}", suffix);
        Ok((parse_suffix_condition(suffix)?, None))
    } else if let Some(zeros) = args.leading_zeros {
        info!("搜索条件: 前导零至少 {} 个", zeros);
        Ok((parse_leading_zeros_condition(zeros)?, None))
    } else if let Some(pattern) = &args.pattern {
        info!("搜索条件: 模式匹配 {}", pattern);
        let (condition, pattern_config) = parse_pattern_condition(pattern)?;
        Ok((condition, Some(pattern_config)))
    } else {
        anyhow::bail!("请指定搜索条件: --prefix, --suffix, --leading-zeros 或 --pattern")
    }
}



/// 打印进度到同一行（仅显示运行时间）
fn print_progress_line(elapsed: f64) {
    print!("\r[搜索中] 已运行 {:>6.1}s", elapsed);
    io::stdout().flush().unwrap();
}

/// 清除当前进度行
fn clear_progress_line() {
    print!("\r{:>40}\r", " ");
    io::stdout().flush().unwrap();
}

fn random_nonzero_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    if seed.iter().all(|&b| b == 0) {
        seed[31] = 1;
    }
    seed
}

fn seed_with_offset(base_seed: [u8; 32], offset: u64) -> [u8; 32] {
    let mut out = base_seed;
    let mut carry = offset;
    for b in out.iter_mut().rev() {
        let sum = (*b as u64) + (carry & 0xFF);
        *b = (sum & 0xFF) as u8;
        carry = (carry >> 8) + (sum >> 8);
        if carry == 0 {
            break;
        }
    }
    out
}

fn split_threads(total_threads: usize, workers: usize) -> Vec<usize> {
    if workers == 0 {
        return Vec::new();
    }
    let base = total_threads / workers;
    let remainder = total_threads % workers;
    (0..workers)
        .map(|i| base + usize::from(i < remainder))
        .collect()
}

struct SearchWorker {
    ctx: OpenCLContext,
    kernel: SearchKernel,
    threads: usize,
}

/// 主函数
fn main() -> anyhow::Result<()> {
    // 初始化日志
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    
    // 解析命令行参数
    let args = Args::parse();
    info!("启动 GPU以太坊靓号地址搜索系统");
    info!("参数: {:?}", args);
    
    let source_mode: SourceMode = args.source_mode.into();
    
    // 1. 生成随机种子
    let base_seed = random_nonzero_seed();
    match source_mode {
        SourceMode::MnemonicEntropy => {
            info!("来源模式: 助记词熵派生");
            info!("搜索空间: {} 个线程从随机熵开始并行遍历", args.threads);
        }
        SourceMode::PrivateKey => {
            info!("来源模式: 直接私钥遍历");
            info!("搜索空间: {} 个线程从随机私钥开始并行遍历", args.threads);
        }
    }
    
    // 2. 解析搜索条件
    let (condition, pattern_config) = parse_condition(&args)?;
    info!("条件编码: 0x{:016X}", condition);
    
    // 3. 初始化 OpenCL
    info!("初始化 OpenCL...");
    let contexts = if args.multi_gpu {
        let gpu_contexts = OpenCLContext::all_gpu_contexts()?;
        if gpu_contexts.is_empty() {
            info!("未检测到多个 GPU，回退到默认设备");
            vec![OpenCLContext::new()?]
        } else {
            gpu_contexts
        }
    } else {
        vec![OpenCLContext::new()?]
    };
    for ctx in &contexts {
        ctx.print_device_info()?;
    }

    let thread_plan = split_threads(args.threads as usize, contexts.len());

    // 4. 加载并编译内核
    info!("加载 OpenCL 内核...");
    // 使用完整版内核 (包含完整加密实现)
    let kernel_source = load_kernel_source()?;
    let mut workers = Vec::new();
    for (idx, (ctx, threads)) in contexts.into_iter().zip(thread_plan.into_iter()).enumerate() {
        if threads == 0 {
            let device_name = ctx.device.name().unwrap_or_else(|_| String::from("<unknown>"));
            info!("跳过设备 #{idx} ({device_name})，分配线程为 0");
            continue;
        }

        let device_name = ctx.device.name().unwrap_or_else(|_| String::from("<unknown>"));
        let kernel = SearchKernel::new(&ctx, &kernel_source, threads)?;
        let worker_seed = seed_with_offset(base_seed, idx as u64 + 1);
        let config = if let Some(pattern) = pattern_config {
            SearchConfig::new_with_pattern(worker_seed, threads as u32, condition, pattern)
        } else {
            SearchConfig::new(worker_seed, threads as u32, condition)
        }
        .with_source_mode(source_mode)
        .with_target_chain(TargetChain::Ethereum);
        kernel.set_config(&config)?;
        info!("设备 #{idx}: {device_name}，分配线程: {threads}");
        workers.push(SearchWorker { ctx, kernel, threads });
    }
    if workers.is_empty() {
        anyhow::bail!("可用设备的线程分配结果为空，请提高 --threads 或关闭 --multi-gpu");
    }

    // 6. 启动内核
    info!("启动搜索内核，设备数: {}，总线程数: {}", workers.len(), args.threads);
    let start_time = Instant::now();
    for worker in &workers {
        worker.kernel.launch(worker.threads, Some(args.work_group_size))?;
    }
    
    // 7. 轮询等待结果并读取
    info!("开始轮询等待结果...");
    let mut found = None;
    let mut progress_printed = false;
    let timeout_enabled = args.timeout > 0;
    let timeout_secs = args.timeout;
    let mut result = SearchResult::default();
    
    loop {
        let elapsed_secs = start_time.elapsed().as_secs();
        let is_timeout = timeout_enabled && elapsed_secs >= timeout_secs;
        
        // 检查超时（优先于找到结果，强制终止）
        if is_timeout {
            info!("搜索超时 ({} 秒)", timeout_secs);
            break;
        }
        
        // 检查是否找到（原子读取标志）
        for (idx, worker) in workers.iter_mut().enumerate() {
            if let Some(is_found) = worker.kernel.poll_found()? {
                if is_found {
                    found = Some(idx);
                    result = worker.kernel.read_result()?;
                    break;
                }
            }
        }
        if found.is_some() {
            break;
        }
        
        // 显示进度（仅运行时间）
        let elapsed = start_time.elapsed().as_secs_f64();
        print_progress_line(elapsed);
        progress_printed = true;
        
        // 等待一段时间再检查
        sleep(Duration::from_millis(args.poll_interval));
    }
    
    if progress_printed {
        clear_progress_line();
    }

    // 如果超时但还未读取到结果，尝试读取一次
    if found.is_none() {
        for (idx, worker) in workers.iter().enumerate() {
            if let Ok(r) = worker.kernel.read_result() {
                if r.found != 0 {
                    found = Some(idx);
                    result = r;
                    break;
                }
            }
        }
    }
    
    let elapsed = start_time.elapsed();
    let is_timeout = timeout_enabled && elapsed.as_secs() >= timeout_secs;
    
    // 9. 输出结果
    println!();
    println!("========================================");

    let total_checked: u64 = workers
        .iter()
        .map(|w| w.kernel.read_total_checked(w.threads).unwrap_or(0))
        .sum();
    let total_checked = if total_checked > 0 {
        total_checked
    } else {
        result.total_checked()
    };
    let speed = if elapsed.as_secs_f64() > 0.0 {
        total_checked as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    
    if found.is_some() && result.found != 0 {
        println!("✓ 找到符合条件的地址!");
        println!("========================================");
        println!("以太坊地址: 0x{}", hex::encode(result.eth_address));

        match source_mode {
            SourceMode::MnemonicEntropy => {
                // 从熵生成助记词，确保校验和正确
                let mnemonic = Mnemonic::from_entropy(&result.result_seed)
                    .expect("从熵生成助记词失败");
                println!("助记词: {}", mnemonic);
            }
            SourceMode::PrivateKey => {
                println!("私钥: 0x{}", hex::encode(result.result_seed));
            }
        }

        println!("找到线程: {}", result.found_by_thread);
        if let Some(worker_idx) = found {
            let device_name = workers[worker_idx]
                .ctx
                .device
                .name()
                .unwrap_or_else(|_| String::from("<unknown>"));
            println!("找到设备: #{} {}", worker_idx, device_name);
        }
    } else if found.is_none() && is_timeout {
        println!("✗ 搜索超时 ({} 秒) - 强制终止", timeout_secs);
    } else {
        println!("✗ 未找到符合条件的地址");
    }
    
    println!("搜索时间: {:.2} 秒", elapsed.as_secs_f64());
    println!("检查地址数: {} | 平均速度: {:.0} 地址/秒", total_checked, speed);
    println!("========================================");
    
    // 10. 等待内核完成（确保 GPU 资源正确释放）
    // 如果已经找到结果，内核会在检测到全局标志后自动退出
    // 添加超时避免无限等待
    if found.is_some() {
        info!("已找到结果，等待 GPU 内核清理（最多5秒）...");
        // 给内核一些时间来检测全局标志并退出
        sleep(Duration::from_millis(500));
        // 尝试非阻塞方式等待，如果超时则继续
        // 注意：在 macOS 上，强制终止内核可能导致问题，所以这里只是短暂等待
    } else {
        info!("等待 GPU 内核完成...");
        for worker in &workers {
            let _ = worker.kernel.wait();
        }
    }
    
    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;
    use rust_profanity::config::ConditionType;

    /// 模拟 OpenCL 端的 compare_prefix 逻辑
    fn compare_prefix(address: &[u8; 20], param_bytes: usize, param: u64) -> bool {
        if param_bytes >= 2 {
            if address[1] != (param & 0xFF) as u8 { return false; }
        }
        if param_bytes >= 1 {
            let shift = if param_bytes > 1 { 8 * (param_bytes - 1) } else { 0 };
            if address[0] != ((param >> shift) & 0xFF) as u8 { return false; }
        }
        true
    }

    #[test]
    fn test_parse_args() {
        let args = Args {
            prefix: Some("8888".to_string()),
            suffix: None,
            leading_zeros: None,
            pattern: None,
            threads: 1024,
            work_group_size: 256,
            poll_interval: 100,
            timeout: 0,
            source_mode: SourceModeArg::Mnemonic,
            multi_gpu: false,
        };
        
        let (condition, _) = parse_condition(&args).unwrap();
        assert!(condition > 0);
    }

    /// 测试: 验证无参数时会返回错误
    #[test]
    fn test_parse_condition_requires_args() {
        let args = Args {
            prefix: None,
            suffix: None,
            leading_zeros: None,
            pattern: None,
            threads: 1024,
            work_group_size: 128,
            poll_interval: 250,
            timeout: 0,
            source_mode: SourceModeArg::Mnemonic,
            multi_gpu: false,
        };
        
        let result = parse_condition(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("请指定搜索条件"));
    }

    /// 测试: 验证偶数长度前缀"8888"的编码
    #[test]
    fn test_even_length_prefix_8888() {
        let condition = parse_prefix_condition("8888").unwrap();
        
        let cond_type = (condition >> 48) & 0xFFFF;
        assert_eq!(cond_type, ConditionType::Prefix as u64);
        
        let bytes_field = (condition >> 44) & 0x0F;
        assert_eq!(bytes_field, 2);
        
        let param = condition & 0xFFFFFFFFFF;
        assert_eq!(param, 0x8888);
    }

    /// 测试: 验证前缀匹配逻辑 (1234)
    #[test]
    fn test_compare_prefix_1234() {
        let condition = parse_prefix_condition("1234").unwrap();
        let param_bytes = ((condition >> 44) & 0x0F) as usize;
        let param = condition & 0xFFFFFFFFFF;
        
        // bytes=[0x12, 0x34] -> param = 0x1234
        assert_eq!(param, 0x1234);
        
        let matching_address = [0x12u8, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        assert!(compare_prefix(&matching_address, param_bytes, param),
                "应该匹配 0x1234 开头的地址");
        
        println!("✓ 前缀匹配逻辑测试通过 (1234)");
        println!("  参数字节数: {}", param_bytes);
        println!("  参数值: 0x{:010X}", param);
    }

    /// 测试: 单字节前缀
    #[test]
    fn test_compare_prefix_single_byte() {
        let condition = parse_prefix_condition("AB").unwrap();
        let param_bytes = ((condition >> 44) & 0x0F) as usize;
        let param = condition & 0xFFFFFFFFFF;
        
        // "AB" -> bytes=[0xAB] -> param = 0xAB
        assert_eq!(param, 0xAB);
        assert_eq!(param_bytes, 1);
        
        let matching_address = [0xABu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        assert!(compare_prefix(&matching_address, param_bytes, param),
                "应该匹配 0xAB 开头的地址");
        
        println!("✓ 单字节前缀测试通过 (AB)");
    }
}
