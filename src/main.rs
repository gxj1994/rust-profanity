//! GPU以太坊靓号地址搜索系统 - 主程序
//!
//! 使用方式:
//!   cargo run -- --prefix 8888 --threads 1024
//!   cargo run -- --suffix dead --threads 2048
//!   cargo run -- --leading-zeros 4 --threads 4096

use clap::Parser;
use log::info;
use std::time::{Duration, Instant};
use std::thread::sleep;

use rust_profanity::{
    config::*,
    mnemonic::Mnemonic,
    opencl::{OpenCLContext, SearchKernel},
};

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
    
    /// 前导零个数
    #[arg(long, group = "condition")]
    leading_zeros: Option<u32>,
    
    /// GPU 线程数
    #[arg(short, long, default_value = "1024")]
    threads: u32,
    
    /// 本地工作组大小
    #[arg(short, long, default_value = "128")]
    work_group_size: usize,
    
    /// 轮询间隔 (毫秒)
    #[arg(long, default_value = "100")]
    poll_interval: u64,
    
    /// 超时时间 (秒，0表示无超时)
    #[arg(long, default_value = "0")]
    timeout: u64,
}

/// 解析搜索条件
fn parse_condition(args: &Args) -> anyhow::Result<u64> {
    if let Some(prefix) = &args.prefix {
        info!("搜索条件: 前缀匹配 {}", prefix);
        parse_prefix_condition(prefix)
    } else if let Some(suffix) = &args.suffix {
        info!("搜索条件: 后缀匹配 {}", suffix);
        parse_suffix_condition(suffix)
    } else if let Some(zeros) = args.leading_zeros {
        info!("搜索条件: 前导零 {}", zeros);
        parse_leading_zeros_condition(zeros)
    } else {
        // 默认搜索前缀 8888
        info!("搜索条件: 默认前缀匹配 8888");
        parse_prefix_condition("8888")
    }
}

/// 加载完整版内核源代码 (包含完整加密实现)
fn load_kernel_source() -> anyhow::Result<String> {
    // 读取主内核文件
    let mut source = String::new();
    
    // 由于 OpenCL 不支持 #include，我们需要手动合并所有文件
    // 按正确的依赖顺序包含所有内核代码
    
    // 1. SHA-512 (PBKDF2 依赖)
    source.push_str(include_str!("../kernels/crypto/sha512.cl"));
    source.push('\n');
    
    // 2. PBKDF2 (BIP39 依赖)
    source.push_str(include_str!("../kernels/crypto/pbkdf2.cl"));
    source.push('\n');
    
    // 3. SHA-256 (HMAC-SHA256 可能用到)
    source.push_str(include_str!("../kernels/crypto/sha256.cl"));
    source.push('\n');
    
    // 4. Keccak-256 (以太坊地址生成)
    source.push_str(include_str!("../kernels/crypto/keccak.cl"));
    source.push('\n');
    
    // 5. secp256k1 (椭圆曲线运算)
    source.push_str(include_str!("../kernels/crypto/secp256k1.cl"));
    source.push('\n');
    
    // 6. 条件匹配
    source.push_str(include_str!("../kernels/utils/condition.cl"));
    source.push('\n');
    
    // 7. 主搜索内核 (包含 local_mnemonic_t 定义，必须在 mnemonic.cl 之前)
    let search_kernel = include_str!("../kernels/search.cl");
    for line in search_kernel.lines() {
        if !line.trim_start().starts_with("#include") {
            source.push_str(line);
            source.push('\n');
        }
    }
    source.push('\n');
    
    // 8. BIP39 词表 (mnemonic.cl 依赖)
    source.push_str(include_str!("../kernels/bip39/wordlist.cl"));
    source.push('\n');
    
    // 9. BIP39 助记词处理 (依赖 local_mnemonic_t 和 wordlist.cl)
    source.push_str(include_str!("../kernels/bip39/mnemonic.cl"));
    source.push('\n');
    
    Ok(source)
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
    
    // 1. 生成随机助记词种子
    info!("生成随机助记词种子...");
    let base_mnemonic = Mnemonic::generate_random()?;
    info!("基础助记词: {}", base_mnemonic);
    
    // 2. 解析搜索条件
    let condition = parse_condition(&args)?;
    info!("条件编码: 0x{:016X}", condition);
    
    // 3. 初始化 OpenCL
    info!("初始化 OpenCL...");
    let ctx = OpenCLContext::new()?;
    ctx.print_device_info()?;
    
    // 4. 加载并编译内核
    info!("加载 OpenCL 内核...");
    // 使用完整版内核 (包含完整加密实现)
    let kernel_source = load_kernel_source()?;
    // 使用简化版内核 (用于测试)
    // let kernel_source = load_simple_kernel_source()?;
    let search_kernel = SearchKernel::new(&ctx, &kernel_source)?;
    
    // 5. 准备配置数据
    let config = SearchConfig::new(
        base_mnemonic.words,
        args.threads,
        condition,
    );
    search_kernel.set_config(&config)?;
    
    // 6. 启动内核
    info!("启动搜索内核，使用 {} 个线程...", args.threads);
    let start_time = Instant::now();
    search_kernel.launch(args.threads as usize, Some(args.work_group_size))?;
    
    // 7. 轮询等待结果
    info!("开始轮询等待结果...");
    let mut found = false;
    let mut poll_count = 0;
    
    loop {
        // 检查是否找到
        if search_kernel.check_found()? {
            found = true;
            break;
        }
        
        // 检查超时
        if args.timeout > 0 && start_time.elapsed().as_secs() >= args.timeout {
            info!("搜索超时 ({} 秒)", args.timeout);
            break;
        }
        
        // 显示进度
        poll_count += 1;
        if poll_count % 10 == 0 {
            let elapsed = start_time.elapsed().as_secs();
            info!("搜索中... 已运行 {} 秒", elapsed);
        }
        
        // 等待一段时间再检查
        sleep(Duration::from_millis(args.poll_interval));
    }
    
    // 8. 读取结果
    let result = search_kernel.read_result()?;
    let elapsed = start_time.elapsed();
    
    // 9. 输出结果
    println!();
    println!("========================================");
    
    if found && result.found != 0 {
        println!("✓ 找到符合条件的地址!");
        println!("========================================");
        println!("以太坊地址: 0x{}", hex::encode(&result.eth_address));
        println!("助记词: {}", format_mnemonic(&result.result_mnemonic));
        println!("找到线程: {}", result.found_by_thread);
    } else {
        println!("✗ 未找到符合条件的地址");
    }
    
    println!("搜索时间: {:.2} 秒", elapsed.as_secs_f64());
    println!("========================================");
    
    Ok(())
}

/// 格式化助记词显示
fn format_mnemonic(words: &[u16; 24]) -> String {
    use rust_profanity::mnemonic::BIP39_WORDLIST;
    
    words
        .iter()
        .map(|&idx| {
            let idx_usize = idx as usize;
            if idx_usize < BIP39_WORDLIST.len() {
                BIP39_WORDLIST[idx_usize]
            } else {
                "unknown"
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args() {
        let args = Args {
            prefix: Some("8888".to_string()),
            suffix: None,
            leading_zeros: None,
            threads: 1024,
            work_group_size: 256,
            poll_interval: 100,
            timeout: 0,
        };
        
        let condition = parse_condition(&args).unwrap();
        assert!(condition > 0);
    }
}
