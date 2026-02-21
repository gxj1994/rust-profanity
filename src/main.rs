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
    config::{*},
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
    
    /// 前导零个数 (至少)
    #[arg(long, group = "condition")]
    leading_zeros: Option<u32>,
    
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
        info!("搜索条件: 前导零至少 {} 个", zeros);
        parse_leading_zeros_condition(zeros)
    } else {
        anyhow::bail!("请指定搜索条件: --prefix, --suffix 或 --leading-zeros")
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
    
    // 3. SHA-256 (BIP39 校验和计算依赖)
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
    
    // 7. BIP39 词表 (entropy.cl 和 mnemonic.cl 依赖)
    source.push_str(include_str!("../kernels/bip39/wordlist.cl"));
    source.push('\n');
    
    // 8. BIP39 熵处理 (entropy_to_mnemonic 等，依赖 sha256 和 wordlist)
    source.push_str(include_str!("../kernels/bip39/entropy.cl"));
    source.push('\n');
    
    // 9. 主搜索内核 (包含 local_mnemonic_t 定义，必须在 mnemonic.cl 之前)
    let search_kernel = include_str!("../kernels/search.cl");
    for line in search_kernel.lines() {
        if !line.trim_start().starts_with("#include") {
            source.push_str(line);
            source.push('\n');
        }
    }
    source.push('\n');
    
    // 10. BIP39 助记词处理 (依赖 local_mnemonic_t 和 wordlist.cl)
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
    
    // 1. 生成随机熵种子
    info!("生成随机熵种子...");
    let base_mnemonic = Mnemonic::generate_random()?;
    let (base_entropy, _) = base_mnemonic.to_entropy();
    info!("搜索空间: {} 个线程从随机熵开始并行遍历", args.threads);
    
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
    let search_kernel = SearchKernel::new(&ctx, &kernel_source)?;
    
    // 5. 准备配置数据
    // 验证助记词校验和
    let (_, checksum_valid) = base_mnemonic.to_entropy();
    if !checksum_valid {
        log::warn!("基础助记词校验和验证失败，继续执行...");
    }
    let config = SearchConfig::new(
        base_entropy,
        args.threads,
        condition,
    );
    search_kernel.set_config(&config)?;
    
    // 6. 启动内核
    info!("启动搜索内核，使用 {} 个线程...", args.threads);
    let start_time = Instant::now();
    search_kernel.launch(args.threads as usize, Some(args.work_group_size))?;
    
    // 7. 轮询等待结果并读取
    info!("开始轮询等待结果...");
    let mut found = false;
    let mut poll_count = 0;
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
        if search_kernel.check_found()? {
            found = true;
            // 读取结果
            result = search_kernel.read_result()?;
            break;
        }
        
        // 显示进度
        poll_count += 1;
        if poll_count % 10 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            // 读取结果统计
            if let Ok(r) = search_kernel.read_result() {
                result = r;
                let checked = result.total_checked();
                let speed = if elapsed > 0.0 { checked as f64 / elapsed } else { 0.0 };
                info!(
                    "搜索中... 已运行 {:.1} 秒 | 已检查 {} 个地址 | 速度 {:.0} 地址/秒",
                    elapsed, checked, speed
                );
            }
        }
        
        // 等待一段时间再检查
        sleep(Duration::from_millis(args.poll_interval));
    }
    
    // 如果超时但还未读取到结果，尝试读取一次
    if !found {
        if let Ok(r) = search_kernel.read_result() {
            result = r;
        }
    }
    
    let elapsed = start_time.elapsed();
    let is_timeout = timeout_enabled && elapsed.as_secs() >= timeout_secs;
    
    // 9. 输出结果
    println!();
    println!("========================================");
    
    // 计算统计信息
    let total_checked = result.total_checked();
    let speed = if elapsed.as_secs_f64() > 0.0 {
        total_checked as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    
    if found && result.found != 0 {
        println!("✓ 找到符合条件的地址!");
        println!("========================================");
        println!("以太坊地址: 0x{}", hex::encode(result.eth_address));
        
        // 从熵生成助记词，确保校验和正确
        let mnemonic = Mnemonic::from_entropy(&result.result_entropy)
            .expect("从熵生成助记词失败");
        println!("助记词: {}", mnemonic);
        println!("找到线程: {}", result.found_by_thread);
    } else if !found && is_timeout {
        println!("✗ 搜索超时 ({} 秒) - 强制终止", timeout_secs);
    } else {
        println!("✗ 未找到符合条件的地址");
    }
    
    println!("搜索时间: {:.2} 秒", elapsed.as_secs_f64());
    println!("检查地址数: {} | 平均速度: {:.0} 地址/秒", total_checked, speed);
    println!("========================================");
    
    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;
    use rust_profanity::config::ConditionType;

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

    /// 测试: 验证无参数时会返回错误
    #[test]
    fn test_parse_condition_requires_args() {
        let args = Args {
            prefix: None,
            suffix: None,
            leading_zeros: None,
            threads: 1024,
            work_group_size: 128,
            poll_interval: 250,
            timeout: 0,
        };
        
        let result = parse_condition(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("请指定搜索条件"));
    }

    /// 测试: 验证奇数长度前缀"888"的编码和解码逻辑
    /// 确保 Rust 端编码和 OpenCL 端解码一致
    #[test]
    fn test_odd_length_prefix_888() {
        // 解析 "888" -> 应该变成 "8888" -> [0x88, 0x88]
        let condition = parse_prefix_condition("888").unwrap();
        
        // 验证类型是 Prefix
        let cond_type = (condition >> 48) & 0xFFFF;
        assert_eq!(cond_type, ConditionType::Prefix as u64);
        
        // 验证字节数 = 2 (因为 "8888" = 2 字节)
        let bytes_field = (condition >> 44) & 0x0F;
        assert_eq!(bytes_field, 2);
        
        // 验证参数 = 0x8888
        let param = condition & 0xFFFFFFFFFF;
        assert_eq!(param, 0x8888);
        
        println!("条件编码: 0x{:016X}", condition);
        println!("类型: 0x{:04X}", cond_type);
        println!("字节数字段: {}", bytes_field);
        println!("参数: 0x{:010X}", param);
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

    /// 测试: 验证 "88888" -> "888888" -> 3 字节
    #[test]
    fn test_odd_length_prefix_88888() {
        let condition = parse_prefix_condition("88888").unwrap();
        
        let bytes_field = (condition >> 44) & 0x0F;
        assert_eq!(bytes_field, 3); // 3 字节
        
        let param = condition & 0xFFFFFFFFFF;
        assert_eq!(param, 0x888888);
    }

    /// 模拟 OpenCL 端的 compare_prefix 逻辑进行验证
    /// 这是修复后的正确逻辑
    #[test]
    fn test_compare_prefix_logic() {
        // 测试 "888" 条件 (实际编码为 2 字节 0x8888)
        let condition = parse_prefix_condition("888").unwrap();
        let param_bytes = ((condition >> 44) & 0x0F) as usize;
        let param = condition & 0xFFFFFFFFFF;
        
        // 匹配地址: 0x8888xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        let matching_address = [0x88u8, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // 不匹配地址: 0x8811xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        let non_matching_address = [0x88u8, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // 模拟修复后的 OpenCL compare_prefix 逻辑
        fn compare_prefix(address: &[u8; 20], param_bytes: usize, param: u64) -> bool {
            if param_bytes >= 2 {
                // address[1] 对应 param 的最低字节
                if address[1] != (param & 0xFF) as u8 { return false; }
            }
            if param_bytes >= 1 {
                // address[0] 的偏移量取决于字节数
                let shift = if param_bytes > 1 { 8 * (param_bytes - 1) } else { 0 };
                if address[0] != ((param >> shift) & 0xFF) as u8 { return false; }
            }
            true
        }
        
        assert!(compare_prefix(&matching_address, param_bytes, param), 
                "应该匹配 0x8888 开头的地址");
        assert!(!compare_prefix(&non_matching_address, param_bytes, param),
                "不应该匹配 0x8811 开头的地址");
        
        println!("✓ 前缀匹配逻辑测试通过 (888 -> 8888)");
        println!("  参数字节数: {}", param_bytes);
        println!("  参数值: 0x{:010X}", param);
    }

    /// 测试: 使用不同的值验证匹配逻辑 (1234)
    #[test]
    fn test_compare_prefix_1234() {
        let condition = parse_prefix_condition("1234").unwrap();
        let param_bytes = ((condition >> 44) & 0x0F) as usize;
        let param = condition & 0xFFFFFFFFFF;
        
        // bytes=[0x12, 0x34] -> param = 0x1234
        assert_eq!(param, 0x1234);
        
        let matching_address = [0x12u8, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // 模拟修复后的逻辑
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
        
        fn compare_prefix(address: &[u8; 20], param_bytes: usize, param: u64) -> bool {
            if param_bytes >= 1 {
                let shift = if param_bytes > 1 { 8 * (param_bytes - 1) } else { 0 };
                if address[0] != ((param >> shift) & 0xFF) as u8 { return false; }
            }
            true
        }
        
        assert!(compare_prefix(&matching_address, param_bytes, param),
                "应该匹配 0xAB 开头的地址");
        
        println!("✓ 单字节前缀测试通过 (AB)");
    }
}
