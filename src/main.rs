//! GPU以太坊靓号地址搜索系统 - 主程序
//!
//! 使用方式:
//!   cargo run -- --prefix 8888 --threads 1024
//!   cargo run -- --suffix dead --threads 2048
//!   cargo run -- --leading-zeros 4 --threads 4096

use clap::Parser;
use log::info;
use std::time::Duration;

use rust_profanity::{Mnemonic, SearchCondition, SearchRequest, SourceMode, search};

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
fn parse_condition(args: &Args) -> anyhow::Result<SearchCondition> {
    if let Some(prefix) = &args.prefix {
        info!("搜索条件: 前缀匹配 {}", prefix);
        Ok(SearchCondition::Prefix(prefix.clone()))
    } else if let Some(suffix) = &args.suffix {
        info!("搜索条件: 后缀匹配 {}", suffix);
        Ok(SearchCondition::Suffix(suffix.clone()))
    } else if let Some(zeros) = args.leading_zeros {
        info!("搜索条件: 前导零至少 {} 个", zeros);
        Ok(SearchCondition::LeadingZeros(zeros))
    } else if let Some(pattern) = &args.pattern {
        info!("搜索条件: 模式匹配 {}", pattern);
        Ok(SearchCondition::Pattern(pattern.clone()))
    } else {
        anyhow::bail!("请指定搜索条件: --prefix, --suffix, --leading-zeros 或 --pattern")
    }
}

/// 主函数
fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    info!("启动 GPU以太坊靓号地址搜索系统");
    info!("参数: {:?}", args);

    let source_mode: SourceMode = args.source_mode.into();
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

    let condition = parse_condition(&args)?;

    let mut request = SearchRequest::new(condition);
    request.threads = args.threads;
    request.work_group_size = args.work_group_size;
    request.poll_interval = Duration::from_millis(args.poll_interval);
    request.timeout = if args.timeout == 0 {
        None
    } else {
        Some(Duration::from_secs(args.timeout))
    };
    request.source_mode = source_mode;
    request.multi_gpu = args.multi_gpu;

    let response = search(request)?;

    println!();
    println!("========================================");

    if response.found {
        println!("✓ 找到符合条件的地址!");
        println!("========================================");
        println!(
            "以太坊地址: 0x{}",
            response.eth_address_hex().unwrap_or_default()
        );

        match response.source_mode {
            SourceMode::MnemonicEntropy => {
                if let Some(seed) = response.result_seed {
                    let mnemonic = Mnemonic::from_entropy(&seed).expect("从熵生成助记词失败");
                    println!("助记词: {}", mnemonic);
                }
            }
            SourceMode::PrivateKey => {
                if let Some(seed) = response.result_seed {
                    println!("私钥: 0x{}", hex::encode(seed));
                }
            }
        }

        if let Some(found_by_thread) = response.found_by_thread {
            println!("找到线程: {}", found_by_thread);
        }
        if let Some(device_name) = response.found_device {
            println!("找到设备: {}", device_name);
        }
    } else if response.timed_out {
        println!("✗ 搜索超时 ({} 秒) - 强制终止", args.timeout);
    } else {
        println!("✗ 未找到符合条件的地址");
    }

    println!("搜索时间: {:.2} 秒", response.elapsed.as_secs_f64());
    println!(
        "检查地址数: {} | 平均速度: {:.0} 地址/秒",
        response.total_checked, response.speed
    );
    println!("========================================");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_profanity::config::ConditionType;
    use rust_profanity::{
        parse_leading_zeros_condition, parse_pattern_condition, parse_prefix_condition,
        parse_suffix_condition,
    };

    /// 模拟 OpenCL 端的 compare_prefix 逻辑
    fn compare_prefix(address: &[u8; 20], param_bytes: usize, param: u64) -> bool {
        if param_bytes >= 2 {
            if address[1] != (param & 0xFF) as u8 {
                return false;
            }
        }
        if param_bytes >= 1 {
            let shift = if param_bytes > 1 {
                8 * (param_bytes - 1)
            } else {
                0
            };
            if address[0] != ((param >> shift) & 0xFF) as u8 {
                return false;
            }
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

        let condition = parse_condition(&args).unwrap();
        assert!(matches!(condition, SearchCondition::Prefix(_)));
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

        let matching_address = [
            0x12u8, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(
            compare_prefix(&matching_address, param_bytes, param),
            "应该匹配 0x1234 开头的地址"
        );

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

        let matching_address = [
            0xABu8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert!(
            compare_prefix(&matching_address, param_bytes, param),
            "应该匹配 0xAB 开头的地址"
        );

        println!("✓ 单字节前缀测试通过 (AB)");
    }

    #[test]
    fn test_parse_condition_for_other_modes() {
        let suffix = Args {
            prefix: None,
            suffix: Some("dead".to_string()),
            leading_zeros: None,
            pattern: None,
            threads: 1,
            work_group_size: 1,
            poll_interval: 1,
            timeout: 0,
            source_mode: SourceModeArg::Mnemonic,
            multi_gpu: false,
        };
        assert!(matches!(
            parse_condition(&suffix).unwrap(),
            SearchCondition::Suffix(_)
        ));

        let leading = Args {
            prefix: None,
            suffix: None,
            leading_zeros: Some(4),
            pattern: None,
            threads: 1,
            work_group_size: 1,
            poll_interval: 1,
            timeout: 0,
            source_mode: SourceModeArg::Mnemonic,
            multi_gpu: false,
        };
        assert!(matches!(
            parse_condition(&leading).unwrap(),
            SearchCondition::LeadingZeros(4)
        ));

        let pattern = Args {
            prefix: None,
            suffix: None,
            leading_zeros: None,
            pattern: Some("0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdead".to_string()),
            threads: 1,
            work_group_size: 1,
            poll_interval: 1,
            timeout: 0,
            source_mode: SourceModeArg::Mnemonic,
            multi_gpu: false,
        };
        assert!(matches!(
            parse_condition(&pattern).unwrap(),
            SearchCondition::Pattern(_)
        ));
    }

    #[test]
    fn test_condition_parser_functions_still_available() {
        assert!(parse_suffix_condition("dead").is_ok());
        assert!(parse_leading_zeros_condition(4).is_ok());
        assert!(parse_pattern_condition("0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdead").is_ok());
    }
}
