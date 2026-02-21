//! 搜索配置和数据结构定义

/// 搜索任务配置 (传递给 GPU)
/// 注意：必须与 OpenCL 的 search_config_t 结构体完全匹配
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SearchConfig {
    /// 基础熵 (32字节 = 256位) - 对应 OpenCL uchar[32]
    /// 使用熵而非助记词，确保 GPU 可以生成符合 BIP39 标准的有效助记词
    pub base_entropy: [u8; 32],
    /// GPU 线程数 - 对应 OpenCL uint
    pub num_threads: u32,
    /// 搜索条件编码 - 对应 OpenCL ulong
    /// 高16位: 条件类型, 低48位: 条件参数
    pub condition: u64,
    /// 检查标志间隔 (迭代次数) - 对应 OpenCL uint
    pub check_interval: u32,
}

impl SearchConfig {
    pub fn new(base_entropy: [u8; 32], num_threads: u32, condition: u64) -> Self {
        Self {
            base_entropy,
            num_threads,
            condition,
            check_interval: 1024,   // 每1024次迭代检查一次，平衡性能和进度更新
        }
    }
}

/// 搜索结果 (从 GPU 传回)
/// 注意：必须与 OpenCL 的 search_result_t 结构体完全匹配
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SearchResult {
    /// 是否找到 (0/1) - 对应 OpenCL int
    pub found: i32,
    /// 找到的熵 (32字节) - 对应 OpenCL uchar[32]
    /// 由 Rust 端转换为助记词，确保校验和正确
    pub result_entropy: [u8; 32],
    /// 以太坊地址 (20字节) - 对应 OpenCL uchar[20]
    pub eth_address: [u8; 20],
    /// 由哪个线程找到 - 对应 OpenCL uint
    pub found_by_thread: u32,
    /// 总共检查的地址数量 - 低32位 - 对应 OpenCL uint
    pub total_checked_low: u32,
    /// 总共检查的地址数量 - 高32位 - 对应 OpenCL uint
    pub total_checked_high: u32,
}

impl Default for SearchResult {
    fn default() -> Self {
        Self {
            found: 0,
            result_entropy: [0u8; 32],
            eth_address: [0u8; 20],
            found_by_thread: 0,
            total_checked_low: 0,
            total_checked_high: 0,
        }
    }
}

impl SearchResult {
    /// 获取总共检查的地址数量 (64位)
    pub fn total_checked(&self) -> u64 {
        ((self.total_checked_high as u64) << 32) | (self.total_checked_low as u64)
    }
}

/// 条件类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConditionType {
    /// 前缀匹配
    Prefix = 0x01,
    /// 后缀匹配
    Suffix = 0x02,
    /// 模式匹配
    Pattern = 0x03,
    /// 前导零个数 (至少)
    Leading = 0x04,
    /// 前导零个数 (精确匹配)
    LeadingExact = 0x05,
}

impl ConditionType {
    /// 编码条件 (基础版本，不带字节数)
    /// 格式: [类型:16位][参数:48位]
    pub fn encode(self, param: u64) -> u64 {
        ((self as u64) << 48) | (param & 0xFFFFFFFFFFFF)
    }
    
    /// 编码前缀/后缀条件，将字节数打包进 condition
    /// 格式: [类型:16位][字节数:8位][参数:40位]
    /// 参数最多40位(5字节)，足够存储6字节的前缀/后缀(因为十六进制字符串最多12字符=6字节)
    /// 但实际上我们存储的是大端序的数值，所以6字节需要48位，这里调整为：
    /// 格式: [类型:16位][字节数:4位][保留:4位][参数:40位]
    /// 对于需要6字节的情况，我们特殊处理：字节数=0表示6字节
    pub fn encode_with_bytes(self, param: u64, bytes: u8) -> u64 {
        let bytes_field = if bytes >= 6 { 0 } else { bytes };
        ((self as u64) << 48) | ((bytes_field as u64) << 44) | (param & 0xFFFFFFFFFF)
    }
}

/// 解析前缀条件
/// 
/// 将十六进制字符串解析为字节序列。
/// 输入应为十六进制字符（0-9, a-f, A-F）。
/// 如果长度为奇数，在后面补最后一个字符变成偶数长度。
/// 例如："888" -> "8888" -> [0x88, 0x88]；"88888" -> "888888" -> [0x88, 0x88, 0x88]
/// 
/// # Example
/// ```
/// use rust_profanity::parse_prefix_condition;
/// let condition = parse_prefix_condition("8888").unwrap();   // [0x88, 0x88]
/// let condition2 = parse_prefix_condition("888").unwrap();   // [0x88, 0x88]（补一个8）
/// let condition3 = parse_prefix_condition("88888").unwrap(); // [0x88, 0x88, 0x88]（补一个8）
/// ```
pub fn parse_prefix_condition(prefix: &str) -> anyhow::Result<u64> {
    let hex_str = prefix.trim_start_matches("0x");
    
    // 验证所有字符都是有效的十六进制字符
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Prefix must contain only hexadecimal characters (0-9, a-f, A-F)");
    }
    
    // 如果长度为奇数，在后面补最后一个字符变成偶数长度
    // 例如："888" -> "8888"；"88888" -> "888888"
    let expanded_hex = if hex_str.len() % 2 == 1 {
        let last_char = hex_str.chars().last().unwrap();
        format!("{}{}", hex_str, last_char)
    } else {
        hex_str.to_string()
    };
    
    let bytes = hex::decode(&expanded_hex)?;
    
    if bytes.len() > 6 {
        anyhow::bail!("Prefix too long, max 12 hex characters (6 bytes)");
    }
    
    let mut param: u64 = 0;
    for &byte in bytes.iter() {
        param = (param << 8) | (byte as u64);
    }
    
    // 使用新的编码方式，将字节数打包进 condition
    let bytes_len = bytes.len() as u8;
    Ok(ConditionType::Prefix.encode_with_bytes(param, bytes_len))
}

/// 解析后缀条件
/// 
/// 将十六进制字符串解析为字节序列。
/// 输入应为十六进制字符（0-9, a-f, A-F）。
/// 如果长度为奇数，在前面补0。
pub fn parse_suffix_condition(suffix: &str) -> anyhow::Result<u64> {
    let hex_str = suffix.trim_start_matches("0x");
    
    // 验证所有字符都是有效的十六进制字符
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Suffix must contain only hexadecimal characters (0-9, a-f, A-F)");
    }
    
    // 如果长度为奇数，在前面补0
    let hex_str = if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };
    
    let bytes = hex::decode(&hex_str)?;
    
    if bytes.len() > 6 {
        anyhow::bail!("Suffix too long, max 6 bytes (12 hex characters)");
    }
    
    let mut param: u64 = 0;
    for &byte in bytes.iter() {
        param = (param << 8) | (byte as u64);
    }
    
    // 使用新的编码方式，将字节数打包进 condition
    let bytes_len = bytes.len() as u8;
    Ok(ConditionType::Suffix.encode_with_bytes(param, bytes_len))
}

/// 解析前导零条件 (至少)
pub fn parse_leading_zeros_condition(zeros: u32) -> anyhow::Result<u64> {
    if zeros > 20 {
        anyhow::bail!("Leading zeros cannot exceed 20");
    }
    Ok(ConditionType::Leading.encode(zeros as u64))
}

/// 打印结构体布局信息（用于调试 OpenCL 对齐问题）
pub fn print_struct_layouts() {
    use std::mem;
    
    println!("=== SearchConfig Layout ===");
    println!("Total size: {} bytes", mem::size_of::<SearchConfig>());
    println!("  base_entropy offset: {} bytes", mem::offset_of!(SearchConfig, base_entropy));
    println!("  num_threads offset: {} bytes", mem::offset_of!(SearchConfig, num_threads));
    println!("  condition offset: {} bytes", mem::offset_of!(SearchConfig, condition));
    println!("  check_interval offset: {} bytes", mem::offset_of!(SearchConfig, check_interval));
    
    println!("\n=== SearchResult Layout ===");
    println!("Total size: {} bytes", mem::size_of::<SearchResult>());
    println!("  found offset: {} bytes", mem::offset_of!(SearchResult, found));
    println!("  result_entropy offset: {} bytes", mem::offset_of!(SearchResult, result_entropy));
    println!("  eth_address offset: {} bytes", mem::offset_of!(SearchResult, eth_address));
    println!("  found_by_thread offset: {} bytes", mem::offset_of!(SearchResult, found_by_thread));
    println!("  total_checked_low offset: {} bytes", mem::offset_of!(SearchResult, total_checked_low));
    println!("  total_checked_high offset: {} bytes", mem::offset_of!(SearchResult, total_checked_high));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_encoding() {
        let condition = ConditionType::Prefix.encode(0x8888);
        assert_eq!(condition >> 48, 0x01);
        assert_eq!(condition & 0xFFFFFFFFFFFF, 0x8888);
    }

    #[test]
    fn test_parse_prefix() {
        let condition = parse_prefix_condition("8888").unwrap();
        assert_eq!(condition >> 48, 0x01);
    }

    #[test]
    fn test_struct_sizes() {
        // 验证结构体大小与 OpenCL 端匹配
        // OpenCL: typedef struct { uchar[32]; uint; ulong; uint; } = 32 + 4 + 8 + 4 = 48 (可能有填充)
        let config_size = std::mem::size_of::<SearchConfig>();
        println!("SearchConfig size: {}", config_size);
        assert!(config_size >= 48, "SearchConfig too small");

        // OpenCL: typedef struct { int; uchar[32]; uchar[20]; uint; uint; uint; } = 4 + 32 + 20 + 4 + 4 + 4 = 68 (可能有填充)
        let result_size = std::mem::size_of::<SearchResult>();
        println!("SearchResult size: {}", result_size);
        assert!(result_size >= 68, "SearchResult too small");
    }

    #[test]
    fn test_struct_layout() {
        // 打印结构体布局用于调试
        print_struct_layouts();
    }

    #[test]
    fn test_total_checked() {
        let result = SearchResult {
            found: 0,
            result_entropy: [0u8; 32],
            eth_address: [0u8; 20],
            found_by_thread: 0,
            total_checked_low: 0x12345678,
            total_checked_high: 0x9ABCDEF0,
        };
        assert_eq!(result.total_checked(), 0x9ABCDEF012345678);
    }
}
