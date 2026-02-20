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
            check_interval: 1024,
        }
    }
}

/// 搜索结果 (从 GPU 传回)
/// 注意：必须与 OpenCL 的 search_result_t 结构体完全匹配
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
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
    /// 总共检查的地址数量 - 对应 OpenCL ulong
    pub total_checked: u64,
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
    /// 编码条件
    pub fn encode(self, param: u64) -> u64 {
        ((self as u64) << 48) | (param & 0xFFFFFFFFFFFF)
    }
}

/// 解析前缀条件
/// 
/// 支持两种格式：
/// 1. 普通字符串：如 "888"，将每个字符作为 ASCII 字节处理
/// 2. 十六进制字符串：如 "0x8888" 或 "8888"（偶数长度）
/// 
/// # Example
/// ```
/// use rust_profanity::parse_prefix_condition;
/// let condition = parse_prefix_condition("8888").unwrap();
/// let condition2 = parse_prefix_condition("888").unwrap();
/// ```
pub fn parse_prefix_condition(prefix: &str) -> anyhow::Result<u64> {
    let hex_str = prefix.trim_start_matches("0x");
    
    // 尝试作为十六进制解析（偶数长度且只包含十六进制字符）
    let bytes = if hex_str.len() % 2 == 0 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(hex_str)?
    } else {
        // 作为普通字符串，每个字符转为 ASCII 字节
        hex_str.as_bytes().to_vec()
    };
    
    if bytes.len() > 6 {
        anyhow::bail!("Prefix too long, max 6 bytes");
    }
    
    let mut param: u64 = 0;
    for &byte in bytes.iter() {
        param = (param << 8) | (byte as u64);
    }
    
    Ok(ConditionType::Prefix.encode(param))
}

/// 解析后缀条件
/// 
/// 支持两种格式：
/// 1. 普通字符串：如 "888"，将每个字符作为 ASCII 字节处理
/// 2. 十六进制字符串：如 "0x8888" 或 "8888"（偶数长度）
pub fn parse_suffix_condition(suffix: &str) -> anyhow::Result<u64> {
    let hex_str = suffix.trim_start_matches("0x");
    
    // 尝试作为十六进制解析（偶数长度且只包含十六进制字符）
    let bytes = if hex_str.len() % 2 == 0 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(hex_str)?
    } else {
        // 作为普通字符串，每个字符转为 ASCII 字节
        hex_str.as_bytes().to_vec()
    };
    
    if bytes.len() > 6 {
        anyhow::bail!("Suffix too long, max 6 bytes");
    }
    
    let mut param: u64 = 0;
    for &byte in bytes.iter() {
        param = (param << 8) | (byte as u64);
    }
    
    Ok(ConditionType::Suffix.encode(param))
}

/// 解析前导零条件 (至少)
pub fn parse_leading_zeros_condition(zeros: u32) -> anyhow::Result<u64> {
    if zeros > 20 {
        anyhow::bail!("Leading zeros cannot exceed 20");
    }
    Ok(ConditionType::Leading.encode(zeros as u64))
}

/// 解析前导零条件 (精确匹配)
pub fn parse_leading_zeros_exact_condition(zeros: u32) -> anyhow::Result<u64> {
    if zeros > 20 {
        anyhow::bail!("Leading zeros cannot exceed 20");
    }
    Ok(ConditionType::LeadingExact.encode(zeros as u64))
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

        // OpenCL: typedef struct { int; uchar[32]; uchar[20]; uint; } = 4 + 32 + 20 + 4 = 60 (可能有填充)
        let result_size = std::mem::size_of::<SearchResult>();
        println!("SearchResult size: {}", result_size);
        assert!(result_size >= 60, "SearchResult too small");
    }
}
