//! 搜索配置和数据结构定义

/// 搜索任务配置 (传递给 GPU)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SearchConfig {
    /// 基础助记词种子 (24个单词索引)
    pub base_mnemonic: [u16; 24],
    /// GPU 线程数
    pub num_threads: u32,
    /// 搜索条件编码
    /// 高16位: 条件类型, 低48位: 条件参数
    pub condition: u64,
    /// 检查标志间隔 (迭代次数)
    pub check_interval: u32,
}

impl SearchConfig {
    pub fn new(base_mnemonic: [u16; 24], num_threads: u32, condition: u64) -> Self {
        Self {
            base_mnemonic,
            num_threads,
            condition,
            check_interval: 1024,
        }
    }
}

/// 搜索结果 (从 GPU 传回)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SearchResult {
    /// 是否找到 (0/1)
    pub found: i32,
    /// 找到的助记词
    pub result_mnemonic: [u16; 24],
    /// 以太坊地址 (20字节)
    pub eth_address: [u8; 20],
    /// 由哪个线程找到
    pub found_by_thread: u32,
}

impl Default for SearchResult {
    fn default() -> Self {
        Self {
            found: 0,
            result_mnemonic: [0; 24],
            eth_address: [0; 20],
            found_by_thread: 0,
        }
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
    /// 前导零个数
    Leading = 0x04,
}

impl ConditionType {
    /// 编码条件
    pub fn encode(self, param: u64) -> u64 {
        ((self as u64) << 48) | (param & 0xFFFFFFFFFFFF)
    }
}

/// 解析前缀条件
/// 
/// # Example
/// ```
/// use rust_profanity::parse_prefix_condition;
/// let condition = parse_prefix_condition("8888").unwrap();
/// ```
pub fn parse_prefix_condition(prefix: &str) -> anyhow::Result<u64> {
    let hex_str = prefix.trim_start_matches("0x");
    let bytes = hex::decode(hex_str)?;
    
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
pub fn parse_suffix_condition(suffix: &str) -> anyhow::Result<u64> {
    let hex_str = suffix.trim_start_matches("0x");
    let bytes = hex::decode(hex_str)?;
    
    if bytes.len() > 6 {
        anyhow::bail!("Suffix too long, max 6 bytes");
    }
    
    let mut param: u64 = 0;
    for &byte in bytes.iter() {
        param = (param << 8) | (byte as u64);
    }
    
    Ok(ConditionType::Suffix.encode(param))
}

/// 解析前导零条件
pub fn parse_leading_zeros_condition(zeros: u32) -> anyhow::Result<u64> {
    if zeros > 20 {
        anyhow::bail!("Leading zeros cannot exceed 20");
    }
    Ok(ConditionType::Leading.encode(zeros as u64))
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
}
