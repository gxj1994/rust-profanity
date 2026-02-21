//! 搜索配置和数据结构定义

/// 模式匹配配置 (用于 profanity 风格的模式匹配)
/// 支持类似 0xXXXXXXXXXXXXabcdXXXXXXXXXXXXXXXXXXXXXXXX 的格式
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PatternConfig {
    /// 掩码数组 (20字节) - 对应 OpenCL uchar[20]
    /// 每个字节表示哪些半字节需要匹配: 0xF0=高半字节, 0x0F=低半字节, 0xFF=整个字节
    pub mask: [u8; 20],
    /// 期望值数组 (20字节) - 对应 OpenCL uchar[20]
    /// 需要匹配的具体值
    pub value: [u8; 20],
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            mask: [0u8; 20],
            value: [0u8; 20],
        }
    }
}

/// 搜索任务配置 (传递给 GPU)
///
/// 注意：必须与 OpenCL 的 search_config_t 结构体完全匹配
/// OpenCL 布局: base_seed[32] @0, num_threads @32, source_mode @36, target_chain @40,
///              _padding1[4] @44, condition @48, check_interval @56, _padding2[4] @60,
///              pattern_mask[20] @64, pattern_value[20] @84
/// 总大小: 104 bytes
///
/// 使用 `#[repr(C, align(8))]` 确保 8 字节对齐，与 OpenCL 端保持一致
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct SearchConfig {
    /// 基础种子 (32字节 = 256位) - 对应 OpenCL uchar[32]
    /// 根据 source_mode 解释为熵或私钥起点
    pub base_seed: [u8; 32],
    /// GPU 线程数 - 对应 OpenCL uint
    pub num_threads: u32,
    /// 搜索来源模式 - 对应 OpenCL uint
    pub source_mode: u32,
    /// 目标链类型 - 对应 OpenCL uint
    pub target_chain: u32,
    /// 填充以对齐 condition 到 8 字节边界 - 对应 OpenCL _padding1[4]
    /// 使用 explicit padding 字段确保内存布局正确
    pub _padding1: [u8; 4],
    /// 搜索条件编码 - 对应 OpenCL ulong
    /// 高16位: 条件类型, 低48位: 条件参数
    pub condition: u64,
    /// 检查标志间隔 (迭代次数) - 对应 OpenCL uint
    pub check_interval: u32,
    /// 填充以对齐 pattern_config - 对应 OpenCL _padding2[4]
    pub _padding2: [u8; 4],
    /// 模式匹配配置 - 用于 profanity 风格的模式匹配
    /// 当 condition 类型为 Pattern 时使用
    pub pattern_config: PatternConfig,
}

impl SearchConfig {
    pub fn new(base_seed: [u8; 32], num_threads: u32, condition: u64) -> Self {
        Self {
            base_seed,
            num_threads,
            source_mode: SourceMode::MnemonicEntropy as u32,
            target_chain: TargetChain::Ethereum as u32,
            _padding1: [0; 4],
            condition,
            check_interval: 2048, // 每2048次迭代检查一次，降低原子写入频率
            _padding2: [0; 4],
            pattern_config: PatternConfig::default(),
        }
    }

    /// 创建带模式匹配的配置
    pub fn new_with_pattern(
        base_seed: [u8; 32],
        num_threads: u32,
        condition: u64,
        pattern_config: PatternConfig,
    ) -> Self {
        Self {
            base_seed,
            num_threads,
            source_mode: SourceMode::MnemonicEntropy as u32,
            target_chain: TargetChain::Ethereum as u32,
            _padding1: [0; 4],
            condition,
            check_interval: 2048,
            _padding2: [0; 4],
            pattern_config,
        }
    }

    pub fn with_source_mode(mut self, source_mode: SourceMode) -> Self {
        self.source_mode = source_mode as u32;
        self
    }

    pub fn with_target_chain(mut self, target_chain: TargetChain) -> Self {
        self.target_chain = target_chain as u32;
        self
    }
}

/// 搜索结果 (从 GPU 传回)
/// 注意：必须与 OpenCL 的 search_result_t 结构体完全匹配
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SearchResult {
    /// 是否找到 (0/1) - 对应 OpenCL int
    pub found: i32,
    /// 找到的候选密钥材料 (32字节) - 对应 OpenCL uchar[32]
    /// 在不同 source_mode 下，可能表示熵或私钥
    pub result_seed: [u8; 32],
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
            result_seed: [0u8; 32],
            eth_address: [0u8; 20],
            found_by_thread: 0,
            total_checked_low: 0,
            total_checked_high: 0,
        }
    }
}

/// 搜索来源模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    /// 从 32 字节熵派生助记词，再生成私钥
    MnemonicEntropy = 0,
    /// 直接将 32 字节作为私钥遍历
    PrivateKey = 1,
}

impl SourceMode {
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// 目标链类型 (预留扩展，比如 Bitcoin)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetChain {
    Ethereum = 0,
}

impl TargetChain {
    pub fn as_u32(self) -> u32 {
        self as u32
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
}

/// 解析模式匹配条件
///
/// 支持类似 profanity 的模式匹配格式:
/// - `0xXXXXXXXXXXXXabcdXXXXXXXXXXXXXXXXXXXXXXXX` - X 表示通配符，其他字符表示需要匹配的值
/// - `0x0000XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` - 前缀匹配
/// - `0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdead` - 后缀匹配
/// - `0xXXXX1234XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` - 中间匹配
///
/// # Example
/// ```
/// use rust_profanity::config::parse_pattern_condition;
/// let (condition, pattern_config) = parse_pattern_condition("0xXXXXXXXXXXXXdeadXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
/// ```
pub fn parse_pattern_condition(pattern: &str) -> anyhow::Result<(u64, PatternConfig)> {
    // 正确处理 0x 前缀，只移除一次前缀而不是所有匹配的字符
    let hex_str = if pattern.starts_with("0x") || pattern.starts_with("0X") {
        &pattern[2..]
    } else {
        pattern
    };

    // 验证长度 (必须是40个十六进制字符 = 20字节)
    if hex_str.len() != 40 {
        anyhow::bail!(
            "Pattern must be exactly 40 hex characters (20 bytes), got {}",
            hex_str.len()
        );
    }

    let mut mask = [0u8; 20];
    let mut value = [0u8; 20];

    // 解析每个字符
    for (i, c) in hex_str.chars().enumerate() {
        let byte_idx = i / 2;
        let is_high_nibble = i % 2 == 0;

        match c {
            'X' | 'x' | '*' | '?' => {
                // 通配符: 不需要匹配这个半字节
                // mask 对应位保持 0
            }
            '0'..='9' | 'a'..='f' | 'A'..='F' => {
                // 需要匹配的十六进制字符
                let nibble = c.to_digit(16).unwrap() as u8;

                if is_high_nibble {
                    // 高半字节 (位7-4)
                    mask[byte_idx] |= 0xF0;
                    value[byte_idx] |= nibble << 4;
                } else {
                    // 低半字节 (位3-0)
                    mask[byte_idx] |= 0x0F;
                    value[byte_idx] |= nibble;
                }
            }
            _ => {
                anyhow::bail!(
                    "Invalid character '{}' in pattern. Use hex digits (0-9, a-f) or X/*/? for wildcards",
                    c
                );
            }
        }
    }

    let pattern_config = PatternConfig { mask, value };
    let condition = ConditionType::Pattern.encode(0); // Pattern 类型不需要额外参数

    Ok((condition, pattern_config))
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
        let (condition, _pattern) =
            parse_pattern_condition("0x8888XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();
        assert_eq!(condition >> 48, 0x03);
    }

    #[test]
    fn test_struct_sizes() {
        // 验证结构体大小与 OpenCL 端匹配
        // OpenCL: typedef struct { uchar[32]; uint; uint; uint; uchar[4]; ulong; uint; uchar[4]; uchar[20]; uchar[20]; }
        let config_size = std::mem::size_of::<SearchConfig>();
        println!("SearchConfig size: {}", config_size);
        assert!(config_size >= 104, "SearchConfig too small");

        // OpenCL: typedef struct { int; uchar[32]; uchar[20]; uint; uint; uint; } = 4 + 32 + 20 + 4 + 4 + 4 = 68 (可能有填充)
        let result_size = std::mem::size_of::<SearchResult>();
        println!("SearchResult size: {}", result_size);
        assert!(result_size >= 68, "SearchResult too small");
    }

    #[test]
    fn test_total_checked() {
        let result = SearchResult {
            found: 0,
            result_seed: [0u8; 32],
            eth_address: [0u8; 20],
            found_by_thread: 0,
            total_checked_low: 0x12345678,
            total_checked_high: 0x9ABCDEF0,
        };
        assert_eq!(result.total_checked(), 0x9ABCDEF012345678);
    }

    #[test]
    fn test_parse_pattern_suffix_dead() {
        // 测试后缀匹配: 0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdead
        let (_condition, pattern_config) =
            parse_pattern_condition("0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdead").unwrap();

        // 验证最后两个字节的掩码和值
        // "dead" = [0xde, 0xad]
        assert_eq!(pattern_config.mask[18], 0xFF); // 第19字节需要完全匹配
        assert_eq!(pattern_config.mask[19], 0xFF); // 第20字节需要完全匹配
        assert_eq!(pattern_config.value[18], 0xde);
        assert_eq!(pattern_config.value[19], 0xad);

        // 验证前面的字节掩码为0 (通配符)
        for i in 0..18 {
            assert_eq!(pattern_config.mask[i], 0, "字节 {} 应该是通配符", i);
        }
    }

    #[test]
    fn test_parse_pattern_prefix_0000() {
        // 测试前缀匹配: 0x0000XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        let (_condition, pattern_config) =
            parse_pattern_condition("0x0000XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();

        // "0000" = [0x00, 0x00]
        assert_eq!(pattern_config.mask[0], 0xFF);
        assert_eq!(pattern_config.mask[1], 0xFF);
        assert_eq!(pattern_config.value[0], 0x00);
        assert_eq!(pattern_config.value[1], 0x00);

        // 验证后面的字节掩码为0
        for i in 2..20 {
            assert_eq!(pattern_config.mask[i], 0, "字节 {} 应该是通配符", i);
        }
    }

    #[test]
    fn test_parse_pattern_middle_abcd() {
        // 测试中间匹配: 0xXXXXXXXXXXXXabcdXXXXXXXXXXXXXXXXXXXXXXXX
        // "abcd" 在第7-8字节位置 (索引6-7)
        let (_condition, pattern_config) =
            parse_pattern_condition("0xXXXXXXXXXXXXabcdXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();

        // "abcd" = [0xab, 0xcd] 在位置 6-7
        assert_eq!(pattern_config.mask[6], 0xFF);
        assert_eq!(pattern_config.mask[7], 0xFF);
        assert_eq!(pattern_config.value[6], 0xab);
        assert_eq!(pattern_config.value[7], 0xcd);

        // 其他字节应该是通配符
        assert_eq!(pattern_config.mask[0], 0);
        assert_eq!(pattern_config.mask[19], 0);
    }

    #[test]
    fn test_parse_pattern_mixed() {
        // 测试混合模式: 0x00XX11XX22XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        let (_condition, pattern_config) =
            parse_pattern_condition("0x00XX11XX22XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();

        // 第0字节: 00 (完全匹配)
        assert_eq!(pattern_config.mask[0], 0xFF);
        assert_eq!(pattern_config.value[0], 0x00);

        // 第1字节: XX (通配符)
        assert_eq!(pattern_config.mask[1], 0x00);

        // 第2字节: 11 (完全匹配)
        assert_eq!(pattern_config.mask[2], 0xFF);
        assert_eq!(pattern_config.value[2], 0x11);

        // 第3字节: XX (通配符)
        assert_eq!(pattern_config.mask[3], 0x00);

        // 第4字节: 22 (完全匹配)
        assert_eq!(pattern_config.mask[4], 0xFF);
        assert_eq!(pattern_config.value[4], 0x22);
    }

    #[test]
    fn test_parse_pattern_invalid_length() {
        // 测试无效长度
        let result = parse_pattern_condition("0x1234");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("40 hex characters")
        );
    }

    #[test]
    fn test_parse_pattern_invalid_char() {
        // 测试无效字符 - 使用正确的40字符长度
        let result = parse_pattern_condition("0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXGXXXX");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid") || err_msg.contains("character"));
    }

    #[test]
    fn test_parse_pattern_wildcard_variants() {
        // 测试不同的通配符: X, x, *, ?
        let (_condition, pattern_config) =
            parse_pattern_condition("0xXx*?1234XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX").unwrap();

        // 前4个字符是通配符
        assert_eq!(pattern_config.mask[0], 0x00);
        assert_eq!(pattern_config.mask[1], 0x00);

        // "1234" = [0x12, 0x34] 在位置 2-3
        assert_eq!(pattern_config.mask[2], 0xFF);
        assert_eq!(pattern_config.value[2], 0x12);
        assert_eq!(pattern_config.mask[3], 0xFF);
        assert_eq!(pattern_config.value[3], 0x34);
    }
}
