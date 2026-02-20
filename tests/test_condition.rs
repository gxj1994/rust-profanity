//! 条件匹配系统测试
//! 验证前缀、后缀、前导零匹配逻辑

use ocl::{ProQue, Buffer, MemFlags};

/// 条件类型
const COND_PREFIX: u16 = 0x01;
const COND_SUFFIX: u16 = 0x02;
const COND_LEADING: u16 = 0x04;

/// 加载 OpenCL 内核源码
fn load_kernel_source() -> String {
    include_str!("../kernels/utils/condition.cl").to_string()
}

/// 编码条件
fn encode_condition(cond_type: u16, param: u64) -> u64 {
    ((cond_type as u64) << 48) | (param & 0xFFFFFFFFFFFF)
}

/// Rust 端前缀比较
fn rust_compare_prefix(address: &[u8; 20], prefix: &[u8]) -> bool {
    if prefix.len() > 6 {
        return false;
    }
    address.starts_with(prefix)
}

/// Rust 端后缀比较
fn rust_compare_suffix(address: &[u8; 20], suffix: &[u8]) -> bool {
    if suffix.len() > 6 {
        return false;
    }
    address.ends_with(suffix)
}

/// Rust 端前导零计数
fn rust_count_leading_zeros(address: &[u8; 20]) -> u32 {
    address.iter().take_while(|&&b| b == 0).count() as u32
}

/// OpenCL 端条件检查
fn opencl_check_condition(address: &[u8; 20], condition: u64) -> ocl::Result<bool> {
    let kernel_source = load_kernel_source();
    
    let proque = ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    // 地址缓冲区
    let address_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(20)
        .copy_host_slice(address)
        .build()?;
    
    // 结果缓冲区
    let result_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(1)
        .build()?;
    
    // 创建内核
    let kernel = proque.kernel_builder("check_condition")
        .arg(&address_buffer)
        .arg(condition)
        .arg(&result_buffer)
        .build()?;
    
    // 执行内核
    unsafe {
        kernel.enq()?;
    }
    
    // 读取结果
    let mut result = vec![0u8; 1];
    result_buffer.read(&mut result).enq()?;
    
    Ok(result[0] != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// 测试前缀匹配
    #[test]
    fn test_prefix_matching() {
        // 测试地址: 0x888888... (前缀 0x888888)
        let mut address = [0u8; 20];
        address[0] = 0x88;
        address[1] = 0x88;
        address[2] = 0x88;
        
        // 测试匹配
        assert!(rust_compare_prefix(&address, &[0x88]));
        assert!(rust_compare_prefix(&address, &[0x88, 0x88]));
        assert!(rust_compare_prefix(&address, &[0x88, 0x88, 0x88]));
        
        // 测试不匹配
        assert!(!rust_compare_prefix(&address, &[0x99]));
        assert!(!rust_compare_prefix(&address, &[0x88, 0x99]));
        
        // 测试空前缀 (应该匹配)
        assert!(rust_compare_prefix(&address, &[]));
    }

    /// 测试后缀匹配
    #[test]
    fn test_suffix_matching() {
        // 测试地址: ...deadbeef (后缀 0xdeadbeef)
        let mut address = [0u8; 20];
        address[16] = 0xde;
        address[17] = 0xad;
        address[18] = 0xbe;
        address[19] = 0xef;
        
        // 测试匹配
        assert!(rust_compare_suffix(&address, &[0xef]));
        assert!(rust_compare_suffix(&address, &[0xbe, 0xef]));
        assert!(rust_compare_suffix(&address, &[0xad, 0xbe, 0xef]));
        assert!(rust_compare_suffix(&address, &[0xde, 0xad, 0xbe, 0xef]));
        
        // 测试不匹配
        assert!(!rust_compare_suffix(&address, &[0xde]));
        assert!(!rust_compare_suffix(&address, &[0xde, 0xad]));
    }

    /// 测试前导零计数
    #[test]
    fn test_leading_zeros() {
        // 0 个前导零
        let address1 = [0x11u8; 20];
        assert_eq!(rust_count_leading_zeros(&address1), 0);
        
        // 3 个前导零
        let mut address2 = [0u8; 20];
        address2[3] = 0x11;
        assert_eq!(rust_count_leading_zeros(&address2), 3);
        
        // 全部前导零
        let address3 = [0u8; 20];
        assert_eq!(rust_count_leading_zeros(&address3), 20);
        
        // 1 个前导零
        let mut address4 = [0u8; 20];
        address4[0] = 0x00;
        address4[1] = 0x11;
        assert_eq!(rust_count_leading_zeros(&address4), 1);
    }

    /// 测试条件编码
    #[test]
    fn test_condition_encoding() {
        // 前缀条件: 0x8888
        let prefix_cond = encode_condition(COND_PREFIX, 0x8888);
        assert_eq!((prefix_cond >> 48) as u16, COND_PREFIX);
        assert_eq!(prefix_cond & 0xFFFFFFFFFFFF, 0x8888);
        
        // 后缀条件: 0xdead
        let suffix_cond = encode_condition(COND_SUFFIX, 0xdead);
        assert_eq!((suffix_cond >> 48) as u16, COND_SUFFIX);
        assert_eq!(suffix_cond & 0xFFFFFFFFFFFF, 0xdead);
        
        // 前导零条件: 4 个
        let leading_cond = encode_condition(COND_LEADING, 4);
        assert_eq!((leading_cond >> 48) as u16, COND_LEADING);
        assert_eq!(leading_cond & 0xFFFFFFFFFFFF, 4);
    }

    /// 测试完整条件匹配场景
    #[test]
    fn test_full_condition_scenarios() {
        // 场景 1: 匹配前缀 0x1234
        let mut address1 = [0u8; 20];
        address1[0] = 0x12;
        address1[1] = 0x34;
        
        assert!(rust_compare_prefix(&address1, &[0x12, 0x34]));
        
        // 场景 2: 匹配后缀 0xabcd
        let mut address2 = [0u8; 20];
        address2[18] = 0xab;
        address2[19] = 0xcd;
        
        assert!(rust_compare_suffix(&address2, &[0xab, 0xcd]));
        
        // 场景 3: 4 个前导零
        let mut address3 = [0u8; 20];
        address3[4] = 0x01;
        
        assert!(rust_count_leading_zeros(&address3) >= 4);
    }

    /// 测试边界条件
    #[test]
    fn test_edge_cases() {
        // 最大前缀长度 (6字节)
        let mut address = [0u8; 20];
        for i in 0..6 {
            address[i] = 0xAB;
        }
        
        let long_prefix = [0xABu8; 6];
        assert!(rust_compare_prefix(&address, &long_prefix));
        
        // 超过 6 字节的前缀应该失败
        let too_long_prefix = [0xABu8; 7];
        assert!(!rust_compare_prefix(&address, &too_long_prefix));
        
        // 最大后缀长度 (6字节)
        let mut address2 = [0u8; 20];
        for i in 0..6 {
            address2[14 + i] = 0xCD;
        }
        
        let long_suffix = [0xCDu8; 6];
        assert!(rust_compare_suffix(&address2, &long_suffix));
    }

    /// 测试以太坊靓号场景
    #[test]
    fn test_vanity_scenarios() {
        // 靓号: 0x0000... (多个前导零)
        let mut address1 = [0u8; 20];
        address1[4] = 0x01;  // 4 个前导零
        
        assert_eq!(rust_count_leading_zeros(&address1), 4);
        
        // 靓号: 0x8888... (特定前缀)
        let mut address2 = [0u8; 20];
        address2[0] = 0x88;
        address2[1] = 0x88;
        
        assert!(rust_compare_prefix(&address2, &[0x88, 0x88]));
        
        // 靓号: ...DEAD (特定后缀)
        let mut address3 = [0u8; 20];
        address3[18] = 0xDE;
        address3[19] = 0xAD;
        
        assert!(rust_compare_suffix(&address3, &[0xDE, 0xAD]));
    }
}

/// OpenCL 兼容性测试
#[cfg(test)]
mod opencl_tests {
    use super::*;
    
    /// 测试 OpenCL 条件检查 (如果可用)
    #[test]
    fn test_opencl_condition_check() {
        let address = [0x88u8; 20];
        let condition = encode_condition(COND_PREFIX, 0x8888);
        
        match opencl_check_condition(&address, condition) {
            Ok(result) => {
                // 应该匹配
                assert!(result, "OpenCL 前缀匹配失败");
            }
            Err(e) => {
                println!("OpenCL 测试跳过: {}", e);
            }
        }
    }
    
    /// 测试 OpenCL 前导零检查
    #[test]
    fn test_opencl_leading_zeros() {
        let mut address = [0u8; 20];
        address[3] = 0x01;  // 3 个前导零
        
        let condition = encode_condition(COND_LEADING, 3);
        
        match opencl_check_condition(&address, condition) {
            Ok(result) => {
                assert!(result, "OpenCL 前导零检查失败");
            }
            Err(e) => {
                println!("OpenCL 测试跳过: {}", e);
            }
        }
    }
}
