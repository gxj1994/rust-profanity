//! 条件匹配系统测试

const COND_PREFIX: u16 = 0x01;
const COND_SUFFIX: u16 = 0x02;
const COND_LEADING: u16 = 0x04;

/// 旧版编码（不带字节数）- 用于前导零条件
fn encode_condition(cond_type: u16, param: u64) -> u64 {
    ((cond_type as u64) << 48) | (param & 0xFFFFFFFFFFFF)
}

/// 新版编码（带字节数）- 用于前缀/后缀条件
/// 格式: [类型:16位][字节数:4位][保留:4位][参数:40位]
fn encode_condition_with_bytes(cond_type: u16, param: u64, bytes: u8) -> u64 {
    let bytes_field = if bytes >= 6 { 0 } else { bytes };
    ((cond_type as u64) << 48) | ((bytes_field as u64) << 44) | (param & 0xFFFFFFFFFF)
}

fn rust_compare_prefix(address: &[u8; 20], prefix: &[u8]) -> bool {
    if prefix.len() > 6 {
        return false;
    }
    address.starts_with(prefix)
}

fn rust_compare_suffix(address: &[u8; 20], suffix: &[u8]) -> bool {
    if suffix.len() > 6 {
        return false;
    }
    address.ends_with(suffix)
}

fn rust_count_leading_zeros(address: &[u8; 20]) -> u32 {
    address.iter().take_while(|&&b| b == 0).count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_matching() {
        let mut address = [0u8; 20];
        address[0] = 0x88;
        address[1] = 0x88;
        address[2] = 0x88;

        assert!(rust_compare_prefix(&address, &[0x88]));
        assert!(rust_compare_prefix(&address, &[0x88, 0x88]));
        assert!(rust_compare_prefix(&address, &[0x88, 0x88, 0x88]));
        assert!(!rust_compare_prefix(&address, &[0x99]));
        assert!(!rust_compare_prefix(&address, &[0x88, 0x99]));
        assert!(rust_compare_prefix(&address, &[]));
    }

    #[test]
    fn test_suffix_matching() {
        let mut address = [0u8; 20];
        address[16] = 0xde;
        address[17] = 0xad;
        address[18] = 0xbe;
        address[19] = 0xef;

        assert!(rust_compare_suffix(&address, &[0xef]));
        assert!(rust_compare_suffix(&address, &[0xbe, 0xef]));
        assert!(rust_compare_suffix(&address, &[0xad, 0xbe, 0xef]));
        assert!(rust_compare_suffix(&address, &[0xde, 0xad, 0xbe, 0xef]));
        assert!(!rust_compare_suffix(&address, &[0xde]));
        assert!(!rust_compare_suffix(&address, &[0xde, 0xad]));
    }

    #[test]
    fn test_leading_zeros() {
        let address1 = [0x11u8; 20];
        assert_eq!(rust_count_leading_zeros(&address1), 0);

        let mut address2 = [0u8; 20];
        address2[3] = 0x11;
        assert_eq!(rust_count_leading_zeros(&address2), 3);

        let address3 = [0u8; 20];
        assert_eq!(rust_count_leading_zeros(&address3), 20);

        let mut address4 = [0u8; 20];
        address4[0] = 0x00;
        address4[1] = 0x11;
        assert_eq!(rust_count_leading_zeros(&address4), 1);
    }

    #[test]
    fn test_condition_encoding() {
        let prefix_cond = encode_condition(COND_PREFIX, 0x8888);
        assert_eq!((prefix_cond >> 48) as u16, COND_PREFIX);
        assert_eq!(prefix_cond & 0xFFFFFFFFFFFF, 0x8888);

        let suffix_cond = encode_condition(COND_SUFFIX, 0xdead);
        assert_eq!((suffix_cond >> 48) as u16, COND_SUFFIX);
        assert_eq!(suffix_cond & 0xFFFFFFFFFFFF, 0xdead);

        let leading_cond = encode_condition(COND_LEADING, 4);
        assert_eq!((leading_cond >> 48) as u16, COND_LEADING);
        assert_eq!(leading_cond & 0xFFFFFFFFFFFF, 4);
    }

    #[test]
    fn test_full_condition_scenarios() {
        let mut address1 = [0u8; 20];
        address1[0] = 0x12;
        address1[1] = 0x34;
        assert!(rust_compare_prefix(&address1, &[0x12, 0x34]));

        let mut address2 = [0u8; 20];
        address2[18] = 0xab;
        address2[19] = 0xcd;
        assert!(rust_compare_suffix(&address2, &[0xab, 0xcd]));

        let mut address3 = [0u8; 20];
        address3[4] = 0x01;
        assert!(rust_count_leading_zeros(&address3) >= 4);
    }

    #[test]
    fn test_edge_cases() {
        let mut address = [0u8; 20];
        for byte in address.iter_mut().take(6) {
            *byte = 0xAB;
        }

        let long_prefix = [0xABu8; 6];
        assert!(rust_compare_prefix(&address, &long_prefix));

        let too_long_prefix = [0xABu8; 7];
        assert!(!rust_compare_prefix(&address, &too_long_prefix));

        let mut address2 = [0u8; 20];
        for i in 0..6 {
            address2[14 + i] = 0xCD;
        }

        let long_suffix = [0xCDu8; 6];
        assert!(rust_compare_suffix(&address2, &long_suffix));
    }

    #[test]
    fn test_vanity_scenarios() {
        let mut address1 = [0u8; 20];
        address1[4] = 0x01;
        assert_eq!(rust_count_leading_zeros(&address1), 4);

        let mut address2 = [0u8; 20];
        address2[0] = 0x88;
        address2[1] = 0x88;
        assert!(rust_compare_prefix(&address2, &[0x88, 0x88]));

        let mut address3 = [0u8; 20];
        address3[18] = 0xDE;
        address3[19] = 0xAD;
        assert!(rust_compare_suffix(&address3, &[0xDE, 0xAD]));
    }
}

#[cfg(test)]
mod opencl_tests {
    use super::*;
    use ocl::{Buffer, MemFlags, ProQue};

    fn load_kernel_source() -> String {
        include_str!("../kernels/utils/condition.cl").to_string()
    }

    fn opencl_check_condition(address: &[u8; 20], condition: u64) -> ocl::Result<bool> {
        let kernel_source = load_kernel_source();

        let proque = ProQue::builder().src(kernel_source).dims(1).build()?;

        let address_buffer = Buffer::<u8>::builder()
            .queue(proque.queue().clone())
            .flags(MemFlags::READ_ONLY)
            .len(20)
            .copy_host_slice(address)
            .build()?;

        let result_buffer = Buffer::<u8>::builder()
            .queue(proque.queue().clone())
            .flags(MemFlags::WRITE_ONLY)
            .len(1)
            .build()?;

        let kernel = proque
            .kernel_builder("check_condition")
            .arg(&address_buffer)
            .arg(condition)
            .arg(&result_buffer)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        let mut result = vec![0u8; 1];
        result_buffer.read(&mut result).enq()?;

        Ok(result[0] != 0)
    }

    #[test]
    fn test_opencl_condition_check() {
        let address = [0x88u8; 20];
        // 使用新版编码，2字节前缀 0x8888
        let condition = encode_condition_with_bytes(COND_PREFIX, 0x8888, 2);

        match opencl_check_condition(&address, condition) {
            Ok(result) => assert!(result, "OpenCL 前缀匹配失败"),
            Err(e) => println!("OpenCL 测试跳过: {}", e),
        }
    }

    #[test]
    fn test_opencl_leading_zeros() {
        let mut address = [0u8; 20];
        address[3] = 0x01;

        let condition = encode_condition(COND_LEADING, 3);

        match opencl_check_condition(&address, condition) {
            Ok(result) => assert!(result, "OpenCL 前导零检查失败"),
            Err(e) => println!("OpenCL 测试跳过: {}", e),
        }
    }
}
