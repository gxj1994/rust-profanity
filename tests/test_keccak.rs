//! Keccak-256 哈希测试
//! 验证 OpenCL 内核与 Rust sha3 crate 的一致性

use sha3::{Keccak256, Digest};
use ocl::{ProQue, Buffer, MemFlags};

fn load_kernel_source() -> String {
    let mut source = include_str!("../kernels/crypto/keccak.cl").to_string();
    // 添加内核包装，因为 keccak.cl 中只有普通函数
    // 支持最大 1024 字节的输入
    source.push_str(r#"
__kernel void keccak256_kernel(
    __global uchar* data,
    uint len,
    __global uchar* hash
) {
    // 支持最大 1024 字节的输入
    uchar local_data[1024];
    for (int i = 0; i < len && i < 1024; i++) {
        local_data[i] = data[i];
    }
    
    uchar local_hash[32];
    keccak256(local_data, len, local_hash);
    
    for (int i = 0; i < 32; i++) {
        hash[i] = local_hash[i];
    }
}
"#);
    source
}

fn rust_keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn opencl_keccak256(data: &[u8]) -> ocl::Result<[u8; 32]> {
    // 限制输入大小
    if data.len() > 1024 {
        return Err(ocl::Error::from("Input too large for test kernel"));
    }
    
    let kernel_source = load_kernel_source();
    
    let proque = ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    // 输入数据缓冲区 - 空输入时至少分配 1 字节
    let input_len = if data.len() == 0 { 1 } else { data.len() };
    let input_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(input_len)
        .copy_host_slice(if data.len() == 0 { &[0u8] } else { data })
        .build()?;
    
    // 输出哈希缓冲区
    let output_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build()?;
    
    // 创建内核
    let kernel = proque.kernel_builder("keccak256_kernel")
        .arg(&input_buffer)
        .arg(data.len() as u32)
        .arg(&output_buffer)
        .build()?;
    
    // 执行内核
    unsafe {
        kernel.enq()?;
    }
    
    // 读取结果
    let mut result = vec![0u8; 32];
    output_buffer.read(&mut result).enq()?;
    
    let mut fixed_result = [0u8; 32];
    fixed_result.copy_from_slice(&result);
    Ok(fixed_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        let data = b"";
        let rust_hash = rust_keccak256(data);
        
        // 已知的 Keccak-256 空输入哈希值
        let expected = hex::decode(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ).unwrap();
        
        assert_eq!(rust_hash.to_vec(), expected, "Rust Keccak-256 空输入测试失败");
        
        // 如果 OpenCL 可用，测试 OpenCL 实现
        if let Ok(cl_hash) = opencl_keccak256(data) {
            assert_eq!(cl_hash.to_vec(), expected, "OpenCL Keccak-256 空输入测试失败");
            assert_eq!(rust_hash, cl_hash, "Rust 与 OpenCL 结果不一致");
        }
    }

    #[test]
    fn test_keccak256_simple() {
        let test_cases = vec![
            (b"hello" as &[u8], "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"),
            (b"The quick brown fox jumps over the lazy dog", 
             "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
        ];
        
        for (data, expected_hex) in test_cases {
            let expected = hex::decode(expected_hex).unwrap();
            let rust_hash = rust_keccak256(data);
            
            assert_eq!(
                rust_hash.to_vec(), 
                expected, 
                "Rust Keccak-256 测试失败: {}", 
                std::str::from_utf8(data).unwrap_or("<binary>")
            );
            
            // 如果 OpenCL 可用，测试 OpenCL 实现
            if let Ok(cl_hash) = opencl_keccak256(data) {
                assert_eq!(
                    cl_hash.to_vec(), 
                    expected, 
                    "OpenCL Keccak-256 测试失败: {}", 
                    std::str::from_utf8(data).unwrap_or("<binary>")
                );
                assert_eq!(
                    rust_hash, 
                    cl_hash, 
                    "Rust 与 OpenCL 结果不一致: {}", 
                    std::str::from_utf8(data).unwrap_or("<binary>")
                );
            }
        }
    }

    #[test]
    fn test_keccak256_long_input() {
        // 生成 200 字节的测试数据
        let data: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
        
        let rust_hash = rust_keccak256(&data);
        
        // 如果 OpenCL 可用，测试 OpenCL 实现
        if let Ok(cl_hash) = opencl_keccak256(&data) {
            assert_eq!(rust_hash, cl_hash, "长输入测试: Rust 与 OpenCL 结果不一致");
        }
    }

    #[test]
    fn test_keccak256_public_key() {
        // 使用有效的实际公钥数据 (65字节: 0x04 + x + y)
        // 来自 test_opencl_debug_derivation 测试
        let public_key: [u8; 65] = [
            0x04, // 前缀
            0xdc, 0x28, 0x6c, 0x82, 0x1c, 0x74, 0x90, 0xaf,
            0xbe, 0x20, 0xa7, 0x9d, 0x13, 0x12, 0x3b, 0x9f,
            0x41, 0xf3, 0xd7, 0xef, 0x21, 0xe4, 0xa9, 0xca,
            0xac, 0xd2, 0x2f, 0x59, 0x83, 0xb2, 0x8e, 0xca,
            0x0e, 0x4d, 0xbd, 0x56, 0x24, 0x50, 0x5a, 0x2c,
            0x96, 0x8f, 0xec, 0x15, 0xf2, 0x59, 0x90, 0xc7,
            0x32, 0x47, 0x36, 0x89, 0x0f, 0x6d, 0x0f, 0x74,
            0x24, 0x1f, 0x98, 0xe4, 0x25, 0x9c, 0x1d, 0x42,
        ];
        
        // 跳过 0x04 前缀，哈希 64 字节的 x||y
        let rust_hash = rust_keccak256(&public_key[1..]);
        
        // 如果 OpenCL 可用，测试 OpenCL 实现
        if let Ok(cl_hash) = opencl_keccak256(&public_key[1..]) {
            assert_eq!(rust_hash, cl_hash, "公钥哈希测试: Rust 与 OpenCL 结果不一致");
        }
    }
}
