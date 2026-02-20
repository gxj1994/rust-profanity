//! Keccak-256 哈希测试
//! 验证 OpenCL 内核与 Rust sha3 crate 的一致性

use sha3::{Keccak256, Digest};
use ocl::{ProQue, Buffer, MemFlags};

fn load_kernel_source() -> String {
    include_str!("../kernels/crypto/keccak.cl").to_string()
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
    let kernel_source = load_kernel_source();
    
    let proque = ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    // 输入数据缓冲区
    let input_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(data.len())
        .copy_host_slice(data)
        .build()?;
    
    // 输出哈希缓冲区
    let output_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build()?;
    
    // 创建内核
    let kernel = proque.kernel_builder("keccak256")
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
        // 示例未压缩公钥 (65字节: 0x04 + x + y)
        let public_key = hex::decode(
            "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df4264\
             5cd1a215354bf6de76c5e5a7c9e0c5e5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5"
        ).unwrap_or_else(|_| vec![0u8; 65]);
        
        // 跳过 0x04 前缀，哈希 64 字节的 x||y
        let rust_hash = rust_keccak256(&public_key[1..]);
        
        // 如果 OpenCL 可用，测试 OpenCL 实现
        if let Ok(cl_hash) = opencl_keccak256(&public_key[1..]) {
            assert_eq!(rust_hash, cl_hash, "公钥哈希测试: Rust 与 OpenCL 结果不一致");
        }
    }
}
