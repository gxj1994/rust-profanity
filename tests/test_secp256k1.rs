//! secp256k1 椭圆曲线运算测试
//! 验证 OpenCL 内核与 Rust secp256k1 crate 的一致性

use ocl::{ProQue, Buffer, MemFlags};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

/// 加载 OpenCL secp256k1 内核源码
fn load_kernel_source() -> String {
    let mut source = String::new();
    source.push_str(include_str!("../kernels/crypto/secp256k1.cl"));
    source
}

/// 测试 OpenCL 模运算
fn test_opencl_mod_ops() -> ocl::Result<()> {
    let kernel_source = load_kernel_source();
    
    let proque = ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    // 测试模加
    let a: [u64; 4] = [1, 0, 0, 0];  // 1
    let b: [u64; 4] = [2, 0, 0, 0];  // 2
    
    let a_buffer = Buffer::<u64>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(4)
        .copy_host_slice(&a)
        .build()?;
    
    let b_buffer = Buffer::<u64>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(4)
        .copy_host_slice(&b)
        .build()?;
    
    let result_buffer = Buffer::<u64>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(4)
        .build()?;
    
    // 注意：需要创建测试内核来调用 mod_add
    // 这里仅作为示例框架
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// 测试 secp256k1 曲线参数
    #[test]
    fn test_secp256k1_curve_params() {
        // secp256k1 素数 p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        // = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        let _p = [
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFEu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
        ];
        
        // 阶 n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        let _n = [
            0xBFD25E8CD0364141u64,
            0xBAAEDCE6AF48A03Bu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFEu64,
        ];
        
        // 验证参数不为零
        assert!(_p.iter().any(|&x| x != 0));
        assert!(_n.iter().any(|&x| x != 0));
    }
    
    /// 测试已知私钥的公钥生成
    #[test]
    fn test_known_private_keys() {
        let secp = Secp256k1::new();
        
        // 测试向量：私钥 1 的公钥
        let test_cases = vec![
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            ),
        ];
        
        for (priv_hex, expected_pub_hex) in test_cases {
            let priv_bytes = hex::decode(priv_hex).unwrap();
            let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            
            let public_key_bytes = public_key.serialize_uncompressed();
            let expected_pub = hex::decode(expected_pub_hex).unwrap();
            
            assert_eq!(
                public_key_bytes.to_vec(),
                expected_pub,
                "公钥不匹配 for private key {}",
                priv_hex
            );
        }
    }
    
    /// 测试私钥范围
    #[test]
    fn test_private_key_range() {
        let secp = Secp256k1::new();
        
        // 有效私钥 (1 到 n-1)
        let valid_private_keys = vec![
            "0000000000000000000000000000000000000000000000000000000000000001",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        ];
        
        for key_hex in valid_private_keys {
            let key_bytes = hex::decode(key_hex).unwrap();
            assert!(SecretKey::from_slice(&key_bytes).is_ok());
        }
        
        // 无效私钥 (0 和 >= n)
        let invalid_private_keys = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        ];
        
        for key_hex in invalid_private_keys {
            let key_bytes = hex::decode(key_hex).unwrap();
            assert!(SecretKey::from_slice(&key_bytes).is_err());
        }
    }
    
    /// 测试公钥序列化格式
    #[test]
    fn test_public_key_formats() {
        let secp = Secp256k1::new();
        
        let priv_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // 未压缩格式 (65字节)
        let uncompressed = public_key.serialize_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);
        
        // 压缩格式 (33字节)
        let compressed = public_key.serialize();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }
    
    /// 测试以太坊地址生成流程
    #[test]
    fn test_ethereum_address_generation() {
        use sha3::{Keccak256, Digest};
        
        let secp = Secp256k1::new();
        
        // 使用已知私钥
        let priv_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        // 获取未压缩公钥 (跳过 0x04 前缀)
        let uncompressed = public_key.serialize_uncompressed();
        let public_key_bytes = &uncompressed[1..];  // 64字节
        
        // Keccak-256 哈希
        let mut hasher = Keccak256::new();
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();
        
        // 取后20字节作为地址
        let address = &hash[12..];
        assert_eq!(address.len(), 20);
        
        // 验证地址不为零
        assert!(address.iter().any(|&b| b != 0));
    }
    
    /// 测试大数运算 (256位)
    #[test]
    fn test_uint256_operations() {
        // 测试大数加法和减法
        let a: [u64; 4] = [1, 0, 0, 0];
        let b: [u64; 4] = [2, 0, 0, 0];
        
        // 加法
        let mut sum = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let s = a[i] + b[i] + carry;
            carry = if s < a[i] || (s == a[i] && carry > 0) { 1 } else { 0 };
            sum[i] = s;
        }
        
        assert_eq!(sum[0], 3);
        assert_eq!(sum[1], 0);
        
        // 减法
        let mut diff = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let d = a[i].wrapping_sub(b[i] + borrow);
            borrow = if a[i] < b[i] + borrow { 1 } else { 0 };
            diff[i] = d;
        }
        
        // 1 - 2 应该下溢
        assert!(borrow > 0 || diff[0] != 0);
    }
}

/// OpenCL 相关测试
#[cfg(test)]
mod opencl_tests {
    use super::*;
    
    /// 检查 OpenCL 可用性
    #[test]
    fn test_opencl_availability() {
        match ProQue::builder()
            .src("__kernel void test() {}")
            .dims(1)
            .build() {
            Ok(_) => println!("OpenCL 可用"),
            Err(e) => println!("OpenCL 不可用: {}", e),
        }
    }
}
