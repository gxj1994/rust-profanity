//! BIP32 密钥派生测试

use secp256k1::{SecretKey, PublicKey, Secp256k1};
use hmac::{Hmac, Mac};
use sha2::Sha512;

#[cfg(test)]
mod tests {
    use super::*;
    
    type HmacSha512 = Hmac<Sha512>;
    
    /// BIP32 secp256k1 阶 n
    const SECP256K1_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ];
    
    /// 将字节数组转换为 u64 数组（大端序）
    fn bytes_to_u64_be(bytes: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            u64::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            u64::from_be_bytes([
                bytes[16], bytes[17], bytes[18], bytes[19],
                bytes[20], bytes[21], bytes[22], bytes[23],
            ]),
            u64::from_be_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27],
                bytes[28], bytes[29], bytes[30], bytes[31],
            ]),
        ]
    }
    
    /// 将 u64 数组转换为字节数组（大端序）
    fn u64_to_bytes_be(value: &[u64; 4]) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&value[0].to_be_bytes());
        result[8..16].copy_from_slice(&value[1].to_be_bytes());
        result[16..24].copy_from_slice(&value[2].to_be_bytes());
        result[24..32].copy_from_slice(&value[3].to_be_bytes());
        result
    }
    
    /// 比较两个 uint256（大端序）
    fn uint256_cmp_be(a: &[u64; 4], b: &[u64; 4]) -> i32 {
        for i in 0..4 {
            if a[i] < b[i] { return -1; }
            if a[i] > b[i] { return 1; }
        }
        0
    }
    
    /// 模加: (a + b) mod n
    fn mod_add_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let a_u64 = bytes_to_u64_be(a);
        let b_u64 = bytes_to_u64_be(b);
        let n_u64 = bytes_to_u64_be(&SECP256K1_N);
        
        let mut carry = 0u64;
        let mut sum = [0u64; 4];
        
        // 从最低位（索引3）开始加法
        for i in (0..4).rev() {
            let temp_sum = a_u64[i].wrapping_add(b_u64[i]);
            let carry1 = if temp_sum < a_u64[i] { 1 } else { 0 };
            
            let final_sum = temp_sum.wrapping_add(carry);
            let carry2 = if final_sum < temp_sum { 1 } else { 0 };
            
            carry = carry1 + carry2;
            sum[i] = final_sum;
        }
        
        // 如果结果 >= n，减去 n
        if carry > 0 || uint256_cmp_be(&sum, &n_u64) >= 0 {
            let mut borrow = 0u64;
            for i in (0..4).rev() {
                let diff = sum[i].wrapping_sub(n_u64[i]).wrapping_sub(borrow);
                // 检查是否需要借位：如果 sum[i] < n_u64[i]，或者 sum[i] == n_u64[i] 且 borrow == 1
                borrow = if sum[i] < n_u64[i] || (sum[i] == n_u64[i] && borrow == 1) { 1 } else { 0 };
                sum[i] = diff;
            }
        }
        
        u64_to_bytes_be(&sum)
    }
    
    /// 调试打印字节数组
    fn print_hex(label: &str, data: &[u8]) {
        print!("{}: ", label);
        for byte in data {
            print!("{:02x}", byte);
        }
        println!();
    }
    
    /// 调试打印 u64 数组（大端序）
    fn print_u64(label: &str, data: &[u64; 4]) {
        print!("{}: [", label);
        for (i, val) in data.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("0x{:016x}", val);
        }
        println!("]");
    }

    #[test]
    fn test_private_to_public() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let public_key_bytes = public_key.serialize_uncompressed();
        assert_eq!(public_key_bytes.len(), 65);
        assert_eq!(public_key_bytes[0], 0x04);

        let expected_public = hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        ).unwrap();
        assert_eq!(public_key_bytes.to_vec(), expected_public);
    }

    #[test]
    fn test_private_to_public_2() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        ).unwrap();

        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let public_key_bytes = public_key.serialize_uncompressed();
        assert_eq!(public_key_bytes.len(), 65);
        assert!(public_key_bytes[1..33].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_invalid_private_key() {
        let invalid_key = [0u8; 32];
        assert!(SecretKey::from_slice(&invalid_key).is_err());
    }

    #[test]
    fn test_key_serialization() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let secret_bytes = secret_key.secret_bytes();
        let public_bytes = public_key.serialize_uncompressed();

        let recovered_secret = SecretKey::from_slice(&secret_bytes).unwrap();
        let recovered_public = PublicKey::from_secret_key(&secp, &recovered_secret);

        assert_eq!(public_bytes.to_vec(), recovered_public.serialize_uncompressed().to_vec());
    }

    #[test]
    fn test_compressed_public_key() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let compressed = public_key.serialize();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn test_hmac_sha512_master_key() {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = b"Bitcoin seed";

        let mut mac = HmacSha512::new_from_slice(key).unwrap();
        mac.update(&seed);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        assert_eq!(bytes.len(), 64);

        let _master_private_key = &bytes[..32];
        let _master_chain_code = &bytes[32..];
    }

    #[test]
    fn test_derivation_index() {
        let hardened_44: u32 = 0x8000002C;
        let hardened_60: u32 = 0x8000003C;
        let normal_0: u32 = 0x00000000;

        assert!(hardened_44 >= 0x80000000);
        assert!(hardened_60 >= 0x80000000);
        assert!(normal_0 < 0x80000000);

        assert_eq!(hardened_44, 2147483692);
        assert_eq!(hardened_60, 2147483708);
    }
    
    /// 详细的 BIP32 派生调试测试
    /// 对比 Rust 和 OpenCL 的每一步中间结果
    #[test]
    fn test_bip32_derivation_debug() {
        println!("\n========== BIP32 派生详细调试 ==========\n");
        
        // 使用与 OpenCL 测试相同的助记词 (23个 abandon + art)
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        
        // 1. 从助记词生成种子
        let salt = format!("mnemonic{}", "");
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            mnemonic_phrase.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed,
        );
        print_hex("Seed", &seed);
        
        // 2. 生成主密钥
        let key = b"Bitcoin seed";
        let mut mac = HmacSha512::new_from_slice(key).unwrap();
        mac.update(&seed);
        let master_key_bytes = mac.finalize().into_bytes();
        let master_key: [u8; 64] = master_key_bytes.as_slice().try_into().unwrap();
        
        print_hex("Master Private Key", &master_key[0..32]);
        print_hex("Master Chain Code", &master_key[32..64]);
        
        // 验证主私钥 u64 表示
        let master_priv_u64 = bytes_to_u64_be(&master_key[0..32].try_into().unwrap());
        print_u64("Master Private Key (u64)", &master_priv_u64);
        
        // 3. 派生路径: m/44'/60'/0'/0/0
        let path = [0x8000002Cu32, 0x8000003Cu32, 0x80000000u32, 0x00000000u32, 0x00000000u32];
        
        let mut current_key = master_key;
        
        for (i, &index) in path.iter().enumerate() {
            println!("\n--- 派生步骤 {}: index = 0x{:08x} ---", i + 1, index);
            
            // 构建 HMAC 数据
            let mut data = [0u8; 37];
            if index >= 0x80000000 {
                // 硬化派生
                data[0] = 0x00;
                data[1..33].copy_from_slice(&current_key[0..32]);
            } else {
                // 普通派生 - 计算公钥
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&current_key[0..32]).unwrap();
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                let compressed = public_key.serialize();
                data[0..33].copy_from_slice(&compressed);
            }
            data[33] = (index >> 24) as u8;
            data[34] = (index >> 16) as u8;
            data[35] = (index >> 8) as u8;
            data[36] = index as u8;
            
            print_hex("HMAC Data", &data);
            
            // HMAC-SHA512
            let mut mac = HmacSha512::new_from_slice(&current_key[32..64]).unwrap();
            mac.update(&data);
            let hmac_result = mac.finalize().into_bytes();
            let hmac_arr: [u8; 64] = hmac_result.as_slice().try_into().unwrap();
            
            print_hex("HMAC Left (IL)", &hmac_arr[0..32]);
            print_hex("HMAC Right (IR)", &hmac_arr[32..64]);
            
            // 验证 IL 的 u64 表示
            let il_u64 = bytes_to_u64_be(&hmac_arr[0..32].try_into().unwrap());
            print_u64("IL (u64)", &il_u64);
            
            // 验证父私钥的 u64 表示
            let parent_priv_u64 = bytes_to_u64_be(&current_key[0..32].try_into().unwrap());
            print_u64("Parent Private Key (u64)", &parent_priv_u64);
            
            // 模加运算
            let parent_priv: [u8; 32] = current_key[0..32].try_into().unwrap();
            let il: [u8; 32] = hmac_arr[0..32].try_into().unwrap();
            let child_priv = mod_add_n(&parent_priv, &il);
            
            // 显示原始加法结果（仅用于调试，使用大整数加法）
            print_hex("IL (hex)", &il);
            print_hex("Parent (hex)", &parent_priv);
            print_hex("Child Private Key (after mod n)", &child_priv);
            
            // 验证子私钥的 u64 表示
            let child_priv_u64 = bytes_to_u64_be(&child_priv);
            print_u64("Child Private Key (u64)", &child_priv_u64);
            
            // 更新当前密钥
            current_key[0..32].copy_from_slice(&child_priv);
            current_key[32..64].copy_from_slice(&hmac_arr[32..64]);
            
            print_hex("Current Key (Private)", &current_key[0..32]);
            print_hex("Current Key (Chain Code)", &current_key[32..64]);
        }
        
        println!("\n========== 最终私钥 ==========");
        print_hex("Final Private Key", &current_key[0..32]);
        
        // 验证私钥有效性
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&current_key[0..32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        println!("Public Key (compressed): {}", hex::encode(public_key.serialize()));
    }
    
    /// 测试字节序转换函数
    #[test]
    fn test_endianness_conversion() {
        // 测试值: 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        
        print_hex("Original bytes", &bytes);
        
        let u64_arr = bytes_to_u64_be(&bytes);
        print_u64("As u64 array", &u64_arr);
        
        // 期望的 u64 值（大端序）
        assert_eq!(u64_arr[0], 0x0102030405060708);
        assert_eq!(u64_arr[1], 0x090a0b0c0d0e0f10);
        assert_eq!(u64_arr[2], 0x1112131415161718);
        assert_eq!(u64_arr[3], 0x191a1b1c1d1e1f20);
        
        // 转换回字节
        let bytes_back = u64_to_bytes_be(&u64_arr);
        print_hex("Converted back", &bytes_back);
        
        assert_eq!(bytes, bytes_back);
        
        // 测试 SECP256K1_N 的 u64 表示
        let n_u64 = bytes_to_u64_be(&SECP256K1_N);
        print_u64("SECP256K1_N (u64)", &n_u64);
        // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert_eq!(n_u64[0], 0xFFFFFFFFFFFFFFFF);
        assert_eq!(n_u64[1], 0xFFFFFFFFFFFFFFFE);
        assert_eq!(n_u64[2], 0xBAAEDCE6AF48A03B);
        assert_eq!(n_u64[3], 0xBFD25E8CD0364141);
    }
    
    /// 测试模加运算
    #[test]
    fn test_mod_add() {
        // 测试简单加法
        let a: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let b: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        
        let result = mod_add_n(&a, &b);
        print_hex("1 + 2 mod n", &result);
        
        let expected: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        ];
        assert_eq!(result, expected);
        
        // 测试溢出（接近 n 的值）
        let c: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40, // n - 1
        ];
        let d: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
        ];
        
        let result2 = mod_add_n(&c, &d);
        print_hex("(n-1) + 1 mod n", &result2);
        
        // 结果应该是 0
        let expected2 = [0u8; 32];
        assert_eq!(result2, expected2);
    }
    
    /// 对比测试：验证 Rust 与 OpenCL 的 BIP32 派生中间值
    #[test]
    fn test_bip32_step_by_step_comparison() {
        println!("\n========== BIP32 逐步对比 (Rust vs OpenCL 期望) ==========\n");
        
        // 主密钥 (来自 OpenCL 测试)
        let master_key: [u8; 64] = [
            0x23, 0x5b, 0x34, 0xcd, 0x7c, 0x9f, 0x6d, 0x7e, 0x45, 0x95, 0xff, 0xe9, 0xae, 0x4b, 0x1c, 0xb5,
            0x60, 0x6d, 0xf8, 0xac, 0xa2, 0xb5, 0x27, 0xd2, 0x0a, 0x07, 0xc8, 0xf5, 0x6b, 0x23, 0x42, 0xf4,
            0xf4, 0x0e, 0xaa, 0xd2, 0x16, 0x41, 0xca, 0x7c, 0xb5, 0xac, 0x00, 0xf9, 0xce, 0x21, 0xca, 0xc9,
            0xba, 0x07, 0x0b, 0xb6, 0x73, 0xa2, 0x37, 0xf7, 0xbc, 0xe5, 0x7a, 0xcd, 0xa5, 0x43, 0x86, 0xa4,
        ];
        
        print_hex("Master Key (Priv)", &master_key[0..32]);
        print_hex("Master Key (Chain)", &master_key[32..64]);
        
        // 派生路径
        let path = [0x8000002Cu32, 0x8000003Cu32, 0x80000000u32, 0x00000000u32, 0x00000000u32];
        
        let mut current_key = master_key;
        
        for (step, &index) in path.iter().enumerate() {
            println!("\n--- 步骤 {}: index = 0x{:08x} ---", step + 1, index);
            
            // 构建 HMAC 数据
            let mut data = [0u8; 37];
            if index >= 0x80000000 {
                data[0] = 0x00;
                data[1..33].copy_from_slice(&current_key[0..32]);
            } else {
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&current_key[0..32]).unwrap();
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                let compressed = public_key.serialize();
                data[0..33].copy_from_slice(&compressed);
            }
            data[33] = (index >> 24) as u8;
            data[34] = (index >> 16) as u8;
            data[35] = (index >> 8) as u8;
            data[36] = index as u8;
            
            print_hex("HMAC Data", &data);
            
            // HMAC-SHA512
            let mut mac = HmacSha512::new_from_slice(&current_key[32..64]).unwrap();
            mac.update(&data);
            let hmac_result = mac.finalize().into_bytes();
            
            print_hex("HMAC Left (IL)", &hmac_result[0..32]);
            print_hex("HMAC Right (IR)", &hmac_result[32..64]);
            
            // 模加
            let parent_priv: [u8; 32] = current_key[0..32].try_into().unwrap();
            let il: [u8; 32] = hmac_result[0..32].try_into().unwrap();
            let child_priv = mod_add_n(&parent_priv, &il);
            
            print_hex("Parent Priv", &parent_priv);
            print_hex("IL", &il);
            print_hex("Child Priv (mod n)", &child_priv);
            
            // 更新
            current_key[0..32].copy_from_slice(&child_priv);
            current_key[32..64].copy_from_slice(&hmac_result[32..64]);
        }
        
        println!("\n========== 最终结果 ==========");
        print_hex("Final Private Key", &current_key[0..32]);
        
        // 期望的结果（来自 OpenCL 测试中的 Rust 参考值）
        let expected: [u8; 32] = [
            0x10, 0x53, 0xfa, 0xe1, 0xb3, 0xac, 0x64, 0xf1,
            0x78, 0xbc, 0xc2, 0x10, 0x26, 0xfd, 0x06, 0xa3,
            0xf4, 0x54, 0x4e, 0xc2, 0xf3, 0x53, 0x38, 0xb0,
            0x01, 0xf0, 0x2d, 0x1d, 0x8e, 0xfa, 0x3d, 0x5f,
        ];
        print_hex("Expected", &expected);
        
        assert_eq!(&current_key[0..32], &expected[..], "最终私钥不匹配！");
        println!("✓ 结果匹配！");
    }
}
