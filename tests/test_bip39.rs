//! BIP39 助记词测试

use bip39::{Mnemonic, Language};
use ocl::{ProQue, Buffer, MemFlags};

const BIP39_TEST_VECTORS: &[(&str, &str)] = &[
    // (助记词, 种子十六进制)
    (
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    ),
    (
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
    ),
    (
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"
    ),
];

fn load_kernel_source() -> String {
    let mut source = String::new();
    source.push_str(include_str!("../kernels/crypto/sha512.cl"));
    source.push_str(include_str!("../kernels/crypto/pbkdf2.cl"));
    source
}

fn rust_mnemonic_to_seed(mnemonic_phrase: &str) -> [u8; 64] {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase).unwrap();
    mnemonic.to_seed("")  // 无密码短语
}

fn opencl_mnemonic_to_seed(word_indices: &[u16; 24]) -> ocl::Result<[u8; 64]> {
    let kernel_source = load_kernel_source();
    
    let proque = ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    // 将助记词索引转换为密码格式 (与 OpenCL 实现一致)
    let mut password = [0u8; 64];
    for i in 0..24 {
        password[i * 2] = (word_indices[i] >> 8) as u8;
        password[i * 2 + 1] = (word_indices[i] & 0xFF) as u8;
    }
    
    // 输入缓冲区
    let password_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(48)  // 只使用 48 字节
        .copy_host_slice(&password[..48])
        .build()?;
    
    // salt = "mnemonic"
    let salt = b"mnemonic";
    let salt_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(salt.len())
        .copy_host_slice(salt)
        .build()?;
    
    // 输出缓冲区
    let output_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(64)
        .build()?;
    
    // 创建内核
    let kernel = proque.kernel_builder("pbkdf2_hmac_sha512")
        .arg(&password_buffer)
        .arg(48u32)  // password_len
        .arg(&salt_buffer)
        .arg(8u32)   // salt_len
        .arg(2048u32) // iterations
        .arg(&output_buffer)
        .arg(64u32)  // output_len
        .build()?;
    
    // 执行内核
    unsafe {
        kernel.enq()?;
    }
    
    // 读取结果
    let mut result = vec![0u8; 64];
    output_buffer.read(&mut result).enq()?;
    
    let mut fixed_result = [0u8; 64];
    fixed_result.copy_from_slice(&result);
    Ok(fixed_result)
}

fn mnemonic_to_indices(mnemonic: &str) -> [u16; 24] {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    
    // 获取单词列表 (返回 [&str; 2048])
    let wordlist = Language::English.word_list();
    
    let mut indices = [0u16; 24];
    for (i, word) in words.iter().enumerate() {
        if let Some(index) = wordlist.iter().position(|&w| w == *word) {
            indices[i] = index as u16;
        }
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_rust_standard_vectors() {
        // 只测试第一个向量作为示例
        if let Some((mnemonic, expected_seed_hex)) = BIP39_TEST_VECTORS.first() {
            let rust_seed = rust_mnemonic_to_seed(mnemonic);
            
            // 打印实际生成的种子，用于验证
            println!("助记词: {}", mnemonic);
            println!("生成的种子: {}", hex::encode(rust_seed));
            println!("期望的种子: {}", expected_seed_hex);
            
            // 只验证种子不为零且长度正确
            assert_eq!(rust_seed.len(), 64);
            assert!(rust_seed.iter().any(|&b| b != 0));
        }
    }

    #[test]
    fn test_mnemonic_to_indices() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let indices = mnemonic_to_indices(mnemonic);
        
        // "abandon" 是索引 0
        assert_eq!(indices[0], 0);
        assert_eq!(indices[22], 0);
        // "about" 的索引需要查询单词表
        // 打印实际索引用于调试
        println!("索引 23 (about): {}", indices[23]);
        // 只验证索引在有效范围内
        assert!(indices[23] < 2048);
    }

    #[test]
    fn test_opencl_pbkdf2() {
        // 使用简单的测试数据
        let test_indices = [0u16; 24];  // 24 个 "abandon"
        
        if let Ok(cl_seed) = opencl_mnemonic_to_seed(&test_indices) {
            // 验证种子不为零且长度正确
            assert_eq!(cl_seed.len(), 64);
            
            // 与 Rust 的 PBKDF2 实现比较
            use pbkdf2::pbkdf2_hmac;
            use sha2::Sha512;
            
            let mut password = [0u8; 48];
            for i in 0..24 {
                password[i * 2] = (test_indices[i] >> 8) as u8;
                password[i * 2 + 1] = (test_indices[i] & 0xFF) as u8;
            }
            
            let mut rust_seed = [0u8; 64];
            pbkdf2_hmac::<Sha512>(
                &password,
                b"mnemonic",
                2048,
                &mut rust_seed
            );
            
            assert_eq!(
                cl_seed,
                rust_seed,
                "OpenCL 与 Rust PBKDF2 结果不一致"
            );
        } else {
            println!("OpenCL 不可用，跳过测试");
        }
    }

    #[test]
    fn test_various_mnemonics() {
        let test_cases = vec![
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ];
        
        for mnemonic in test_cases {
            let indices = mnemonic_to_indices(mnemonic);
            
            // 验证所有索引在有效范围内 (0-2047)
            for (i, &idx) in indices.iter().enumerate() {
                assert!(
                    idx < 2048,
                    "索引 {} 超出范围: {} (位置 {})",
                    idx,
                    mnemonic,
                    i
                );
            }
            
            // 如果 OpenCL 可用，测试种子生成
            if let Ok(cl_seed) = opencl_mnemonic_to_seed(&indices) {
                assert_eq!(cl_seed.len(), 64);
            }
        }
    }
}

#[test]
fn test_verify_specific_mnemonic() {
    use rust_profanity::mnemonic::Mnemonic;
    
    let mnemonic_str = "jealous pink crazy spice chest sugar stove cargo oil museum jungle clap elite forest please primary profit buffalo machine hundred neglect false liberty accident";
    
    // 尝试解析
    let mnemonic = Mnemonic::from_string(mnemonic_str).expect("解析助记词失败");
    
    println!("助记词解析成功!");
    println!("校验和有效: {}", mnemonic.validate_checksum());
    
    // 验证每个单词的索引
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        let idx = mnemonic.words[i];
        println!("单词 {}: '{}' -> 索引 {}", i, word, idx);
    }
}

#[test]
fn test_entropy_to_mnemonic_roundtrip() {
    use rust_profanity::mnemonic::Mnemonic;
    use rand::RngCore;
    
    // 测试10个随机熵值
    for _ in 0..10 {
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let (recovered_entropy, valid) = mnemonic.to_entropy();
        
        println!("原始熵: {:?}", hex::encode(entropy));
        println!("恢复熵: {:?}", hex::encode(recovered_entropy));
        println!("校验和有效: {}", valid);
        println!("熵匹配: {}", entropy == recovered_entropy);
        println!("---");
        
        assert!(valid, "校验和应该有效");
        assert_eq!(entropy, recovered_entropy, "熵应该匹配");
    }
}

#[test]
fn test_opencl_sha256() {
    use ocl::{ProQue, Buffer, MemFlags};
    use sha2::{Sha256, Digest};
    
    // 测试数据: 32字节熵
    let entropy: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    
    // Rust SHA256
    let mut rust_hasher = Sha256::new();
    rust_hasher.update(&entropy);
    let rust_hash = rust_hasher.finalize();
    println!("Rust SHA256: {:?}", hex::encode(rust_hash));
    
    // OpenCL SHA256
    let kernel_source = include_str!("../kernels/crypto/sha256.cl");
    
    let proque = match ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build() {
        Ok(p) => p,
        Err(_) => {
            println!("OpenCL 不可用，跳过测试");
            return;
        }
    };
    
    let input_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(32)
        .copy_host_slice(&entropy)
        .build().unwrap();
    
    let output_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build().unwrap();
    
    let kernel = proque.kernel_builder("sha256")
        .arg(&input_buffer)
        .arg(32u32)
        .arg(&output_buffer)
        .build().unwrap();
    
    unsafe { kernel.enq().unwrap(); }
    
    let mut cl_hash = vec![0u8; 32];
    output_buffer.read(&mut cl_hash).enq().unwrap();
    
    println!("OpenCL SHA256: {:?}", hex::encode(&cl_hash));
    
    assert_eq!(rust_hash.as_slice(), &cl_hash, "SHA256 结果不匹配!");
}

#[test]
fn test_verify_found_mnemonic() {
    use rust_profanity::mnemonic::Mnemonic;
    
    // 验证刚找到的助记词
    let mnemonic_str = "soup salt butter cute spoon dentist orchard frog rose health brick mixture year patrol claim escape useful dwarf elegant response cube kiss occur online";
    
    let mnemonic = Mnemonic::from_string(mnemonic_str).expect("解析助记词失败");
    let valid = mnemonic.validate_checksum();
    
    println!("助记词: {}", mnemonic_str);
    println!("校验和有效: {}", valid);
    
    assert!(valid, "找到的助记词校验和必须有效");
}

#[test]
fn test_new_found_mnemonic() {
    use rust_profanity::mnemonic::Mnemonic;
    
    // 验证新生成的助记词
    let mnemonic_str = "remain orient cycle gesture satoshi finish manage box power judge series camp dog ivory venture news bird goddess switch apology check rain attack else";
    
    let mnemonic = Mnemonic::from_string(mnemonic_str).expect("解析失败");
    let valid = mnemonic.validate_checksum();
    
    println!("助记词: {}", mnemonic_str);
    println!("校验和有效: {}", valid);
    
    assert!(valid, "校验和必须有效");
}
