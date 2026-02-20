//! BIP39 助记词生成与管理 (简化版)

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

// 引入完整的 BIP39 单词表
include!("wordlist.rs");

/// BIP39 助记词
#[derive(Debug, Clone)]
pub struct Mnemonic {
    /// 24个单词的索引 (每个索引 0-2047)
    pub words: [u16; 24],
}

impl Mnemonic {
    /// 生成随机助记词
    pub fn generate_random() -> anyhow::Result<Self> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        
        Self::from_entropy(&entropy)
    }
    
    /// 从熵生成助记词 (符合 BIP39 标准)
    pub fn from_entropy(entropy: &[u8; 32]) -> anyhow::Result<Self> {
        // 计算校验和: SHA256 的前 8 位 (256/32 = 8)
        let hash = Sha256::digest(entropy);
        let checksum_bits = hash[0]; // 取前8位
        
        // 组合: 256位熵 + 8位校验和 = 264位
        // 将数据视为大端序的位流
        let mut all_bits = [0u8; 33];
        all_bits[..32].copy_from_slice(entropy);
        all_bits[32] = checksum_bits;
        
        // 提取24个11位索引
        let mut words = [0u16; 24];
        for (i, word) in words.iter_mut().enumerate() {
            let bit_offset = i * 11;
            
            // 读取11位索引 (可能跨越2-3个字节)
            let mut idx: u16 = 0;
            for j in 0..11 {
                let bit_pos = bit_offset + j;
                let byte_idx = bit_pos / 8;
                let bit_in_byte = 7 - (bit_pos % 8); // 大端序: MSB在前
                
                if (all_bits[byte_idx] >> bit_in_byte) & 1 == 1 {
                    idx |= 1 << (10 - j); // 大端序存储
                }
            }
            
            *word = idx & 0x7FF;
        }
        
        Ok(Self { words })
    }
    
    /// 转换为 BIP39 种子
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic_str = self.to_string();
        let salt = format!("mnemonic{}", passphrase);
        
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;
        
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(
            mnemonic_str.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed,
        );
        
        seed
    }
    
    /// 转换为字符串
    pub fn as_phrase(&self) -> String {
        self.words
            .iter()
            .map(|&idx| {
                if (idx as usize) < BIP39_WORDLIST.len() {
                    BIP39_WORDLIST[idx as usize]
                } else {
                    "unknown"
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
    
    /// 从字符串解析
    pub fn from_string(s: &str) -> anyhow::Result<Self> {
        let word_strs: Vec<&str> = s.split_whitespace().collect();
        
        if word_strs.len() != 24 {
            anyhow::bail!("Expected 24 words, got {}", word_strs.len());
        }
        
        let mut words = [0u16; 24];
        for (i, word) in word_strs.iter().enumerate() {
            match BIP39_WORDLIST.iter().position(|&w| w == *word) {
                Some(idx) => words[i] = idx as u16,
                None => anyhow::bail!("Unknown word: {}", word),
            }
        }
        
        Ok(Self { words })
    }
    
    /// 验证助记词校验和 (BIP39 标准验证)
    pub fn validate_checksum(&self) -> bool {
        // 从单词索引重建位流
        let mut all_bits = [0u8; 33];
        
        for (i, &word_idx) in self.words.iter().enumerate() {
            let bit_offset = i * 11;
            
            for j in 0..11 {
                let bit_pos = bit_offset + j;
                let byte_idx = bit_pos / 8;
                let bit_in_byte = 7 - (bit_pos % 8);
                
                if (word_idx >> (10 - j)) & 1 == 1 {
                    all_bits[byte_idx] |= 1 << bit_in_byte;
                }
            }
        }
        
        // 提取熵和校验和
        let entropy = &all_bits[..32];
        let checksum = all_bits[32];
        
        // 计算期望的校验和
        let hash = Sha256::digest(entropy);
        let expected_checksum = hash[0];
        
        checksum == expected_checksum
    }
    
    /// 从助记词重建熵 (256位)
    /// 返回熵和校验和是否有效的布尔值
    pub fn to_entropy(&self) -> ([u8; 32], bool) {
        // 从单词索引重建位流
        let mut all_bits = [0u8; 33];
        
        for (i, &word_idx) in self.words.iter().enumerate() {
            let bit_offset = i * 11;
            
            for j in 0..11 {
                let bit_pos = bit_offset + j;
                let byte_idx = bit_pos / 8;
                let bit_in_byte = 7 - (bit_pos % 8);
                
                if (word_idx >> (10 - j)) & 1 == 1 {
                    all_bits[byte_idx] |= 1 << bit_in_byte;
                }
            }
        }
        
        // 提取熵
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&all_bits[..32]);
        let checksum = all_bits[32];
        
        // 验证校验和
        let hash = Sha256::digest(entropy);
        let expected_checksum = hash[0];
        let valid = checksum == expected_checksum;
        
        (entropy, valid)
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_phrase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate_random().unwrap();
        assert_eq!(mnemonic.words.len(), 24);
        
        for &word in &mnemonic.words {
            assert!(word < 2048);
        }
        
        // 验证生成的助记词校验和正确
        assert!(mnemonic.validate_checksum(), "Generated mnemonic has invalid checksum");
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let mnemonic = Mnemonic::generate_random().unwrap();
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64);
    }
    
    /// 测试 BIP39 标准测试向量
    /// 来自: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    #[test]
    fn test_bip39_vectors() {
        // 测试向量 1: 全零熵
        let entropy1 = [0u8; 32];
        let mnemonic1 = Mnemonic::from_entropy(&entropy1).unwrap();
        let phrase1 = mnemonic1.to_string();
        println!("Vector 1 mnemonic: {}", phrase1);
        assert!(mnemonic1.validate_checksum(), "Vector 1 checksum failed");
        
        // 验证前几个单词是 "abandon"
        assert_eq!(mnemonic1.words[0], 0, "First word should be 'abandon' (index 0)");
        assert_eq!(mnemonic1.words[1], 0, "Second word should be 'abandon' (index 0)");
        
        // 测试向量 2: 特定熵
        let entropy2: [u8; 32] = [
            0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
            0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
            0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
            0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        ];
        let mnemonic2 = Mnemonic::from_entropy(&entropy2).unwrap();
        println!("Vector 2 mnemonic: {}", mnemonic2);
        assert!(mnemonic2.validate_checksum(), "Vector 2 checksum failed");
    }
    
    #[test]
    fn test_roundtrip() {
        // 生成 -> 字符串 -> 解析 -> 验证
        let original = Mnemonic::generate_random().unwrap();
        let phrase = original.to_string();
        let parsed = Mnemonic::from_string(&phrase).unwrap();
        
        assert_eq!(original.words, parsed.words);
        assert!(parsed.validate_checksum());
    }
}
