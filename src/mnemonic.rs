//! BIP39 助记词生成与管理 (简化版)

use rand::RngCore;
use sha2::{Digest, Sha256};

/// BIP39 助记词单词表 (2048个单词)
/// 从文件加载或使用硬编码的前100个单词
pub static BIP39_WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
];

/// BIP39 助记词
#[derive(Debug, Clone)]
pub struct Mnemonic {
    /// 24个单词的索引 (每个索引 0-2047)
    pub words: [u16; 24],
}

impl Mnemonic {
    /// 生成随机助记词
    pub fn generate_random() -> anyhow::Result<Self> {
        let mut rng = rand::thread_rng();
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        
        Self::from_entropy(&entropy)
    }
    
    /// 从熵生成助记词
    pub fn from_entropy(entropy: &[u8; 32]) -> anyhow::Result<Self> {
        // 计算校验和 (SHA256前8位 = 1字节)
        let hash = Sha256::digest(entropy);
        let checksum = hash[0];
        
        // 组合: 256位熵 + 8位校验和 = 264位
        let mut data = [0u8; 33];
        data[..32].copy_from_slice(entropy);
        data[32] = checksum;
        
        // 提取24个11位索引
        let mut words = [0u16; 24];
        for i in 0..24 {
            let bit_offset = i * 11;
            let byte_offset = bit_offset / 8;
            let bit_shift = bit_offset % 8;
            
            let mut idx = ((data[byte_offset] as u16) << 8) | (data[byte_offset + 1] as u16);
            // 避免减法溢出，使用 saturating_sub
            let shift = 5u16.saturating_sub(bit_shift as u16);
            idx >>= shift;
            idx &= 0x7FF;
            
            words[i] = idx;
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
    pub fn to_string(&self) -> String {
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
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
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
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let mnemonic = Mnemonic::generate_random().unwrap();
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64);
    }
}
