//! OpenCL 内核源代码加载模块
//!
//! 提供统一的内核源代码加载功能，避免在 main.rs 和测试代码中重复。

/// 加载完整版内核源代码 (包含完整加密实现)
///
/// 按正确的依赖顺序合并所有内核文件:
/// 1. SHA-512 (PBKDF2 依赖)
/// 2. PBKDF2 (BIP39 依赖)
/// 3. SHA-256 (BIP39 校验和计算依赖)
/// 4. Keccak-256 (以太坊地址生成)
/// 5. secp256k1 (椭圆曲线运算)
/// 6. 条件匹配
/// 7. BIP39 词表
/// 8. BIP39 熵处理
/// 9. 主搜索内核
/// 10. BIP39 助记词处理
///
/// # Example
/// ```
/// use rust_profanity::load_kernel_source;
///
/// let kernel_source = load_kernel_source().expect("Failed to load kernel source");
/// ```
pub fn load_kernel_source() -> anyhow::Result<String> {
    let mut source = String::new();

    // 1. SHA-512 (PBKDF2 依赖)
    source.push_str(include_str!("../kernels/crypto/sha512.cl"));
    source.push('\n');

    // 2. PBKDF2 (BIP39 依赖)
    source.push_str(include_str!("../kernels/crypto/pbkdf2.cl"));
    source.push('\n');

    // 3. SHA-256 (BIP39 校验和计算依赖)
    source.push_str(include_str!("../kernels/crypto/sha256.cl"));
    source.push('\n');

    // 4. Keccak-256 (以太坊地址生成)
    source.push_str(include_str!("../kernels/crypto/keccak.cl"));
    source.push('\n');

    // 5. secp256k1 (椭圆曲线运算)
    source.push_str(include_str!("../kernels/crypto/secp256k1.cl"));
    source.push('\n');

    // 6. 条件匹配
    source.push_str(include_str!("../kernels/utils/condition.cl"));
    source.push('\n');

    // 7. BIP39 词表 (entropy.cl 和 mnemonic.cl 依赖)
    source.push_str(include_str!("../kernels/bip39/wordlist.cl"));
    source.push('\n');

    // 8. BIP39 熵处理 (entropy_to_mnemonic 等，依赖 sha256 和 wordlist)
    source.push_str(include_str!("../kernels/bip39/entropy.cl"));
    source.push('\n');

    // 9. 主搜索内核 (包含 local_mnemonic_t 定义，必须在 mnemonic.cl 之前)
    let search_kernel = include_str!("../kernels/search.cl");
    for line in search_kernel.lines() {
        if !line.trim_start().starts_with("#include") {
            source.push_str(line);
            source.push('\n');
        }
    }
    source.push('\n');

    // 10. BIP39 助记词处理 (依赖 local_mnemonic_t 和 wordlist.cl)
    source.push_str(include_str!("../kernels/bip39/mnemonic.cl"));
    source.push('\n');

    Ok(source)
}

/// 加载指定阶段的内核源代码 (用于测试和调试)
///
/// # Arguments
/// * `stages` - 要加载的内核阶段列表，按顺序:
///   - "sha512" - SHA-512 哈希
///   - "pbkdf2" - PBKDF2 密钥派生
///   - "sha256" - SHA-256 哈希
///   - "keccak" - Keccak-256 哈希
///   - "secp256k1" - 椭圆曲线运算
///   - "condition" - 条件匹配
///   - "wordlist" - BIP39 词表
///   - "entropy" - BIP39 熵处理
///   - "search" - 主搜索内核
///   - "mnemonic" - BIP39 助记词处理
///
/// # Example
/// ```
/// use rust_profanity::kernel_loader::load_kernel_stages;
///
/// let source = load_kernel_stages(&["sha512", "pbkdf2"]).expect("Failed to load stages");
/// ```
pub fn load_kernel_stages(stages: &[&str]) -> anyhow::Result<String> {
    let mut source = String::new();

    for stage in stages {
        match *stage {
            "sha512" => {
                source.push_str(include_str!("../kernels/crypto/sha512.cl"));
            }
            "pbkdf2" => {
                source.push_str(include_str!("../kernels/crypto/pbkdf2.cl"));
            }
            "sha256" => {
                source.push_str(include_str!("../kernels/crypto/sha256.cl"));
            }
            "keccak" => {
                source.push_str(include_str!("../kernels/crypto/keccak.cl"));
            }
            "secp256k1" => {
                source.push_str(include_str!("../kernels/crypto/secp256k1.cl"));
            }
            "condition" => {
                source.push_str(include_str!("../kernels/utils/condition.cl"));
            }
            "wordlist" => {
                source.push_str(include_str!("../kernels/bip39/wordlist.cl"));
            }
            "entropy" => {
                source.push_str(include_str!("../kernels/bip39/entropy.cl"));
            }
            "search" => {
                let search_kernel = include_str!("../kernels/search.cl");
                for line in search_kernel.lines() {
                    if !line.trim_start().starts_with("#include") {
                        source.push_str(line);
                        source.push('\n');
                    }
                }
            }
            "mnemonic" => {
                source.push_str(include_str!("../kernels/bip39/mnemonic.cl"));
            }
            _ => anyhow::bail!("Unknown kernel stage: {}", stage),
        }
        source.push('\n');
    }

    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_full_kernel() {
        let source = load_kernel_source();
        assert!(source.is_ok());
        let source = source.unwrap();
        assert!(!source.is_empty());
        // 验证包含关键函数定义
        assert!(source.contains("search_kernel"));
        assert!(source.contains("keccak256"));
        assert!(source.contains("pbkdf2_hmac_sha512"));
    }

    #[test]
    fn test_load_kernel_stages() {
        let source = load_kernel_stages(&["sha512", "pbkdf2"]).unwrap();
        assert!(source.contains("sha512"));
        assert!(source.contains("pbkdf2"));
        // 不应该包含其他阶段
        assert!(!source.contains("keccak256"));
    }

    #[test]
    fn test_load_unknown_stage() {
        let result = load_kernel_stages(&["unknown_stage"]).map_err(|e| e.to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown kernel stage"));
    }
}
