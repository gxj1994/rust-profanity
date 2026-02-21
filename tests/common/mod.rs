//! 测试公共模块
//!
//! 提供测试用的公共函数和工具

use rust_profanity::mnemonic::Mnemonic;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha3::{Keccak256, Digest};
use bip32::XPrv;

/// 从助记词生成以太坊地址 (使用 bip32 crate)
/// 
/// # Arguments
/// * `mnemonic_str` - BIP39 助记词字符串
/// * `path` - 派生路径，如 "m/44'/60'/0'/0/0"
///
/// # Returns
/// 返回以太坊地址 (20字节) 和对应的私钥 (32字节)
pub fn generate_ethereum_address_from_mnemonic(
    mnemonic_str: &str,
    path: &str,
) -> anyhow::Result<([u8; 20], [u8; 32])> {
    // 解析助记词
    let bip39_mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, mnemonic_str)
        .map_err(|e| anyhow::anyhow!("解析助记词失败: {}", e))?;
    
    // 生成种子
    let seed = bip39_mnemonic.to_seed("");
    
    // 创建主密钥
    let xprv = XPrv::new(&seed)
        .map_err(|e| anyhow::anyhow!("创建主密钥失败: {}", e))?;
    
    // 解析派生路径
    let child_xprv = derive_path(&xprv, path)?;
    
    // 获取最终私钥
    let private_key = child_xprv.private_key().to_bytes();
    
    // 生成公钥
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key)
        .map_err(|e| anyhow::anyhow!("无效的私钥: {}", e))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    // 生成地址
    let uncompressed = public_key.serialize_uncompressed();
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]); // 跳过 0x04 前缀
    let hash = hasher.finalize();
    
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    
    Ok((address, private_key))
}

/// 从助记词生成以太坊地址 (使用 rust_profanity 的 Mnemonic)
/// 
/// # Arguments
/// * `mnemonic_str` - BIP39 助记词字符串
///
/// # Returns
/// 返回以太坊地址 (20字节)
pub fn generate_address_with_rust_profanity(mnemonic_str: &str) -> anyhow::Result<[u8; 20]> {
    let mnemonic = Mnemonic::from_string(mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    
    // 生成主密钥
    let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
        .map_err(|e| anyhow::anyhow!("HMAC 初始化失败: {}", e))?;
    mac.update(&seed);
    let master_key = mac.finalize().into_bytes();
    
    // 派生路径 m/44'/60'/0'/0/0
    let path = [0x8000002Cu32, 0x8000003C, 0x80000000, 0x00000000, 0x00000000];
    let mut current_key = master_key.to_vec();
    
    for &index in &path {
        let parent_private = &current_key[..32];
        let parent_chain = &current_key[32..];
        
        let mut data = vec![0u8; 37];
        if index >= 0x80000000 {
            data[0] = 0x00;
            data[1..33].copy_from_slice(parent_private);
        }
        data[33..37].copy_from_slice(&index.to_be_bytes());
        
        let mut mac = Hmac::<Sha512>::new_from_slice(parent_chain)
            .map_err(|e| anyhow::anyhow!("HMAC 初始化失败: {}", e))?;
        mac.update(&data);
        let hmac_result = mac.finalize().into_bytes();
        
        let left_hmac = &hmac_result[..32];
        let mut child_private = [0u8; 32];
        
        let mut carry = 0u16;
        for j in (0..32).rev() {
            let sum = parent_private[j] as u16 + left_hmac[j] as u16 + carry;
            child_private[j] = sum as u8;
            carry = sum >> 8;
        }
        
        current_key[..32].copy_from_slice(&child_private);
        current_key[32..].copy_from_slice(&hmac_result[32..]);
    }
    
    // 生成公钥和地址
    let final_private_key = &current_key[..32];
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(final_private_key)
        .map_err(|e| anyhow::anyhow!("无效的私钥: {}", e))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    let uncompressed = public_key.serialize_uncompressed();
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]);
    let hash = hasher.finalize();
    
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    
    Ok(address)
}

/// 解析派生路径并派生子密钥
fn derive_path(xprv: &XPrv, path: &str) -> anyhow::Result<XPrv> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() || parts[0] != "m" {
        anyhow::bail!("Invalid derivation path: must start with 'm'");
    }
    
    let mut current = xprv.clone();
    
    for part in &parts[1..] {
        let (index, hardened) = if part.ends_with('\'') {
            let num: u32 = part[..part.len()-1].parse()
                .map_err(|e| anyhow::anyhow!("Invalid path component: {}", e))?;
            (num + 0x80000000, true)
        } else {
            let num: u32 = part.parse()
                .map_err(|e| anyhow::anyhow!("Invalid path component: {}", e))?;
            (num, false)
        };
        
        current = current.derive_child(
            bip32::ChildNumber::new(index & 0x7FFFFFFF, hardened)
                .map_err(|e| anyhow::anyhow!("派生失败: {}", e))?
        ).map_err(|e| anyhow::anyhow!("派生失败: {}", e))?;
    }
    
    Ok(current)
}

/// 打印 OpenCL 构建日志 (用于调试)
#[cfg(feature = "opencl_debug")]
pub fn print_opencl_build_logs(proque: &ocl::ProQue, label: &str) {
    use ocl::enums::{ProgramBuildInfo, ProgramBuildInfoResult};
    
    println!("========== OpenCL Build Logs: {} ==========", label);
    for device in proque.context().devices() {
        let device_name = device.name().unwrap_or_else(|_| String::from("<unknown>"));
        println!("--- Device: {} ---", device_name);

        match proque.program().build_info(device, ProgramBuildInfo::BuildStatus) {
            Ok(status) => println!("BuildStatus: {}", status),
            Err(e) => println!("BuildStatus 获取失败: {}", e),
        }

        match proque.program().build_info(device, ProgramBuildInfo::BuildOptions) {
            Ok(options) => println!("BuildOptions: {}", options),
            Err(e) => println!("BuildOptions 获取失败: {}", e),
        }

        match proque.program().build_info(device, ProgramBuildInfo::BuildLog) {
            Ok(ProgramBuildInfoResult::BuildLog(log)) => {
                if log.trim().is_empty() {
                    println!("BuildLog: <empty>");
                } else {
                    println!("BuildLog:\n{}", log);
                }
            }
            Ok(other) => println!("BuildLog 返回了非日志结果: {}", other),
            Err(e) => println!("BuildLog 获取失败: {}", e),
        }
    }
    println!("========== End OpenCL Build Logs ==========");
}
