//! OpenCL 内核测试模块
//! 
//! 本模块包含对 GPU 以太坊靓号地址搜索系统 OpenCL 内核的测试。
//! 测试验证 OpenCL 实现与 Rust 标准实现的一致性。

pub mod test_keccak;
pub mod test_bip39;
pub mod test_bip32;
pub mod test_secp256k1;
pub mod test_condition;

/// 测试工具函数
pub mod utils {
    use ocl::ProQue;
    
    /// 检查 OpenCL 是否可用
    pub fn is_opencl_available() -> bool {
        ProQue::builder()
            .src("__kernel void test() {}")
            .dims(1)
            .build()
            .is_ok()
    }
    
    /// 获取 OpenCL 设备信息
    pub fn get_device_info() -> Option<String> {
        match ocl::Platform::list().first() {
            Some(platform) => {
                match ocl::Device::list_all(platform) {
                    Ok(devices) if !devices.is_empty() => {
                        let device = &devices[0];
                        Some(format!(
                            "Platform: {}, Device: {}",
                            platform.name().unwrap_or_default(),
                            device.name().unwrap_or_default()
                        ))
                    }
                    _ => None,
                }
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::utils;
    
    /// 测试 OpenCL 环境
    #[test]
    fn test_opencl_environment() {
        if let Some(info) = utils::get_device_info() {
            println!("OpenCL 设备信息: {}", info);
            // 只打印信息，不强制要求 OpenCL 可用
        } else {
            println!("警告: 未检测到 OpenCL 设备");
        }
    }
    
    /// 打印测试配置
    #[test]
    fn print_test_configuration() {
        println!("\n=== OpenCL 内核测试配置 ===");
        println!("测试模块:");
        println!("  - test_keccak: Keccak-256 哈希测试");
        println!("  - test_bip39: BIP39 助记词测试");
        println!("  - test_bip32: BIP32 密钥派生测试");
        println!("  - test_secp256k1: secp256k1 椭圆曲线测试");
        println!("  - test_condition: 条件匹配测试");
        
        if let Some(info) = utils::get_device_info() {
            println!("\nOpenCL 设备: {}", info);
        } else {
            println!("\nOpenCL 设备: 未检测到");
        }
        println!("===========================\n");
    }
}
