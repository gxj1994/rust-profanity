//! OpenCL 上下文管理

use ocl::{Context, Device, Platform, Queue};
use ocl::enums::DeviceInfo;
use log::info;

/// OpenCL 上下文结构
pub struct OpenCLContext {
    /// 选择的平台
    pub platform: Platform,
    /// 选择的设备 (GPU)
    pub device: Device,
    /// OpenCL 上下文
    pub context: Context,
    /// 命令队列
    pub queue: Queue,
}

impl OpenCLContext {
    /// 创建新的 OpenCL 上下文
    /// 
    /// 自动选择最佳的 GPU 设备
    pub fn new() -> anyhow::Result<Self> {
        // 获取所有平台
        let platforms = Platform::list();
        if platforms.is_empty() {
            anyhow::bail!("No OpenCL platforms found");
        }
        
        info!("Found {} OpenCL platform(s)", platforms.len());
        
        // 选择第一个有 GPU 设备的平台
        let mut selected_platform = None;
        let mut selected_device = None;
        
        for platform in &platforms {
            let devices = Device::list_all(platform)?;
            info!("Platform: {:?}, Devices: {}", platform.name(), devices.len());
            
            // 优先选择 GPU 设备
            for device in devices {
                let device_name = device.name()?;
                
                // 使用 OpenCL API 查询设备类型
                let device_type = device.info(DeviceInfo::Type).ok()
                    .and_then(|t| t.to_string().parse::<u64>().ok())
                    .map(|t| match t {
                        4 => "GPU",
                        2 => "CPU",
                        8 => "ACCELERATOR",
                        _ => "OTHER",
                    })
                    .unwrap_or("UNKNOWN");
                
                info!("  Device: {} (Type: {})", device_name, device_type);
                
                // 检测是否为 GPU (优先使用 API 查询，回退到名称判断)
                let is_gpu = device_type == "GPU" || {
                    let name_lower = device_name.to_lowercase();
                    name_lower.contains("gpu")
                        || name_lower.contains("graphics")
                        || name_lower.contains("nvidia")
                        || name_lower.contains("amd")
                        || name_lower.contains("radeon")
                };
                
                if is_gpu {
                    selected_platform = Some(*platform);
                    selected_device = Some(device);
                    break;
                }
            }
            
            if selected_device.is_some() {
                break;
            }
        }
        
        // 如果没有找到 GPU，使用第一个可用设备
        let (platform, device) = if let (Some(p), Some(d)) = (selected_platform, selected_device) {
            info!("Selected GPU device");
            (p, d)
        } else {
            info!("No GPU found, using first available device");
            let p = platforms[0];
            let devices = Device::list_all(p)?;
            if devices.is_empty() {
                anyhow::bail!("No OpenCL devices found");
            }
            (p, devices[0])
        };
        
        let device_name = device.name()?;
        info!("Using device: {}", device_name);
        
        // 创建上下文
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()?;
        
        // 创建命令队列
        let queue = Queue::new(&context, device, None)?;
        
        Ok(Self {
            platform,
            device,
            context,
            queue,
        })
    }
    
    /// 获取设备信息
    pub fn print_device_info(&self) -> anyhow::Result<()> {
        let name = self.device.name()?;
        let vendor = self.device.vendor()?;
        let version = self.device.version()?;
        
        info!("OpenCL Device Information:");
        info!("  Name: {}", name);
        info!("  Vendor: {}", vendor);
        info!("  Version: {}", version);
        info!("  (详细的设备信息查询在当前 OpenCL 版本中可能不可用)");
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = OpenCLContext::new();
        assert!(ctx.is_ok());
    }
}
