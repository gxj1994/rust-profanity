# rust-profanity

GPU 以太坊靓号地址搜索系统 - Rust + OpenCL 实现

> ⚠️ **注意**: 本项目由 AI 辅助编写，仅供学习研究使用，生产环境请谨慎使用。

## 功能特性

- **GPU 加速**: 使用 OpenCL 在 GPU 上并行搜索以太坊靓号地址
- **多 GPU 并行**: 可选使用全部可用 GPU 并发搜索
- **多条件支持**: 支持前缀匹配、后缀匹配、前导零匹配
- **BIP39/BIP32**: 完整的助记词和密钥派生支持
- **跨平台**: 支持 macOS、Linux、Windows (需 OpenCL 运行时)

## 系统要求

- Rust 1.70+
- OpenCL 1.2+ 运行时
- GPU 设备 (Apple Silicon / NVIDIA / AMD / Intel)

### macOS

```bash
# 系统自带 OpenCL，无需额外安装
```

### Linux

```bash
# Ubuntu/Debian
sudo apt-get install ocl-icd-opencl-dev

# 安装 GPU 驱动
# NVIDIA: CUDA Toolkit
# AMD: ROCm 或 AMDGPU-PRO
# Intel: Intel OpenCL Runtime
```

## 编译安装

```bash
# 克隆仓库
git clone <repository-url>
cd rust-profanity

# 编译 Release 版本
cargo build --release

# 运行测试
cargo test
```

## 使用方法

### 前缀匹配

搜索以 `00` 开头的以太坊地址：

```bash
./target/release/rust-profanity --prefix 00 --threads 256 --timeout 60
```

### 直接私钥模式

跳过助记词推导，直接从随机私钥起点并行遍历（更快）：

```bash
./target/release/rust-profanity --prefix 00 --source-mode private-key --threads 256 --timeout 60
```

### 后缀匹配

搜索以 `dead` 结尾的以太坊地址：

```bash
./target/release/rust-profanity --suffix dead --threads 512 --timeout 120
```

### 前导零匹配

搜索有 4 个前导零的以太坊地址：

```bash
./target/release/rust-profanity --leading-zeros 4 --threads 1024 --timeout 300
```

### 模式匹配

搜索包含特定模式的以太坊地址（使用 `X`、`*` 或 `?` 作为通配符）：

```bash
# 搜索后缀为 "dead" 的地址
./target/release/rust-profanity --pattern 0xXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXdead --threads 1024 --timeout 60

# 搜索前缀为 "0000" 的地址
./target/release/rust-profanity --pattern 0x0000XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX --threads 1024 --timeout 60

# 搜索中间包含 "abcd" 的地址
./target/release/rust-profanity --pattern 0xXXXXXXXXXXXXabcdXXXXXXXXXXXXXXXXXXXXXXXX --threads 2048 --timeout 120

# 搜索多个特定位置
./target/release/rust-profanity --pattern 0x0XXX1XXXX2XXXXXXXXXXXXXXXXXXXXXXXXXXXX1X --threads 4096 --timeout 300
```

### 多 GPU 并行

自动使用全部可用 GPU，并将 `--threads` 总线程数按设备均分：

```bash
./target/release/rust-profanity --prefix 00 --threads 4096 --multi-gpu --timeout 60
```

### 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--prefix` | 地址前缀匹配 (十六进制) | - |
| `--suffix` | 地址后缀匹配 (十六进制) | - |
| `--leading-zeros` | 前导零个数 | - |
| `--pattern` | 完整地址模式匹配 (X/*/? 为通配符) | - |
| `--threads` | GPU 线程数 | 1024 |
| `--multi-gpu` | 启用多 GPU 并行（自动使用全部 GPU） | false |
| `--timeout` | 搜索超时时间 (秒) | 60 |
| `--work-group-size` | OpenCL 工作组大小 | 128 |
| `--source-mode` | 搜索来源模式: `mnemonic` / `private-key` | `mnemonic` |

## 输出示例

```
========================================
✓ 找到符合条件的地址!
========================================
以太坊地址: 0x00887efd8e34f6ba231543d385e0cd1e2b0441d9
助记词: chair tragic cereal hawk disagree portion hard route donate zone rebel army long once buyer table silver shadow balcony nature cruel youth cannon wage
找到线程: 20
搜索时间: 0.47 秒
========================================
```

## 性能调优

### 推荐线程数

| 设备 | 推荐线程数 |
|------|-----------|
| Apple M3 Max | 1024-4096 |
| NVIDIA RTX 4090 | 4096-8192 |
| AMD RX 7900 XTX | 2048-4096 |

### 调试日志

```bash
RUST_LOG=info ./target/release/rust-profanity --prefix 00 --threads 1024
```

## 项目结构

```
rust-profanity/
├── src/
│   ├── main.rs              # 程序入口
│   ├── lib.rs               # 库模块
│   ├── config.rs            # 配置和条件解析
│   ├── kernel_loader.rs     # OpenCL 内核源代码加载
│   ├── mnemonic.rs          # BIP39 助记词生成
│   ├── wordlist.rs          # BIP39 单词表 (2048词)
│   └── opencl/
│       ├── mod.rs           # OpenCL 模块
│       ├── context.rs       # 上下文管理
│       └── kernel.rs        # 内核加载与执行
├── kernels/
│   ├── search.cl            # 主搜索内核
│   ├── crypto/
│   │   ├── keccak.cl        # Keccak-256 哈希
│   │   ├── secp256k1.cl     # 椭圆曲线运算
│   │   ├── sha256.cl        # SHA256
│   │   ├── sha512.cl        # SHA512
│   │   └── pbkdf2.cl        # PBKDF2 密钥派生
│   ├── bip39/
│   │   ├── entropy.cl       # BIP39 熵处理
│   │   ├── mnemonic.cl      # BIP39/BIP32 实现
│   │   └── wordlist.cl      # BIP39 单词表
│   └── utils/
│       └── condition.cl     # 条件匹配
├── tests/                   # 测试代码
│   ├── mod.rs               # 测试模块入口
│   ├── common/              # 测试公共函数
│   │   └── mod.rs
│   ├── test_keccak.rs
│   ├── test_bip39.rs
│   ├── test_bip32.rs
│   ├── test_secp256k1.rs
│   └── test_condition.rs
└── Cargo.toml
```

## 技术实现

### 核心流程

```
CPU (Rust): 生成随机24词助记词作为种子
                ↓
OpenCL: 接收种子 + 搜索条件 + 线程配置
                ↓
GPU: 所有线程并行遍历助记词空间，生成地址并匹配条件
                ↓
GPU: 任一线程找到目标，原子操作设置全局标志并保存结果
                ↓
CPU (Rust): 轮询检测结果，输出找到的助记词和地址
```

### 密码学算法

- **BIP39**: 助记词生成、PBKDF2-HMAC-SHA512
- **BIP32**: 分层确定性钱包密钥派生
- **secp256k1**: 椭圆曲线数字签名算法
- **Keccak-256**: 以太坊地址哈希

## 测试

```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test test_keccak
cargo test test_bip39
cargo test test_secp256k1

# 显示详细输出
cargo test -- --nocapture
```

## 注意事项

1. **搜索难度**: 前缀每增加 1 个字符，搜索难度增加 16 倍
2. **安全性**: 生成的助记词是随机的，找到的结果应立即保存，不要共享
3. **仅用于学习和研究目的**

## 许可证

MIT License

## 致谢

- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - 助记词标准
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - 分层确定性钱包
- [OpenCL](https://www.khronos.org/opencl/) - GPU 并行计算框架
