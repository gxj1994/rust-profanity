// GPU以太坊靓号地址搜索系统 - OpenCL内核
// Rust + OpenCL 实现
//
// 注意: 所有依赖文件已由 main.rs 手动合并
// 不要在此文件中添加 #include 语句

// 搜索配置结构 (与Rust端对应)
// 注意：使用基本类型数组而不是嵌套结构体，避免OpenCL兼容性问题
typedef struct {
    uchar base_entropy[32];  // 基础熵 (256位)，而非助记词单词
    uint num_threads;
    ulong condition;
    uint check_interval;
} search_config_t;

// 搜索结果结构
typedef struct {
    int found;
    uchar result_entropy[32];  // 找到的熵 (32字节)，由 Rust 端转换为助记词
    uchar eth_address[20];
    uint found_by_thread;
    uint total_checked_low;    // 总共检查的地址数量 - 低32位
    uint total_checked_high;   // 总共检查的地址数量 - 高32位
} search_result_t;

// 本地助记词结构 (与 mnemonic.cl 中的定义保持一致)
typedef struct {
    ushort words[24];
} local_mnemonic_t;

// 函数前置声明
void get_ethereum_private_key_local(const local_mnemonic_t* mnemonic, uchar private_key[32]);
void entropy_to_mnemonic(const uchar entropy[32], ushort words[24]);
bool increment_entropy(uchar entropy[32], uint step);

// 从熵生成以太坊地址
// 流程: 熵 -> 助记词 -> 种子 -> 私钥 -> 公钥 -> Keccak-256 -> 地址
void derive_address_from_entropy(const uchar entropy[32], uchar address[20]) {
    // 1. 熵 -> 助记词 (符合 BIP39 标准，包含正确校验和)
    ushort words[24];
    entropy_to_mnemonic(entropy, words);
    
    // 2. 构建 local_mnemonic_t (使用 ulong 指针批量复制)
    local_mnemonic_t mn;
    // 24 * 2 = 48 bytes = 6 ulongs
    ulong* mn_words = (ulong*)mn.words;
    ulong* src_words = (ulong*)words;
    mn_words[0] = src_words[0]; mn_words[1] = src_words[1];
    mn_words[2] = src_words[2]; mn_words[3] = src_words[3];
    mn_words[4] = src_words[4]; mn_words[5] = src_words[5];
    
    // 3. 助记词 -> 私钥 (BIP39 + BIP32)
    uchar private_key[32];
    get_ethereum_private_key_local(&mn, private_key);
    
    // 4. 私钥 -> 公钥 (secp256k1)
    uchar public_key[65];
    private_to_public(private_key, public_key);
    
    // 5. 公钥 -> Keccak-256 哈希 (跳过 0x04 前缀)
    uchar hash[32];
    keccak256(public_key + 1, 64, hash);
    
    // 6. 取后 20 字节作为以太坊地址 (使用 ulong + uint 批量复制)
    *((ulong*)address) = *((ulong*)(hash + 12));
    *((ulong*)(address + 8)) = *((ulong*)(hash + 20));
    *((uint*)(address + 16)) = *((uint*)(hash + 28));
}

// 辅助函数：原子读取 32 位标志
inline int atomic_load_flag(__global int* flag) {
    return atomic_add(flag, 0);
}

// 辅助函数：原子累加 64 位计数器 (拆分为两个 32 位)
// 注意：此函数使用原子操作分别更新低32位和高32位
// 由于是两个独立的原子操作，计数可能不是完全精确的，但对于统计目的是足够的
inline void atom_add_64(__global uint* low, __global uint* high, ulong value) {
    uint low_val = (uint)value;
    uint high_val = (uint)(value >> 32);
    
    // 先更新低32位
    uint old_low = atom_add(low, low_val);
    
    // 如果低32位溢出，增加高32位
    // 注意：这里假设 value 不会导致多次溢出（即 value < 2^32）
    if (old_low > 0xFFFFFFFFU - low_val) {
        atom_add(high, 1);
    }
    
    // 添加高32位部分
    if (high_val > 0) {
        atom_add(high, high_val);
    }
}

// 主搜索内核
__kernel void search_kernel(
    __constant search_config_t* config,
    __global search_result_t* result,
    __global int* g_found_flag
) {
    uint tid = get_global_id(0);
    if (tid >= config->num_threads) return;
    
    // 复制基础熵到本地内存 (使用 uchar16 向量类型优化)
    uchar local_entropy[32];
    __constant uchar16* src16 = (__constant uchar16*)config->base_entropy;
    uchar16* dst16 = (uchar16*)local_entropy;
    dst16[0] = src16[0];
    dst16[1] = src16[1];
    
    // 设置本线程的起始偏移
    // 每个线程从 tid 步进开始，步长为 num_threads
    if (tid > 0) {
        if (!increment_entropy(local_entropy, tid)) {
            // 溢出，此线程没有搜索空间
            return;
        }
    }
    
    uint counter = 0;
    uint local_checked_low = 0;
    uint local_checked_high = 0;
    
    // 使用原子操作读取标志，避免编译器优化
    int flag = atomic_load_flag(g_found_flag);
    while (!flag) {
        // 增加本地计数器 (使用 64 位模拟)
        local_checked_low++;
        if (local_checked_low == 0) {
            local_checked_high++;
        }
        
        // 从熵生成以太坊地址 (自动包含正确的 BIP39 校验和)
        uchar address[20];
        derive_address_from_entropy(local_entropy, address);
        
        // 检查条件
        if (check_condition(address, config->condition)) {
            // 原子操作尝试设置标志
            int old_val = atomic_cmpxchg(g_found_flag, 0, 1);
            if (old_val == 0) {
                result->found = 1;
                // 保存熵 (使用 uchar16 向量类型优化)
                // 注意：必须保存当前的 local_entropy，而不是原始的 base_entropy
                uchar16* result_entropy16 = (uchar16*)result->result_entropy;
                uchar16* src_entropy16 = (uchar16*)local_entropy;
                result_entropy16[0] = src_entropy16[0];
                result_entropy16[1] = src_entropy16[1];
                
                // 保存地址 (使用 ulong + uint 批量复制)
                *((ulong*)result->eth_address) = *((ulong*)address);
                *((ulong*)(result->eth_address + 8)) = *((ulong*)(address + 8));
                *((uint*)(result->eth_address + 16)) = *((uint*)(address + 16));
                
                result->found_by_thread = tid;
            }
            break;
        }
        
        // 遍历到下一个熵值
        if (!increment_entropy(local_entropy, config->num_threads)) {
            break;  // 本线程搜索空间耗尽
        }
        
        // 定期检测全局标志并更新统计
        if ((++counter & (config->check_interval - 1)) == 0) {
            flag = atomic_load_flag(g_found_flag);
            if (flag) break;
            // 原子累加本线程检查的地址数 (64 位拆分)
            if (local_checked_low > 0 || local_checked_high > 0) {
                ulong local_checked = ((ulong)local_checked_high << 32) | local_checked_low;
                atom_add_64(&result->total_checked_low, &result->total_checked_high, local_checked);
                local_checked_low = 0;
                local_checked_high = 0;
            }
        }
    }
    
    // 最后累加剩余的计数
    if (local_checked_low > 0 || local_checked_high > 0) {
        ulong local_checked = ((ulong)local_checked_high << 32) | local_checked_low;
        atom_add_64(&result->total_checked_low, &result->total_checked_high, local_checked);
    }
}
