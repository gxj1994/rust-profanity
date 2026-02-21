// GPU以太坊靓号地址搜索系统 - OpenCL内核
// Rust + OpenCL 实现
//
// 注意: 所有依赖文件已由 main.rs 手动合并
// 不要在此文件中添加 #include 语句

// 搜索配置结构 (与Rust端对应)
// Rust 布局: base_entropy[32] @0, num_threads @32, condition @40, check_interval @48, pattern_config @56
// 总大小: 96 bytes (包含填充)
// 注意：使用基本类型数组而不是嵌套结构体，避免OpenCL兼容性问题
typedef struct {
    uchar base_entropy[32];      // 基础熵 (256位)，而非助记词单词 - offset 0
    uint num_threads;            // offset 32
    uchar _padding1[4];          // 填充以对齐 condition 到 8 字节边界
    ulong condition;             // offset 40
    uint check_interval;         // offset 48
    uchar _padding2[4];          // 填充以对齐 pattern_config
    // pattern_config 展开 (offset 56)
    uchar pattern_mask[20];      // 掩码数组 - 哪些位需要匹配
    uchar pattern_value[20];     // 期望值数组 - 需要匹配的值
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
inline void get_ethereum_private_key_local(const local_mnemonic_t* mnemonic, uchar private_key[32]);
inline bool increment_entropy(uchar entropy[32], uint step);

// 从熵生成以太坊地址
// 流程: 熵 -> 助记词 -> 种子 -> 私钥 -> 公钥 -> Keccak-256 -> 地址
// 优化: entropy_to_mnemonic 逻辑已内联，减少函数调用开销
inline void derive_address_from_entropy(const uchar entropy[32], uchar address[20]) {
    // ===== 内联 entropy_to_mnemonic 开始 =====
    // 计算校验和: SHA256 的前 8 位 (256/32 = 8)
    // 使用单个 hash 缓冲区，减少私有内存占用
    uchar hash[32];
    sha256(entropy, 32, hash);
    uchar checksum_bits = hash[0]; // 取前8位
    
    // 直接写入 local_mnemonic_t，避免 words[24] 临时数组
    local_mnemonic_t mn;
    for (int i = 0; i < 24; i++) {
        int bit_offset = i * 11;
        int byte_idx = bit_offset >> 3;  // / 8
        int bit_shift = bit_offset & 7;  // % 8
        
        // 从 entropy(0..31) + checksum(32) 按需读取 3 字节窗口，避免 all_bits[33] 私有缓冲
        uchar b0 = (byte_idx < 32) ? entropy[byte_idx] : checksum_bits;
        uchar b1 = (byte_idx + 1 < 32) ? entropy[byte_idx + 1] : ((byte_idx + 1 == 32) ? checksum_bits : (uchar)0);
        uchar b2 = (byte_idx + 2 < 32) ? entropy[byte_idx + 2] : ((byte_idx + 2 == 32) ? checksum_bits : (uchar)0);
        uint val = ((uint)b0 << 24) | ((uint)b1 << 16) | ((uint)b2 << 8);
        
        // 提取 11 位 (从大端序)
        val = val << bit_shift;
        mn.words[i] = (ushort)((val >> 21) & 0x7FF);  // 21 = 32 - 11
    }
    // ===== 内联 entropy_to_mnemonic 结束 =====
    
    // 助记词 -> 私钥 (BIP39 + BIP32)
    uchar private_key[32];
    get_ethereum_private_key_local(&mn, private_key);
    
    // 私钥 -> 公钥 (secp256k1)
    uchar public_key[65];
    private_to_public(private_key, public_key);
    
    // 公钥 -> Keccak-256 哈希 (跳过 0x04 前缀)
    // 复用上面的 hash 缓冲区
    keccak256(public_key + 1, 64, hash);
    
    // 取后 20 字节作为以太坊地址（逐字节复制，避免未对齐读写）
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        address[i] = hash[12 + i];
    }
}

// 辅助函数：原子读取 32 位标志
inline int atomic_load_flag(__global int* flag) {
    return atomic_add(flag, 0);
}

// 主搜索内核
__kernel void search_kernel(
    __constant search_config_t* config,
    __global search_result_t* result,
    __global int* g_found_flag,
    __global ulong* thread_checked
) {
    uint tid = get_global_id(0);
    
    if (tid >= config->num_threads) return;

    // 默认计数清零，确保提前退出时不会读到垃圾值
    thread_checked[tid] = 0;
    
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
    
    // 本地标志：如果本线程找到结果，设置为 true
    bool local_found = false;
    
    // 使用原子操作读取标志，避免编译器优化
    int flag = atomic_load_flag(g_found_flag);
    while (!flag && !local_found) {
        // 增加本地计数器 (使用 64 位模拟)
        local_checked_low++;
        if (local_checked_low == 0) {
            local_checked_high++;
        }
        
        // 从熵生成以太坊地址 (自动包含正确的 BIP39 校验和)
        uchar address[20];
        derive_address_from_entropy(local_entropy, address);
        
        // 检查条件 (使用带模式匹配的版本)
        if (check_condition_with_pattern(address, config->condition, config->pattern_mask, config->pattern_value)) {
            // 原子操作尝试设置全局标志
            int old_val = atomic_cmpxchg(g_found_flag, 0, 1);
            if (old_val == 0) {
                result->found = 1;
                // 保存熵 (使用 uchar16 向量类型优化)
                // 注意：必须保存当前的 local_entropy，而不是原始的 base_entropy
                uchar16* result_entropy16 = (uchar16*)result->result_entropy;
                uchar16* src_entropy16 = (uchar16*)local_entropy;
                result_entropy16[0] = src_entropy16[0];
                result_entropy16[1] = src_entropy16[1];
                
                // 保存地址（逐字节复制，避免未对齐读写）
                #pragma unroll
                for (int i = 0; i < 20; i++) {
                    result->eth_address[i] = address[i];
                }
                
                result->found_by_thread = tid;
            }
            // 设置本地标志，让本线程退出循环
            local_found = true;
            break;
        }
        
        // 遍历到下一个熵值
        if (!increment_entropy(local_entropy, config->num_threads)) {
            break;  // 本线程搜索空间耗尽
        }
        
        // 每 2048 次循环检查一次全局标志
        // 使用位运算：counter & 2047 == 0 等价于 counter % 2048 == 0
        if ((++counter & 2047) == 0) {
            flag = atomic_load_flag(g_found_flag);
            if (flag) break;
        }
        
        // 不再周期性写全局统计，降低原子争用
    }
    
    // 每线程写回自己的最终计数，主机侧统一求和
    thread_checked[tid] = ((ulong)local_checked_high << 32) | local_checked_low;
}
