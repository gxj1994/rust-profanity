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
    ushort result_mnemonic_words[24];  // 找到的助记词单词索引
    uchar eth_address[20];
    uint found_by_thread;
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
    
    // 2. 构建 local_mnemonic_t
    local_mnemonic_t mn;
    for (int i = 0; i < 24; i++) {
        mn.words[i] = words[i];
    }
    
    // 3. 助记词 -> 私钥 (BIP39 + BIP32)
    uchar private_key[32];
    get_ethereum_private_key_local(&mn, private_key);
    
    // 4. 私钥 -> 公钥 (secp256k1)
    uchar public_key[65];
    private_to_public(private_key, public_key);
    
    // 5. 公钥 -> Keccak-256 哈希 (跳过 0x04 前缀)
    uchar hash[32];
    keccak256(public_key + 1, 64, hash);
    
    // 6. 取后 20 字节作为以太坊地址
    for (int i = 0; i < 20; i++) {
        address[i] = hash[i + 12];
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
    
    // 复制基础熵到本地内存
    uchar local_entropy[32];
    for (int i = 0; i < 32; i++) {
        local_entropy[i] = config->base_entropy[i];
    }
    
    // 设置本线程的起始偏移
    // 每个线程从 tid 步进开始，步长为 num_threads
    if (tid > 0) {
        if (!increment_entropy(local_entropy, tid)) {
            // 溢出，此线程没有搜索空间
            return;
        }
    }
    
    uint counter = 0;
    
    while (!(*g_found_flag)) {
        // 从熵生成以太坊地址 (自动包含正确的 BIP39 校验和)
        uchar address[20];
        derive_address_from_entropy(local_entropy, address);
        
        // 检查条件
        if (check_condition(address, config->condition)) {
            // 原子操作尝试设置标志
            int old_val = atomic_cmpxchg(g_found_flag, 0, 1);
            if (old_val == 0) {
                // 保存结果 - 从熵重新生成助记词
                ushort words[24];
                entropy_to_mnemonic(local_entropy, words);
                
                result->found = 1;
                for (int i = 0; i < 24; i++) {
                    result->result_mnemonic_words[i] = words[i];
                }
                for (int i = 0; i < 20; i++) {
                    result->eth_address[i] = address[i];
                }
                result->found_by_thread = tid;
            }
            break;
        }
        
        // 遍历到下一个熵值
        if (!increment_entropy(local_entropy, config->num_threads)) {
            break;  // 本线程搜索空间耗尽
        }
        
        // 定期检测全局标志
        if ((++counter & (config->check_interval - 1)) == 0) {
            if (*g_found_flag) break;
        }
    }
}
