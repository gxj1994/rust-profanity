// GPU以太坊靓号地址搜索系统 - OpenCL内核
// Rust + OpenCL 实现
//
// 注意: 所有依赖文件已由 main.rs 手动合并
// 不要在此文件中添加 #include 语句

// 搜索配置结构 (与Rust端对应)
// 注意：使用基本类型数组而不是嵌套结构体，避免OpenCL兼容性问题
typedef struct {
    ushort base_mnemonic_words[24];  // 基础助记词单词索引
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

// 函数前置声明 (在 mnemonic.cl 中实现)
void get_ethereum_private_key_local(const local_mnemonic_t* mnemonic, uchar private_key[32]);

// 助记词遍历 - 按步长递增
// 返回 false 表示遍历完成 (溢出)
bool next_mnemonic(local_mnemonic_t* mn, uint step) {
    uint carry = step;
    
    // 从最后一位开始进位
    for (int i = 23; i >= 0 && carry > 0; i--) {
        uint sum = (uint)mn->words[i] + carry;
        mn->words[i] = (ushort)(sum % 2048);
        carry = sum / 2048;
    }
    
    // 如果还有进位，说明遍历完成
    return (carry == 0);
}

// 完整的以太坊地址生成函数
// 流程: 助记词 -> 种子 -> 私钥 -> 公钥 -> Keccak-256 -> 地址
void derive_address(const local_mnemonic_t* mn, uchar address[20]) {
    // 1. 助记词 -> 私钥 (BIP39 + BIP32)
    uchar private_key[32];
    get_ethereum_private_key_local(mn, private_key);
    
    // 2. 私钥 -> 公钥 (secp256k1)
    uchar public_key[65];
    private_to_public(private_key, public_key);
    
    // 3. 公钥 -> Keccak-256 哈希 (跳过 0x04 前缀)
    uchar hash[32];
    keccak256(public_key + 1, 64, hash);
    
    // 4. 取后 20 字节作为以太坊地址
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
    
    // 复制基础助记词到本地内存
    local_mnemonic_t local_mn;
    for (int i = 0; i < 24; i++) {
        local_mn.words[i] = config->base_mnemonic_words[i];
    }
    
    // 设置本线程的起始偏移
    // 注意：使用 next_mnemonic 来正确设置偏移，避免模运算导致的冲突
    // 每个线程从 tid 步进开始，步长为 num_threads
    if (tid > 0) {
        // 从基础助记词开始，步进 tid 次
        for (uint i = 0; i < tid; i++) {
            if (!next_mnemonic(&local_mn, 1)) {
                // 溢出，此线程没有搜索空间
                return;
            }
        }
    }
    
    uint counter = 0;
    
    while (!(*g_found_flag)) {
        // 生成以太坊地址
        uchar address[20];
        derive_address(&local_mn, address);
        
        // 检查条件
        if (check_condition(address, config->condition)) {
            // 原子操作尝试设置标志
            int old_val = atomic_cmpxchg(g_found_flag, 0, 1);
            if (old_val == 0) {
                // 保存结果
                result->found = 1;
                for (int i = 0; i < 24; i++) {
                    result->result_mnemonic_words[i] = local_mn.words[i];
                }
                for (int i = 0; i < 20; i++) {
                    result->eth_address[i] = address[i];
                }
                result->found_by_thread = tid;
            }
            break;
        }
        
        // 遍历到下一个组合
        if (!next_mnemonic(&local_mn, config->num_threads)) {
            break;  // 本线程搜索空间耗尽
        }
        
        // 定期检测全局标志
        if ((++counter & (config->check_interval - 1)) == 0) {
            if (*g_found_flag) break;
        }
    }
}
