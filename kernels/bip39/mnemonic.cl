// BIP39 助记词处理 (OpenCL)
// 实现助记词到以太坊私钥的完整转换
// 依赖: sha512.cl、pbkdf2.cl、wordlist.cl

// 助记词结构
typedef struct {
    ushort words[24];
} mnemonic_t;

// 种子结构 (512位)
typedef struct {
    uchar bytes[64];
} seed_t;

// BIP32 派生路径: m/44'/60'/0'/0/0 (以太坊标准路径)
// 44' = 0x8000002C (BIP44)
// 60' = 0x8000003C (以太坊币种)
// 0'  = 0x80000000 (账户)
// 0   = 0x00000000 (外部链)
// 0   = 0x00000000 (地址索引)
__constant uint DERIVATION_PATH[5] = {
    0x8000002C,  // 44'
    0x8000003C,  // 60'
    0x80000000,  // 0'
    0x00000000,  // 0
    0x00000000   // 0
};

// 将助记词转换为标准BIP39字符串
// 单词之间用空格分隔
// 返回字符串长度
uchar mnemonic_to_string(const mnemonic_t* mnemonic, uchar* output, uchar max_len) {
    uchar pos = 0;
    
    for (int i = 0; i < 24; i++) {
        // 添加空格分隔符 (第一个单词前不加)
        if (i > 0) {
            if (pos >= max_len) return pos;
            output[pos++] = ' ';
        }
        
        // 复制单词
        ushort word_idx = mnemonic->words[i];
        uchar word_len = copy_word(word_idx, output + pos, max_len - pos);
        pos += word_len;
    }
    
    return pos;
}

// 助记词到种子 (BIP39 标准)
// 使用 PBKDF2-HMAC-SHA512
// password: 助记词字符串 (单词之间用空格分隔)
// salt: "mnemonic" + 可选密码
// 迭代次数: 2048
void mnemonic_to_seed(const mnemonic_t* mnemonic, seed_t* seed) {
    // 构建助记词字符串 (最大约 24 * 8 + 23 = 215 字节)
    uchar password[256];
    // 初始化数组以避免未定义行为
    for (int i = 0; i < 256; i++) {
        password[i] = 0;
    }
    uchar password_len = mnemonic_to_string(mnemonic, password, 255);
    
    // salt = "mnemonic"
    uchar salt[8] = {'m', 'n', 'e', 'm', 'o', 'n', 'i', 'c'};
    
    // PBKDF2-HMAC-SHA512, 2048 次迭代
    pbkdf2_hmac_sha512(password, password_len, salt, 8, 2048, seed->bytes, 64);
}

// HMAC-SHA512 用于 BIP32
void hmac_sha512_bip32(const uchar* key, uint key_len, const uchar* data, uint data_len, uchar result[64]) {
    hmac_sha512(key, key_len, data, data_len, result);
}

// 从种子生成主密钥 (BIP32)
// 返回 64 字节: 前 32 字节是主私钥，后 32 字节是主链码
void seed_to_master_key(const seed_t* seed, uchar master_key[64]) {
    const uchar key[] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
    hmac_sha512_bip32(key, 12, seed->bytes, 64, master_key);
}

// 从字节数组加载 uint256 (小端序)
// result[0] = 最低有效位(LSB), result[3] = 最高有效位(MSB)
// 字节数组是大端序：bytes[0..7] 是最高8字节，bytes[24..31] 是最低8字节
// 转换为小端序数组：result[3] 存储最高8字节，result[0] 存储最低8字节
void uint256_from_bytes_mnemonic(const uchar bytes[32], ulong result[4]) {
    // bytes[24..31] -> result[0] (最低8字节)
    result[0] = ((ulong)bytes[24] << 56) |
                ((ulong)bytes[25] << 48) |
                ((ulong)bytes[26] << 40) |
                ((ulong)bytes[27] << 32) |
                ((ulong)bytes[28] << 24) |
                ((ulong)bytes[29] << 16) |
                ((ulong)bytes[30] << 8) |
                ((ulong)bytes[31]);
    
    // bytes[16..23] -> result[1]
    result[1] = ((ulong)bytes[16] << 56) |
                ((ulong)bytes[17] << 48) |
                ((ulong)bytes[18] << 40) |
                ((ulong)bytes[19] << 32) |
                ((ulong)bytes[20] << 24) |
                ((ulong)bytes[21] << 16) |
                ((ulong)bytes[22] << 8) |
                ((ulong)bytes[23]);
    
    // bytes[8..15] -> result[2]
    result[2] = ((ulong)bytes[8] << 56) |
                ((ulong)bytes[9] << 48) |
                ((ulong)bytes[10] << 40) |
                ((ulong)bytes[11] << 32) |
                ((ulong)bytes[12] << 24) |
                ((ulong)bytes[13] << 16) |
                ((ulong)bytes[14] << 8) |
                ((ulong)bytes[15]);
    
    // bytes[0..7] -> result[3] (最高8字节)
    result[3] = ((ulong)bytes[0] << 56) |
                ((ulong)bytes[1] << 48) |
                ((ulong)bytes[2] << 40) |
                ((ulong)bytes[3] << 32) |
                ((ulong)bytes[4] << 24) |
                ((ulong)bytes[5] << 16) |
                ((ulong)bytes[6] << 8) |
                ((ulong)bytes[7]);
}

// 将 uint256 保存到字节数组 (小端序数组转大端序字节)
// value[0] = 最低有效位(LSB), value[3] = 最高有效位(MSB)
// value[3] 是最高有效位，对应字节数组的 bytes[0..7]
// value[0] 是最低有效位，对应字节数组的 bytes[24..31]
void uint256_to_bytes_mnemonic(const ulong value[4], uchar bytes[32]) {
    // value[3] (最高8字节) -> bytes[0..7]
    bytes[0] = (uchar)(value[3] >> 56);
    bytes[1] = (uchar)(value[3] >> 48);
    bytes[2] = (uchar)(value[3] >> 40);
    bytes[3] = (uchar)(value[3] >> 32);
    bytes[4] = (uchar)(value[3] >> 24);
    bytes[5] = (uchar)(value[3] >> 16);
    bytes[6] = (uchar)(value[3] >> 8);
    bytes[7] = (uchar)(value[3]);
    
    // value[2] -> bytes[8..15]
    bytes[8] = (uchar)(value[2] >> 56);
    bytes[9] = (uchar)(value[2] >> 48);
    bytes[10] = (uchar)(value[2] >> 40);
    bytes[11] = (uchar)(value[2] >> 32);
    bytes[12] = (uchar)(value[2] >> 24);
    bytes[13] = (uchar)(value[2] >> 16);
    bytes[14] = (uchar)(value[2] >> 8);
    bytes[15] = (uchar)(value[2]);
    
    // value[1] -> bytes[16..23]
    bytes[16] = (uchar)(value[1] >> 56);
    bytes[17] = (uchar)(value[1] >> 48);
    bytes[18] = (uchar)(value[1] >> 40);
    bytes[19] = (uchar)(value[1] >> 32);
    bytes[20] = (uchar)(value[1] >> 24);
    bytes[21] = (uchar)(value[1] >> 16);
    bytes[22] = (uchar)(value[1] >> 8);
    bytes[23] = (uchar)(value[1]);
    
    // value[0] (最低8字节) -> bytes[24..31]
    bytes[24] = (uchar)(value[0] >> 56);
    bytes[25] = (uchar)(value[0] >> 48);
    bytes[26] = (uchar)(value[0] >> 40);
    bytes[27] = (uchar)(value[0] >> 32);
    bytes[28] = (uchar)(value[0] >> 24);
    bytes[29] = (uchar)(value[0] >> 16);
    bytes[30] = (uchar)(value[0] >> 8);
    bytes[31] = (uchar)(value[0]);
}

// 比较两个 uint256 (小端序 - 从最高有效位开始比较)
// a[0], b[0] = 最低有效位, a[3], b[3] = 最高有效位
int uint256_cmp_mnemonic(const ulong a[4], const ulong b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// secp256k1 阶 n (小端序 - 与 uint256_from_bytes_mnemonic 一致)
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
__constant ulong SECP256K1_N_MNEMONIC[4] = {
    0xBFD25E8CD0364141ULL,  // 最低 64 位 (索引 0)
    0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL   // 最高 64 位 (索引 3)
};

// 模加: result = (a + b) mod n
// 注意: a, b, result 都是小端序，索引 0 是最低有效位(LSB)，索引 3 是最高有效位(MSB)
void mod_add_n_mnemonic(const ulong a[4], const ulong b[4], ulong result[4]) {
    ulong carry = 0;
    
    // 从最低有效位开始加法（索引 0）
    for (int i = 0; i < 4; i++) {
        // 分两步进行加法以正确检测进位
        // 第一步: a[i] + b[i]
        ulong temp_sum = a[i] + b[i];
        ulong carry1 = (temp_sum < a[i]) ? 1UL : 0UL;  // 检测 a[i] + b[i] 是否溢出
        
        // 第二步: temp_sum + carry
        ulong sum = temp_sum + carry;
        ulong carry2 = (sum < temp_sum) ? 1UL : 0UL;  // 检测 temp_sum + carry 是否溢出
        
        carry = carry1 + carry2;
        result[i] = sum;
    }
    
    // 如果结果 >= n，减去 n
    // 将 __constant 数据复制到局部变量进行比较
    ulong n_local[4];
    for (int i = 0; i < 4; i++) {
        n_local[i] = SECP256K1_N_MNEMONIC[i];
    }
    
    if (carry || uint256_cmp_mnemonic(result, n_local) >= 0) {
        ulong borrow = 0;
        for (int i = 0; i < 4; i++) {
            ulong diff = result[i] - n_local[i] - borrow;
            // 检查是否需要借位
            // 如果 result[i] < n_local[i]，肯定需要借位
            // 如果 result[i] == n_local[i] 且 borrow == 1，也需要借位
            borrow = (result[i] < n_local[i] || (result[i] == n_local[i] && borrow == 1)) ? 1UL : 0UL;
            result[i] = diff;
        }
    }
}

// 派生子密钥 (BIP32)
// parent_key: 64 字节 (32 字节私钥 + 32 字节链码)
// index: 派生索引 (>= 0x80000000 表示硬化派生)
// child_key: 输出 64 字节
void derive_child_key(const uchar parent_key[64], uint index, uchar child_key[64]) {
    // 初始化 data 数组，避免未定义行为
    uchar data[37] = {0};
    
    if (index >= 0x80000000) {
        // 硬化派生: 使用 0x00 || 父私钥 || 索引
        data[0] = 0x00;
        for (int i = 0; i < 32; i++) {
            data[i + 1] = parent_key[i];  // 父私钥
        }
    } else {
        // 普通派生: 使用 压缩父公钥 || 索引
        // 需要先计算父公钥
        uchar parent_public[65];
        private_to_public(parent_key, parent_public);
        
        // BIP32普通派生使用33字节压缩公钥
        // 格式: 0x02(偶数Y) 或 0x03(奇数Y) + X坐标(32字节)
        // 从完整公钥中提取Y的最低位来判断奇偶
        uchar y_lsb = parent_public[64];  // Y坐标的最后一个字节
        data[0] = (y_lsb & 1) ? 0x03 : 0x02;  // 奇数Y用0x03，偶数Y用0x02
        
        // 复制X坐标 (32字节)
        for (int i = 0; i < 32; i++) {
            data[i + 1] = parent_public[i + 1];  // 跳过0x04前缀
        }
    }
    
    // 添加索引 (大端序)
    data[33] = (uchar)(index >> 24);
    data[34] = (uchar)(index >> 16);
    data[35] = (uchar)(index >> 8);
    data[36] = (uchar)index;
    
    // HMAC-SHA512
    uchar hmac_result[64];
    hmac_sha512_bip32(parent_key + 32, 32, data, 37, hmac_result);
    
    // 正确的 BIP32 子私钥计算:
    // child_private_key = (parent_private_key + left_32_hmac) mod n
    // child_chain_code = right_32_hmac
    
    ulong parent_priv[4], left_hmac[4], child_priv[4];
    uint256_from_bytes_mnemonic(parent_key, parent_priv);  // parent_key 前32字节是私钥
    uint256_from_bytes_mnemonic(hmac_result, left_hmac);    // hmac_result 前32字节是左半部分
    
    // BIP32 IL 有效性检查: 如果 left_hmac >= n 或 left_hmac == 0，则当前索引无效
    // 概率极低，但严格实现应添加检查
    ulong zero[4] = {0, 0, 0, 0};
    ulong n_local[4];
    for (int i = 0; i < 4; i++) {
        n_local[i] = SECP256K1_N_MNEMONIC[i];
    }
    if (uint256_cmp_mnemonic(left_hmac, zero) == 0 ||
        uint256_cmp_mnemonic(left_hmac, n_local) >= 0) {
        // IL 无效，置零子私钥（实际应处理重试或返回错误标志）
        for (int i = 0; i < 32; i++) {
            child_key[i] = 0;
        }
    } else {
        // 模加: child_priv = (parent_priv + left_hmac) mod n
        mod_add_n_mnemonic(parent_priv, left_hmac, child_priv);
        
        // 输出子私钥 (前32字节)
        uint256_to_bytes_mnemonic(child_priv, child_key);
    }
    
    // 输出子链码 (后32字节) - 直接复制 HMAC 右半部分
    for (int i = 0; i < 32; i++) {
        child_key[32 + i] = hmac_result[32 + i];
    }
}

// 完整的派生路径
void derive_path(const seed_t* seed, const uint* path, uint path_len, uchar private_key[32]) {
    uchar master_key[64];
    seed_to_master_key(seed, master_key);
    
    uchar current_key[64];
    for (int i = 0; i < 64; i++) {
        current_key[i] = master_key[i];
    }
    
    for (uint i = 0; i < path_len; i++) {
        derive_child_key(current_key, path[i], current_key);
    }
    
    // 取前32字节作为私钥
    for (int i = 0; i < 32; i++) {
        private_key[i] = current_key[i];
    }
}

// 获取以太坊私钥 (标准派生路径 m/44'/60'/0'/0/0)
void get_ethereum_private_key(const mnemonic_t* mnemonic, uchar private_key[32]) {
    seed_t seed;
    mnemonic_to_seed(mnemonic, &seed);
    
    // 复制派生路径到局部变量
    uint path[5];
    for (int i = 0; i < 5; i++) {
        path[i] = DERIVATION_PATH[i];
    }
    
    derive_path(&seed, path, 5, private_key);
}

// 兼容接口: local_mnemonic_t 类型在 search.cl 中定义
void get_ethereum_private_key_local(const local_mnemonic_t* mnemonic, uchar private_key[32]) {
    mnemonic_t mn;
    for (int i = 0; i < 24; i++) {
        mn.words[i] = mnemonic->words[i];
    }
    get_ethereum_private_key(&mn, private_key);
}


