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
static uchar mnemonic_to_string(const mnemonic_t* mnemonic, uchar* output, uchar max_len) {
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
static void mnemonic_to_seed(const mnemonic_t* mnemonic, seed_t* seed) {
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
static void hmac_sha512_bip32(const uchar* key, uint key_len, const uchar* data, uint data_len, uchar result[64]) {
    hmac_sha512(key, key_len, data, data_len, result);
}

// 从种子生成主密钥 (BIP32)
// 返回 64 字节: 前 32 字节是主私钥，后 32 字节是主链码
static void seed_to_master_key(const seed_t* seed, uchar master_key[64]) {
    const uchar key[] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
    hmac_sha512_bip32(key, 12, seed->bytes, 64, master_key);
}

// 从字节数组加载 uint256 (大端序 - BIP32标准)
static void uint256_from_bytes_mnemonic(const uchar bytes[32], ulong result[4]) {
    for (int i = 0; i < 4; i++) {
        result[3 - i] = ((ulong)bytes[i * 8] << 56) |
                       ((ulong)bytes[i * 8 + 1] << 48) |
                       ((ulong)bytes[i * 8 + 2] << 40) |
                       ((ulong)bytes[i * 8 + 3] << 32) |
                       ((ulong)bytes[i * 8 + 4] << 24) |
                       ((ulong)bytes[i * 8 + 5] << 16) |
                       ((ulong)bytes[i * 8 + 6] << 8) |
                       ((ulong)bytes[i * 8 + 7]);
    }
}

// 将 uint256 保存到字节数组 (大端序 - BIP32标准)
static void uint256_to_bytes_mnemonic(const ulong value[4], uchar bytes[32]) {
    for (int i = 0; i < 4; i++) {
        bytes[i * 8] = (uchar)(value[3 - i] >> 56);
        bytes[i * 8 + 1] = (uchar)(value[3 - i] >> 48);
        bytes[i * 8 + 2] = (uchar)(value[3 - i] >> 40);
        bytes[i * 8 + 3] = (uchar)(value[3 - i] >> 32);
        bytes[i * 8 + 4] = (uchar)(value[3 - i] >> 24);
        bytes[i * 8 + 5] = (uchar)(value[3 - i] >> 16);
        bytes[i * 8 + 6] = (uchar)(value[3 - i] >> 8);
        bytes[i * 8 + 7] = (uchar)(value[3 - i]);
    }
}

// 比较两个 uint256 (大端序 - 从最高有效位开始比较)
static int uint256_cmp_mnemonic(const ulong a[4], const ulong b[4]) {
    for (int i = 0; i < 4; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// secp256k1 阶 n (大端序 - 与 uint256_from_bytes_mnemonic 一致)
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
__constant ulong SECP256K1_N_MNEMONIC[4] = {
    0xFFFFFFFFFFFFFFFFULL,  // 最高 64 位
    0xFFFFFFFFFFFFFFFEULL,
    0xBAAEDCE6AF48A03BULL,
    0xBFD25E8CD0364141ULL   // 最低 64 位
};

// 模加: result = (a + b) mod n
static void mod_add_n_mnemonic(const ulong a[4], const ulong b[4], ulong result[4]) {
    ulong carry = 0;
    
    // 从最低有效位开始加法（索引 3）
    for (int i = 3; i >= 0; i--) {
        ulong sum = a[i] + b[i];
        ulong new_carry = (sum < a[i]) ? 1UL : 0UL;
        sum += carry;
        if (sum < carry) new_carry++;
        carry = new_carry;
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
        for (int i = 3; i >= 0; i--) {
            ulong diff = result[i] - n_local[i] - borrow;
            borrow = (result[i] < n_local[i] + borrow) ? 1UL : 0UL;
            result[i] = diff;
        }
    }
}

// 派生子密钥 (BIP32)
// parent_key: 64 字节 (32 字节私钥 + 32 字节链码)
// index: 派生索引 (>= 0x80000000 表示硬化派生)
// child_key: 输出 64 字节
static void derive_child_key(const uchar parent_key[64], uint index, uchar child_key[64]) {
    uchar data[37];
    
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
    uint256_from_bytes_mnemonic(parent_key, parent_priv);
    uint256_from_bytes_mnemonic(hmac_result, left_hmac);
    
    // 模加: child_priv = (parent_priv + left_hmac) mod n
    mod_add_n_mnemonic(parent_priv, left_hmac, child_priv);
    
    // 输出子私钥 (前32字节)
    uint256_to_bytes_mnemonic(child_priv, child_key);
    
    // 输出子链码 (后32字节) - 直接复制 HMAC 右半部分
    for (int i = 0; i < 32; i++) {
        child_key[32 + i] = hmac_result[32 + i];
    }
}

// 完整的派生路径
static void derive_path(const seed_t* seed, const uint* path, uint path_len, uchar private_key[32]) {
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
static void get_ethereum_private_key(const mnemonic_t* mnemonic, uchar private_key[32]) {
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
static void get_ethereum_private_key_local(const local_mnemonic_t* mnemonic, uchar private_key[32]) {
    mnemonic_t mn;
    for (int i = 0; i < 24; i++) {
        mn.words[i] = mnemonic->words[i];
    }
    get_ethereum_private_key(&mn, private_key);
}


