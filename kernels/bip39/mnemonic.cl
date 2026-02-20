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

// 从字节数组加载 mp_number (大端序字节 -> 小端序 mp_number)
// 使用 secp256k1.cl 中的 mp_from_bytes
void mp_from_bytes_mnemonic(const uchar bytes[32], mp_number* result) {
    mp_from_bytes(bytes, result);
}

// 将 mp_number 保存到字节数组 (小端序 mp_number -> 大端序字节)
// 使用 secp256k1.cl 中的 mp_to_bytes
void mp_to_bytes_mnemonic(const mp_number* value, uchar bytes[32]) {
    mp_to_bytes(value, bytes);
}

// secp256k1 阶 n (小端序 mp_number 格式)
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// 小端序: d[0] = 0xd0364141, d[1] = 0xbfd25e8c, d[2] = 0xaf48a03b, d[3] = 0xbaaedce6, 
//         d[4] = 0xfffffffe, d[5] = 0xffffffff, d[6] = 0xffffffff, d[7] = 0xffffffff
__constant mp_word SECP256K1_N_MNEMONIC[8] = {
    0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6,
    0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff
};

// 比较 mp_number 是否为零
int mp_is_zero_mnemonic(const mp_number* a) {
    return mp_is_zero(a);
}

// 比较 mp_number (从高位到低位比较)
int mp_cmp_mnemonic(const mp_number* a, const mp_number* b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return 1;
    }
    return 0;
}

// 模加: result = (a + b) mod n
// 使用 secp256k1.cl 中的 mp_mod_add，但需要针对 n 而不是 p
void mod_add_n_mnemonic(const mp_number* a, const mp_number* b, mp_number* result) {
    // 先执行普通加法
    mp_number temp_result;
    mp_word carry = 0;
    
    for (int i = 0; i < 8; i++) {
        mp_word sum = a->d[i] + b->d[i] + carry;
        carry = (sum < a->d[i]) ? 1 : 0;
        temp_result.d[i] = sum;
    }
    
    // 如果溢出或结果 >= n，需要减去 n
    mp_number n_local;
    for (int i = 0; i < 8; i++) {
        n_local.d[i] = SECP256K1_N_MNEMONIC[i];
    }
    
    // 使用正确的比较函数 (从高位到低位)
    int cmp_result = mp_cmp_mnemonic(&temp_result, &n_local);
    
    if (carry || cmp_result >= 0) {
        mp_word borrow = 0;
        for (int i = 0; i < 8; i++) {
            mp_word diff = temp_result.d[i] - n_local.d[i] - borrow;
            // 正确的借位检测
            if (borrow == 0) {
                borrow = (temp_result.d[i] < n_local.d[i]) ? 1 : 0;
            } else {
                borrow = (temp_result.d[i] <= n_local.d[i]) ? 1 : 0;
            }
            result->d[i] = diff;
        }
    } else {
        *result = temp_result;
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
    
    mp_number parent_priv, left_hmac, child_priv;
    mp_from_bytes_mnemonic(parent_key, &parent_priv);  // parent_key 前32字节是私钥
    mp_from_bytes_mnemonic(hmac_result, &left_hmac);    // hmac_result 前32字节是左半部分
    
    // BIP32 IL 有效性检查: 如果 left_hmac >= n 或 left_hmac == 0，则当前索引无效
    // 概率极低，但严格实现应添加检查
    mp_number zero = {{0, 0, 0, 0, 0, 0, 0, 0}};
    mp_number n_local;
    for (int i = 0; i < 8; i++) {
        n_local.d[i] = SECP256K1_N_MNEMONIC[i];
    }
    if (mp_cmp_mnemonic(&left_hmac, &zero) == 0 ||
        mp_cmp_mnemonic(&left_hmac, &n_local) >= 0) {
        // IL 无效，置零子私钥（实际应处理重试或返回错误标志）
        for (int i = 0; i < 32; i++) {
            child_key[i] = 0;
        }
    } else {
        // 模加: child_priv = (parent_priv + left_hmac) mod n
        mod_add_n_mnemonic(&parent_priv, &left_hmac, &child_priv);
        
        // 输出子私钥 (前32字节)
        mp_to_bytes_mnemonic(&child_priv, child_key);
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


