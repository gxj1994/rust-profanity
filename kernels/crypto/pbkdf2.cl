// PBKDF2 密钥派生 (OpenCL)

#ifndef PBKDF2_CL
#define PBKDF2_CL

// 注意：此头文件需要 sha512.cl
// PBKDF2-HMAC-SHA512 实现 (BIP39 标准)

// 单次 PBKDF2 块计算
void pbkdf2_hmac_sha512_block(
    const uchar* password, uint password_len,
    const uchar* salt, uint salt_len,
    uint iterations,
    uint block_num,
    uchar output[64]
) {
    // U_1 = HMAC-SHA512(Password, Salt || INT_32_BE(block_num))
    // 使用固定大小数组，避免大数组初始化开销
    uchar salt_block[128];  // BIP39 salt "mnemonic" (8字节) + 4 = 12 < 128
    
    // 直接复制 salt，不需要清零整个数组
    for (uint i = 0; i < salt_len; i++) {
        salt_block[i] = salt[i];
    }
    // 直接添加 block_num (大端序)
    salt_block[salt_len] = (uchar)(block_num >> 24);
    salt_block[salt_len + 1] = (uchar)(block_num >> 16);
    salt_block[salt_len + 2] = (uchar)(block_num >> 8);
    salt_block[salt_len + 3] = (uchar)block_num;
    
    uchar u[64];
    hmac_sha512(password, password_len, salt_block, salt_len + 4, u);
    
    // T = U_1 (直接复制到 output)
    for (uint i = 0; i < 64; i++) {
        output[i] = u[i];
    }
    
    // U_2 到 U_iterations
    for (uint iter = 1; iter < iterations; iter++) {
        // 直接使用 u 作为输入和输出，避免 prev_u 拷贝
        hmac_sha512(password, password_len, u, 64, u);
        
        // T ^= U_i
        for (uint i = 0; i < 64; i++) {
            output[i] ^= u[i];
        }
    }
}

// PBKDF2-HMAC-SHA512 (BIP39 标准: 2048 次迭代)
void pbkdf2_hmac_sha512(
    const uchar* password, uint password_len,
    const uchar* salt, uint salt_len,
    uint iterations,
    uchar* output, uint output_len
) {
    // BIP39 只需要 64 字节输出 (512位种子)
    // 所以只需要 1 个块
    if (output_len <= 64) {
        uchar block_result[64];
        pbkdf2_hmac_sha512_block(password, password_len, salt, salt_len, 
                                  iterations, 1, block_result);
        for (uint i = 0; i < output_len; i++) {
            output[i] = block_result[i];
        }
    } else {
        // 多块情况 (如果需要超过 64 字节)
        uint block_count = (output_len + 63) / 64;
        for (uint block = 1; block <= block_count; block++) {
            uchar block_result[64];
            pbkdf2_hmac_sha512_block(password, password_len, salt, salt_len,
                                      iterations, block, block_result);
            uint copy_len = min(64u, output_len - (block - 1) * 64);
            for (uint i = 0; i < copy_len; i++) {
                output[(block - 1) * 64 + i] = block_result[i];
            }
        }
    }
}

#endif // PBKDF2_CL
