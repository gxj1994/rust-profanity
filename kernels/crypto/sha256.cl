// SHA-256 哈希实现 (OpenCL)

#ifndef SHA256_CL
#define SHA256_CL

// SHA-256 初始哈希值
__constant uint SHA256_H[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// SHA-256 常量 K
__constant uint SHA256_K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

// 右旋
uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

// Ch 函数
uint ch(uint x, uint y, uint z) {
    return (x & y) ^ (~x & z);
}

// Maj 函数
uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// Sigma0 函数
uint sigma0(uint x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

// Sigma1 函数
uint sigma1(uint x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

// gamma0 函数
uint gamma0(uint x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

// gamma1 函数
uint gamma1(uint x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA-256 压缩函数
void sha256_compress(uint state[8], const uchar block[64]) {
    uint W[64];
    uint a, b, c, d, e, f, g, h;
    uint T1, T2;
    
    // 准备消息调度 - 使用 vload4 优化大端序加载
    // 注意: vload4 按小端序解释数据，需要字节交换
    for (uint i = 0; i < 16; i++) {
        W[i] = as_uint(rotate(vload4(i, block).s3210, (uint4)0));
    }
    
    for (uint i = 16; i < 64; i++) {
        W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
    }
    
    // 初始化工作变量
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    
    // 主循环
    for (uint i = 0; i < 64; i++) {
        T1 = h + sigma1(e) + ch(e, f, g) + SHA256_K[i] + W[i];
        T2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    
    // 更新哈希值
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// SHA-256 哈希函数
void sha256(const uchar* data, uint len, uchar hash[32]) {
    uint state[8];
    for (uint i = 0; i < 8; i++) {
        state[i] = SHA256_H[i];
    }
    
    // 处理完整块
    uint i = 0;
    while (i + 64 <= len) {
        sha256_compress(state, &data[i]);
        i += 64;
    }
    
    // 填充
    uchar block[64];
    // 初始化块
    for (uint j = 0; j < 64; j++) {
        block[j] = 0;
    }
    uint remaining = len - i;
    for (uint j = 0; j < remaining; j++) {
        block[j] = data[i + j];
    }
    block[remaining] = 0x80;
    
    // 计算消息长度（位）- 使用64位计算避免溢出
    ulong bit_len_64 = (ulong)len * 8ULL;
    
    if (remaining < 56) {
        // 单块填充
        for (uint j = remaining + 1; j < 56; j++) {
            block[j] = 0;
        }
        // 写入64位长度（大端序）
        block[56] = (uchar)(bit_len_64 >> 56);
        block[57] = (uchar)(bit_len_64 >> 48);
        block[58] = (uchar)(bit_len_64 >> 40);
        block[59] = (uchar)(bit_len_64 >> 32);
        block[60] = (uchar)(bit_len_64 >> 24);
        block[61] = (uchar)(bit_len_64 >> 16);
        block[62] = (uchar)(bit_len_64 >> 8);
        block[63] = (uchar)bit_len_64;
        sha256_compress(state, block);
    } else {
        // 双块填充
        for (uint j = remaining + 1; j < 64; j++) {
            block[j] = 0;
        }
        sha256_compress(state, block);
        
        for (uint j = 0; j < 56; j++) {
            block[j] = 0;
        }
        // 写入64位长度（大端序）
        block[56] = (uchar)(bit_len_64 >> 56);
        block[57] = (uchar)(bit_len_64 >> 48);
        block[58] = (uchar)(bit_len_64 >> 40);
        block[59] = (uchar)(bit_len_64 >> 32);
        block[60] = (uchar)(bit_len_64 >> 24);
        block[61] = (uchar)(bit_len_64 >> 16);
        block[62] = (uchar)(bit_len_64 >> 8);
        block[63] = (uchar)bit_len_64;
        sha256_compress(state, block);
    }
    
    // 输出哈希 - 使用 vstore4 优化大端序存储
    for (uint i = 0; i < 8; i++) {
        uint4 val = (uint4)(rotate(state[i], (uint)0));
        vstore4(as_uchar4(rotate(val, (uint4)0)).s3210, i, hash);
    }
}

// HMAC-SHA256
void hmac_sha256(const uchar* key, uint key_len, const uchar* data, uint data_len, uchar result[32]) {
    uchar ipad[64];
    uchar opad[64];
    uchar key_buf[64];
    
    // 如果密钥太长，先哈希
    if (key_len > 64) {
        sha256(key, key_len, key_buf);
        key_len = 32;
    } else {
        for (uint i = 0; i < key_len; i++) {
            key_buf[i] = key[i];
        }
    }
    
    // 清零剩余部分
    for (uint i = key_len; i < 64; i++) {
        key_buf[i] = 0;
    }
    
    // 准备 ipad 和 opad
    for (uint i = 0; i < 64; i++) {
        ipad[i] = key_buf[i] ^ 0x36;
        opad[i] = key_buf[i] ^ 0x5C;
    }
    
    // 内层哈希: SHA256(ipad || data)
    // 使用压缩函数直接处理，避免大数组
    uint state[8];
    for (uint i = 0; i < 8; i++) {
        state[i] = SHA256_H[i];
    }
    
    // 处理 ipad (64字节 = 1个块)
    sha256_compress(state, ipad);
    
    // 处理 data
    uint i = 0;
    while (i + 64 <= data_len) {
        sha256_compress(state, &data[i]);
        i += 64;
    }
    
    // 最后一块填充
    uchar block[64];
    uint remaining = data_len - i;
    for (uint j = 0; j < remaining; j++) {
        block[j] = data[i + j];
    }
    block[remaining] = 0x80;
    
    // 计算内层哈希总长度: ipad(64字节) + data(data_len字节)
    ulong inner_bit_len = (64ULL + (ulong)data_len) * 8ULL;
    
    if (remaining < 56) {
        for (uint j = remaining + 1; j < 56; j++) {
            block[j] = 0;
        }
        // 写入64位长度（大端序）
        block[56] = (uchar)(inner_bit_len >> 56);
        block[57] = (uchar)(inner_bit_len >> 48);
        block[58] = (uchar)(inner_bit_len >> 40);
        block[59] = (uchar)(inner_bit_len >> 32);
        block[60] = (uchar)(inner_bit_len >> 24);
        block[61] = (uchar)(inner_bit_len >> 16);
        block[62] = (uchar)(inner_bit_len >> 8);
        block[63] = (uchar)inner_bit_len;
        sha256_compress(state, block);
    } else {
        for (uint j = remaining + 1; j < 64; j++) {
            block[j] = 0;
        }
        sha256_compress(state, block);
        
        for (uint j = 0; j < 56; j++) {
            block[j] = 0;
        }
        // 写入64位长度（大端序）
        block[56] = (uchar)(inner_bit_len >> 56);
        block[57] = (uchar)(inner_bit_len >> 48);
        block[58] = (uchar)(inner_bit_len >> 40);
        block[59] = (uchar)(inner_bit_len >> 32);
        block[60] = (uchar)(inner_bit_len >> 24);
        block[61] = (uchar)(inner_bit_len >> 16);
        block[62] = (uchar)(inner_bit_len >> 8);
        block[63] = (uchar)inner_bit_len;
        sha256_compress(state, block);
    }
    
    uchar inner_hash[32];
    for (uint j = 0; j < 8; j++) {
        inner_hash[j * 4] = (uchar)(state[j] >> 24);
        inner_hash[j * 4 + 1] = (uchar)(state[j] >> 16);
        inner_hash[j * 4 + 2] = (uchar)(state[j] >> 8);
        inner_hash[j * 4 + 3] = (uchar)state[j];
    }
    
    // 外层哈希: SHA256(opad || inner_hash)
    for (uint j = 0; j < 8; j++) {
        state[j] = SHA256_H[j];
    }
    
    // 处理 opad (64字节 = 1个块)
    sha256_compress(state, opad);
    
    // 处理 inner_hash (32字节，需要填充)
    // 外层哈希总长度: opad(64字节) + inner_hash(32字节) = 96字节
    ulong outer_bit_len = (64ULL + 32ULL) * 8ULL;
    
    for (uint j = 0; j < 32; j++) {
        block[j] = inner_hash[j];
    }
    block[32] = 0x80;
    for (uint j = 33; j < 56; j++) {
        block[j] = 0;
    }
    // 写入64位长度（大端序）
    block[56] = (uchar)(outer_bit_len >> 56);
    block[57] = (uchar)(outer_bit_len >> 48);
    block[58] = (uchar)(outer_bit_len >> 40);
    block[59] = (uchar)(outer_bit_len >> 32);
    block[60] = (uchar)(outer_bit_len >> 24);
    block[61] = (uchar)(outer_bit_len >> 16);
    block[62] = (uchar)(outer_bit_len >> 8);
    block[63] = (uchar)outer_bit_len;
    sha256_compress(state, block);
    
    // 输出结果
    for (uint j = 0; j < 8; j++) {
        result[j * 4] = (uchar)(state[j] >> 24);
        result[j * 4 + 1] = (uchar)(state[j] >> 16);
        result[j * 4 + 2] = (uchar)(state[j] >> 8);
        result[j * 4 + 3] = (uchar)state[j];
    }
}

#endif // SHA256_CL
