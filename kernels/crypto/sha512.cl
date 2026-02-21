// SHA-512 哈希实现 (OpenCL)
// 用于 BIP39 PBKDF2-HMAC-SHA512

#ifndef SHA512_CL
#define SHA512_CL

// SHA-512 初始哈希值
__constant ulong SHA512_H[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

// SHA-512 常量 K
__constant ulong SHA512_K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL,
    0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL,
    0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL,
    0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
    0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL,
    0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL,
    0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
    0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL,
    0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL,
    0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
    0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL,
    0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL,
    0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
    0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL,
    0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL,
    0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
    0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL,
    0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL,
    0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
    0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

// 右旋64位
ulong rotr64(ulong x, uint n) {
    return (x >> n) | (x << (64 - n));
}

// Ch 函数
ulong ch64(ulong x, ulong y, ulong z) {
    return (x & y) ^ (~x & z);
}

// Maj 函数
ulong maj64(ulong x, ulong y, ulong z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// Sigma0 函数
ulong sigma0_64(ulong x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

// Sigma1 函数
ulong sigma1_64(ulong x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

// gamma0 函数
ulong gamma0_64(ulong x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

// gamma1 函数
ulong gamma1_64(ulong x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// SHA-512 压缩函数
void sha512_compress(ulong state[8], const uchar block[128]) {
    ulong W[80];
    ulong a, b, c, d, e, f, g, h;
    ulong T1, T2;
    
    // 准备消息调度 - 大端序加载
    for (uint i = 0; i < 16; i++) {
        uint offset = i * 8;
        W[i] = ((ulong)block[offset] << 56) |
               ((ulong)block[offset + 1] << 48) |
               ((ulong)block[offset + 2] << 40) |
               ((ulong)block[offset + 3] << 32) |
               ((ulong)block[offset + 4] << 24) |
               ((ulong)block[offset + 5] << 16) |
               ((ulong)block[offset + 6] << 8) |
               ((ulong)block[offset + 7]);
    }
    
    for (uint i = 16; i < 80; i++) {
        W[i] = gamma1_64(W[i - 2]) + W[i - 7] + gamma0_64(W[i - 15]) + W[i - 16];
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
    for (uint i = 0; i < 80; i++) {
        T1 = h + sigma1_64(e) + ch64(e, f, g) + SHA512_K[i] + W[i];
        T2 = sigma0_64(a) + maj64(a, b, c);
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

// SHA-512 哈希函数
void sha512(const uchar* data, uint len, uchar hash[64]) {
    ulong state[8];
    for (uint i = 0; i < 8; i++) {
        state[i] = SHA512_H[i];
    }
    
    // 处理完整块 (128字节)
    uint i = 0;
    while (i + 128 <= len) {
        sha512_compress(state, &data[i]);
        i += 128;
    }
    
    // 填充
    uchar block[128];
    uint remaining = len - i;
    for (uint j = 0; j < remaining; j++) {
        block[j] = data[i + j];
    }
    block[remaining] = 0x80;
    
    // 计算消息长度（位）- SHA-512使用128位长度字段
    ulong bit_len = (ulong)len * 8;
    
    if (remaining < 112) {
        // 单块填充
        for (uint j = remaining + 1; j < 112; j++) {
            block[j] = 0;
        }
        // 写入128位长度（大端序）- 高64位为0，低64位为bit_len
        for (uint j = 112; j < 120; j++) {
            block[j] = 0;
        }
        block[120] = (uchar)(bit_len >> 56);
        block[121] = (uchar)(bit_len >> 48);
        block[122] = (uchar)(bit_len >> 40);
        block[123] = (uchar)(bit_len >> 32);
        block[124] = (uchar)(bit_len >> 24);
        block[125] = (uchar)(bit_len >> 16);
        block[126] = (uchar)(bit_len >> 8);
        block[127] = (uchar)bit_len;
        sha512_compress(state, block);
    } else {
        // 双块填充
        for (uint j = remaining + 1; j < 128; j++) {
            block[j] = 0;
        }
        sha512_compress(state, block);
        
        for (uint j = 0; j < 112; j++) {
            block[j] = 0;
        }
        // 写入128位长度（大端序）- 高64位为0，低64位为bit_len
        for (uint j = 112; j < 120; j++) {
            block[j] = 0;
        }
        block[120] = (uchar)(bit_len >> 56);
        block[121] = (uchar)(bit_len >> 48);
        block[122] = (uchar)(bit_len >> 40);
        block[123] = (uchar)(bit_len >> 32);
        block[124] = (uchar)(bit_len >> 24);
        block[125] = (uchar)(bit_len >> 16);
        block[126] = (uchar)(bit_len >> 8);
        block[127] = (uchar)bit_len;
        sha512_compress(state, block);
    }
    
    // 输出哈希 - 大端序存储
    for (uint i = 0; i < 8; i++) {
        uint offset = i * 8;
        hash[offset] = (uchar)(state[i] >> 56);
        hash[offset + 1] = (uchar)(state[i] >> 48);
        hash[offset + 2] = (uchar)(state[i] >> 40);
        hash[offset + 3] = (uchar)(state[i] >> 32);
        hash[offset + 4] = (uchar)(state[i] >> 24);
        hash[offset + 5] = (uchar)(state[i] >> 16);
        hash[offset + 6] = (uchar)(state[i] >> 8);
        hash[offset + 7] = (uchar)state[i];
    }
}

// HMAC-SHA512
void hmac_sha512(const uchar* key, uint key_len, const uchar* data, uint data_len, uchar result[64]) {
    uchar ipad[128];
    uchar opad[128];
    uchar key_buf[128];
    
    // 初始化数组
    for (uint i = 0; i < 128; i++) {
        ipad[i] = 0;
        opad[i] = 0;
        key_buf[i] = 0;
    }
    
    // 如果密钥太长，先哈希
    if (key_len > 128) {
        sha512(key, key_len, key_buf);
        key_len = 64;
    } else {
        for (uint i = 0; i < key_len; i++) {
            key_buf[i] = key[i];
        }
    }
    
    // 清零剩余部分
    for (uint i = key_len; i < 128; i++) {
        key_buf[i] = 0;
    }
    
    // 准备 ipad 和 opad
    for (uint i = 0; i < 128; i++) {
        ipad[i] = key_buf[i] ^ 0x36;
        opad[i] = key_buf[i] ^ 0x5C;
    }
    
    // 内层哈希: SHA512(ipad || data)
    ulong state[8];
    for (uint i = 0; i < 8; i++) {
        state[i] = SHA512_H[i];
    }
    
    // 处理 ipad (128字节 = 1个块)
    sha512_compress(state, ipad);
    
    // 处理 data
    uint i = 0;
    while (i + 128 <= data_len) {
        sha512_compress(state, &data[i]);
        i += 128;
    }
    
    // 最后一块填充
    uchar block[128];
    uint remaining = data_len - i;
    for (uint j = 0; j < remaining; j++) {
        block[j] = data[i + j];
    }
    block[remaining] = 0x80;
    
    // 计算内层哈希总长度: ipad(128字节) + data(data_len字节)
    ulong inner_bit_len = (128ULL + (ulong)data_len) * 8ULL;
    
    if (remaining < 112) {
        for (uint j = remaining + 1; j < 112; j++) {
            block[j] = 0;
        }
        // 写入128位长度（大端序）- 高64位为0，低64位为bit_len
        for (uint j = 112; j < 120; j++) {
            block[j] = 0;
        }
        block[120] = (uchar)(inner_bit_len >> 56);
        block[121] = (uchar)(inner_bit_len >> 48);
        block[122] = (uchar)(inner_bit_len >> 40);
        block[123] = (uchar)(inner_bit_len >> 32);
        block[124] = (uchar)(inner_bit_len >> 24);
        block[125] = (uchar)(inner_bit_len >> 16);
        block[126] = (uchar)(inner_bit_len >> 8);
        block[127] = (uchar)inner_bit_len;
        sha512_compress(state, block);
    } else {
        for (uint j = remaining + 1; j < 128; j++) {
            block[j] = 0;
        }
        sha512_compress(state, block);
        
        for (uint j = 0; j < 112; j++) {
            block[j] = 0;
        }
        // 写入128位长度（大端序）- 高64位为0，低64位为bit_len
        for (uint j = 112; j < 120; j++) {
            block[j] = 0;
        }
        block[120] = (uchar)(inner_bit_len >> 56);
        block[121] = (uchar)(inner_bit_len >> 48);
        block[122] = (uchar)(inner_bit_len >> 40);
        block[123] = (uchar)(inner_bit_len >> 32);
        block[124] = (uchar)(inner_bit_len >> 24);
        block[125] = (uchar)(inner_bit_len >> 16);
        block[126] = (uchar)(inner_bit_len >> 8);
        block[127] = (uchar)inner_bit_len;
        sha512_compress(state, block);
    }
    
    uchar inner_hash[64];
    for (uint j = 0; j < 8; j++) {
        inner_hash[j * 8] = (uchar)(state[j] >> 56);
        inner_hash[j * 8 + 1] = (uchar)(state[j] >> 48);
        inner_hash[j * 8 + 2] = (uchar)(state[j] >> 40);
        inner_hash[j * 8 + 3] = (uchar)(state[j] >> 32);
        inner_hash[j * 8 + 4] = (uchar)(state[j] >> 24);
        inner_hash[j * 8 + 5] = (uchar)(state[j] >> 16);
        inner_hash[j * 8 + 6] = (uchar)(state[j] >> 8);
        inner_hash[j * 8 + 7] = (uchar)state[j];
    }
    
    // 外层哈希: SHA512(opad || inner_hash)
    for (uint j = 0; j < 8; j++) {
        state[j] = SHA512_H[j];
    }
    
    // 处理 opad (128字节 = 1个块)
    sha512_compress(state, opad);
    
    // 处理 inner_hash (64字节，需要填充)
    // 外层哈希总长度: opad(128字节) + inner_hash(64字节) = 192字节
    ulong outer_bit_len = (128ULL + 64ULL) * 8ULL;
    
    for (uint j = 0; j < 64; j++) {
        block[j] = inner_hash[j];
    }
    block[64] = 0x80;
    for (uint j = 65; j < 112; j++) {
        block[j] = 0;
    }
    // 写入128位长度（大端序）- 高64位为0，低64位为bit_len
    for (uint j = 112; j < 120; j++) {
        block[j] = 0;
    }
    block[120] = (uchar)(outer_bit_len >> 56);
    block[121] = (uchar)(outer_bit_len >> 48);
    block[122] = (uchar)(outer_bit_len >> 40);
    block[123] = (uchar)(outer_bit_len >> 32);
    block[124] = (uchar)(outer_bit_len >> 24);
    block[125] = (uchar)(outer_bit_len >> 16);
    block[126] = (uchar)(outer_bit_len >> 8);
    block[127] = (uchar)outer_bit_len;
    sha512_compress(state, block);
    
    // 输出结果
    for (uint j = 0; j < 8; j++) {
        result[j * 8] = (uchar)(state[j] >> 56);
        result[j * 8 + 1] = (uchar)(state[j] >> 48);
        result[j * 8 + 2] = (uchar)(state[j] >> 40);
        result[j * 8 + 3] = (uchar)(state[j] >> 32);
        result[j * 8 + 4] = (uchar)(state[j] >> 24);
        result[j * 8 + 5] = (uchar)(state[j] >> 16);
        result[j * 8 + 6] = (uchar)(state[j] >> 8);
        result[j * 8 + 7] = (uchar)state[j];
    }
}

#endif // SHA512_CL
