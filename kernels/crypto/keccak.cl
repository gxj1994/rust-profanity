// Keccak-256 哈希实现 (OpenCL)
// 基于 Keccak-f[1600] 置换函数

#ifndef KECCAK_CL
#define KECCAK_CL

// 轮常数
__constant ulong KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// 旋转左移 - 使用手动实现避免 rotate 函数歧义
inline ulong keccak_rotl(ulong x, uint n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] 主函数
void keccak_f1600(ulong st[25]) {
    // 24 轮
    for (int r = 0; r < 24; r++) {
        ulong bc[5], t;
        
        // Theta
        for (int i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ keccak_rotl(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }
        
        // Rho Pi
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = (i + 1) % 24;
            // Pi 置换: (3*i + 1) % 16 对应于标准 Keccak 的 rho 偏移
            int pi_idx[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 
                              15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
            int rho_off[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                               27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
            bc[0] = st[pi_idx[i]];
            st[pi_idx[i]] = keccak_rotl(t, rho_off[i]);
            t = bc[0];
        }
        
        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (int i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        
        // Iota
        st[0] ^= KECCAK_RC[r];
    }
}

// 字节序转换辅助函数 - 8字节小端序加载
inline ulong load_u64_le(const uchar* p) {
    ulong v = 0;
    for (int i = 0; i < 8; i++) {
        v |= ((ulong)p[i]) << (i * 8);
    }
    return v;
}

// 字节序转换辅助函数 - 8字节小端序存储
inline void store_u64_le(uchar* p, ulong v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uchar)(v >> (i * 8));
    }
}

// Keccak-256 哈希函数
// 输出 32 字节哈希
void keccak256(const uchar* in, uint inlen, uchar md[32]) {
    // 直接使用 ulong 数组作为状态，避免反复转换
    ulong st[25] = {0}; // 1600 bits = 25 * 64 bits
    
    // 吸收阶段
    uint rate = 136; // 1088 bits for Keccak-256 (17 * 8 bytes)
    uint i = 0;
    
    while (i < inlen) {
        uint block_size = (inlen - i < rate) ? (inlen - i) : rate;
        
        // XOR 输入到状态 (直接操作 ulong 数组)
        uint j = 0;
        for (; j + 8 <= block_size; j += 8) {
            st[j >> 3] ^= load_u64_le(&in[i + j]);
        }
        // 处理剩余字节 (< 8)
        if (j < block_size) {
            ulong tail = 0;
            for (uint k = 0; k < block_size - j; k++) {
                tail |= ((ulong)in[i + j + k]) << (k * 8);
            }
            st[j >> 3] ^= tail;
        }
        
        i += block_size;
        
        if (block_size == rate) {
            keccak_f1600(st);
        }
    }
    
    // 填充 - 直接在 ulong 数组上操作
    uint tail_len = inlen % rate;
    uint word_idx = tail_len >> 3;
    uint byte_idx = tail_len & 7;
    
    // domain separation
    st[word_idx] ^= ((ulong)0x01) << (byte_idx * 8);
    // padding end
    st[(rate >> 3) - 1] ^= 0x8000000000000000ULL;
    
    // 最终置换
    keccak_f1600(st);
    
    // 输出前 32 字节 (4个 ulong)
    for (int j = 0; j < 4; j++) {
        store_u64_le(&md[j * 8], st[j]);
    }
}

#endif // KECCAK_CL
