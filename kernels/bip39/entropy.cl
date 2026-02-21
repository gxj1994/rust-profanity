// BIP39 熵与助记词转换 (OpenCL)
// 实现符合 BIP39 标准的熵到助记词转换，包含正确的校验和计算

// 从 256 位熵生成助记词 (符合 BIP39 标准) - 优化版本
// entropy: 32 字节熵输入
// mnemonic: 输出的助记词结构 (24 个单词索引)
inline void entropy_to_mnemonic(const uchar entropy[32], ushort words[24]) {
    // 计算校验和: SHA256 的前 8 位 (256/32 = 8)
    uchar hash[32];
    sha256(entropy, 32, hash);
    uchar checksum_bits = hash[0]; // 取前8位
    
    // 组合: 256位熵 + 8位校验和 = 264位
    // 将数据视为大端序的位流
    uchar all_bits[33];
    // 使用 uchar16 向量类型批量复制 32 字节
    uchar16* bits16 = (uchar16*)all_bits;
    const uchar16* ent16 = (const uchar16*)entropy;
    bits16[0] = ent16[0];
    bits16[1] = ent16[1];
    all_bits[32] = checksum_bits;
    
    // 提取24个11位索引 - 优化版本
    // 使用 64 位加载减少内存访问
    for (int i = 0; i < 24; i++) {
        int bit_offset = i * 11;
        int byte_idx = bit_offset >> 3;  // / 8
        int bit_shift = bit_offset & 7;  // % 8
        
        // 安全加载最多 3 个字节到 32 位整数
        // 避免越界：all_bits 只有 33 字节 (索引 0-32)
        uint val = ((uint)all_bits[byte_idx] << 24);
        if (byte_idx + 1 < 33) {
            val |= ((uint)all_bits[byte_idx + 1] << 16);
        }
        if (byte_idx + 2 < 33) {
            val |= ((uint)all_bits[byte_idx + 2] << 8);
        }
        
        // 提取 11 位 (从大端序)
        val = val << bit_shift;
        words[i] = (ushort)((val >> 21) & 0x7FF);  // 21 = 32 - 11
    }
}

// 从助记词重建熵 (验证用)
// words: 24 个单词索引
// entropy: 输出的 32 字节熵
// 返回: 校验和是否有效
inline bool mnemonic_to_entropy(const ushort words[24], uchar entropy[32]) {
    // 从单词索引重建位流
    uchar all_bits[33];
    for (int i = 0; i < 33; i++) {
        all_bits[i] = 0;
    }
    
    for (int i = 0; i < 24; i++) {
        ushort word_idx = words[i];
        int bit_offset = i * 11;
        
        for (int j = 0; j < 11; j++) {
            int bit_pos = bit_offset + j;
            int byte_idx = bit_pos / 8;
            int bit_in_byte = 7 - (bit_pos % 8);
            
            if ((word_idx >> (10 - j)) & 1) {
                all_bits[byte_idx] |= 1 << bit_in_byte;
            }
        }
    }
    
    // 提取熵和校验和
    for (int i = 0; i < 32; i++) {
        entropy[i] = all_bits[i];
    }
    uchar checksum = all_bits[32];
    
    // 计算期望的校验和
    uchar hash[32];
    sha256(entropy, 32, hash);
    uchar expected_checksum = hash[0]; // 前8位
    
    return checksum == expected_checksum;
}

// 熵递增 - 按步长递增熵值
// 返回 false 表示溢出
inline bool increment_entropy(uchar entropy[32], uint step) {
    uint carry = step;
    
    // 从最后一个字节开始进位 (小端序处理)
    for (int i = 31; i >= 0 && carry > 0; i--) {
        uint sum = (uint)entropy[i] + carry;
        entropy[i] = (uchar)(sum & 0xFF);
        carry = sum >> 8;
    }
    
    // 如果还有进位，说明溢出
    return (carry == 0);
}
