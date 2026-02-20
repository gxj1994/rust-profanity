// BIP39 熵与助记词转换 (OpenCL)
// 实现符合 BIP39 标准的熵到助记词转换，包含正确的校验和计算

// 从 256 位熵生成助记词 (符合 BIP39 标准)
// entropy: 32 字节熵输入
// mnemonic: 输出的助记词结构 (24 个单词索引)
void entropy_to_mnemonic(const uchar entropy[32], ushort words[24]) {
    // 计算校验和: SHA256 的前 8 位 (256/32 = 8)
    uchar hash[32];
    sha256(entropy, 32, hash);
    uchar checksum_bits = hash[0] >> (8 - 8); // 取前8位
    
    // 组合: 256位熵 + 8位校验和 = 264位
    // 将数据视为大端序的位流
    uchar all_bits[33];
    for (int i = 0; i < 32; i++) {
        all_bits[i] = entropy[i];
    }
    all_bits[32] = checksum_bits;
    
    // 提取24个11位索引
    for (int i = 0; i < 24; i++) {
        int bit_offset = i * 11;
        ushort idx = 0;
        
        // 读取11位索引 (可能跨越2-3个字节)
        for (int j = 0; j < 11; j++) {
            int bit_pos = bit_offset + j;
            int byte_idx = bit_pos / 8;
            int bit_in_byte = 7 - (bit_pos % 8); // 大端序: MSB在前
            
            if ((all_bits[byte_idx] >> bit_in_byte) & 1) {
                idx |= 1 << (10 - j); // 大端序存储
            }
        }
        
        words[i] = idx & 0x7FF;
    }
}

// 从助记词重建熵 (验证用)
// words: 24 个单词索引
// entropy: 输出的 32 字节熵
// 返回: 校验和是否有效
bool mnemonic_to_entropy(const ushort words[24], uchar entropy[32]) {
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
    uchar expected_checksum = hash[0] >> (8 - 8); // 前8位
    
    return checksum == expected_checksum;
}

// 熵递增 - 按步长递增熵值
// 返回 false 表示溢出
bool increment_entropy(uchar entropy[32], uint step) {
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
