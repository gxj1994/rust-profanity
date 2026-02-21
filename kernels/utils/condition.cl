// 条件匹配系统 (OpenCL)

#ifndef CONDITION_CL
#define CONDITION_CL

// 条件类型
#define COND_PREFIX  0x01
#define COND_SUFFIX  0x02
#define COND_PATTERN 0x03
#define COND_LEADING 0x04
#define COND_LEADING_EXACT 0x05  // 精确匹配前导零个数

// Condition 编码格式：
// [类型:16位][字节数:4位][保留:4位][参数:40位]
// 字节数=0 表示 6 字节（最大值）
#define GET_COND_TYPE(cond)    ((cond >> 48) & 0xFFFF)
#define GET_COND_BYTES(cond)   (((cond >> 44) & 0x0F) == 0 ? 6 : ((cond >> 44) & 0x0F))
#define GET_COND_PARAM(cond)   (cond & 0xFFFFFFFFFFULL)  // 40位参数

// 比较前缀 - 优化版本
// condition: 编码后的条件，包含字节数和参数
// 
// Rust 端编码逻辑 (大端序):
//   for byte in bytes:
//       param = (param << 8) | byte
// 例如 bytes=[0x12, 0x34] -> param = 0x1234
// 
// 地址字节与 param 的对应关系:
//   address[0] = (param >> 8) & 0xFF   (最高有效字节)
//   address[1] = param & 0xFF          (最低有效字节)
inline bool compare_prefix(const uchar address[20], ulong condition) {
    uint param_bytes = GET_COND_BYTES(condition);
    ulong param = GET_COND_PARAM(condition);
    
    // 根据 param_bytes 动态计算偏移量
    // 对于 n 字节，address[i] 对应 param 的第 (n-1-i) 个字节
    if (param_bytes >= 6) {
        if (address[5] != ((param >> 0) & 0xFF)) return false;
    }
    if (param_bytes >= 5) {
        if (address[4] != ((param >> 8) & 0xFF)) return false;
    }
    if (param_bytes >= 4) {
        if (address[3] != ((param >> 16) & 0xFF)) return false;
    }
    if (param_bytes >= 3) {
        if (address[2] != ((param >> 24) & 0xFF)) return false;
    }
    if (param_bytes >= 2) {
        // 2字节: address[0]>>8, address[1]>>0
        if (address[1] != (param & 0xFF)) return false;
    }
    if (param_bytes >= 1) {
        // 1字节: address[0] = param & 0xFF (因为 param < 256)
        // 2字节: address[0] = (param >> 8) & 0xFF
        // 通用公式: address[0] = (param >> (8 * max(0, param_bytes-1))) & 0xFF
        uint shift = (param_bytes > 1) ? (8 * (param_bytes - 1)) : 0;
        if (address[0] != ((param >> shift) & 0xFF)) return false;
    }
    
    return true;
}

// 比较后缀 - 优化版本
// condition: 编码后的条件，包含字节数和参数
inline bool compare_suffix(const uchar address[20], ulong condition) {
    uint param_bytes = GET_COND_BYTES(condition);
    ulong param = GET_COND_PARAM(condition);
    
    // 使用展开循环直接比较，避免循环开销和运行时计算
    // 从最低地址（后缀起始）开始比较，可提前退出
    uint start_idx = 20 - param_bytes;
    
    if (param_bytes >= 1) {
        if (address[start_idx] != ((param >> ((param_bytes - 1) * 8)) & 0xFF)) return false;
    }
    if (param_bytes >= 2) {
        if (address[start_idx + 1] != ((param >> ((param_bytes - 2) * 8)) & 0xFF)) return false;
    }
    if (param_bytes >= 3) {
        if (address[start_idx + 2] != ((param >> ((param_bytes - 3) * 8)) & 0xFF)) return false;
    }
    if (param_bytes >= 4) {
        if (address[start_idx + 3] != ((param >> ((param_bytes - 4) * 8)) & 0xFF)) return false;
    }
    if (param_bytes >= 5) {
        if (address[start_idx + 4] != ((param >> ((param_bytes - 5) * 8)) & 0xFF)) return false;
    }
    if (param_bytes >= 6) {
        if (address[start_idx + 5] != (param & 0xFF)) return false;
    }
    
    return true;
}

// 前导零查找表 - 每个字节对应的前导零十六进制字符数
// 索引: 字节值 (0-255), 值: 该字节贡献的前导零字符数 (0, 1, 或 2)
// 0x00 -> 2, 0x01-0x0F -> 1, 0x10-0xFF -> 0
constant uchar LEADING_ZERO_TABLE[256] = {
    2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0x00-0x0F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x10-0x1F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x20-0x2F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x30-0x3F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x40-0x4F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x50-0x5F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x60-0x6F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x70-0x7F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x80-0x8F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x90-0x9F
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xA0-0xAF
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xB0-0xBF
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xC0-0xCF
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xD0-0xDF
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0xE0-0xEF
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 0xF0-0xFF
};

// 统计前导零十六进制字符数 - 优化版本 (使用查找表)
// 每个字节 = 2 个十六进制字符
inline uint count_leading_zeros(const uchar address[20]) {
    uint count = 0;
    
    // 使用 #pragma unroll 提示编译器展开循环
    // 查找表访问是 O(1)，避免分支预测失败
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        uchar zeros = LEADING_ZERO_TABLE[address[i]];
        count += zeros;
        if (zeros != 2) {
            break;  // 遇到非全零字节立即退出
        }
    }
    
    return count;
}

// 检查条件
inline bool check_condition(const uchar address[20], ulong condition) {
    ushort type = (condition >> 48) & 0xFFFF;
    ulong param = condition & 0xFFFFFFFFFFFFULL;
    
    switch (type) {
        case COND_PREFIX:
            return compare_prefix(address, param);
        case COND_SUFFIX:
            return compare_suffix(address, param);
        case COND_LEADING:
            return count_leading_zeros(address) >= param;
        case COND_LEADING_EXACT:
            return count_leading_zeros(address) == param;
        default:
            return false;
    }
}

#endif // CONDITION_CL
