// 条件匹配系统 (OpenCL)

#ifndef CONDITION_CL
#define CONDITION_CL

// 条件类型
#define COND_PREFIX  0x01
#define COND_SUFFIX  0x02
#define COND_PATTERN 0x03
#define COND_LEADING 0x04
#define COND_LEADING_EXACT 0x05  // 精确匹配前导零个数

// 比较前缀
// param: 要匹配的前缀字节 (最多6字节)，按大端序存储
// 例如：匹配 "888" 时，param = 0x0000000000383838 (3字节)
inline bool compare_prefix(const uchar address[20], ulong param) {
    // 确定 param 的有效字节数
    ulong temp = param;
    uint param_bytes = 0;
    while (temp > 0) {
        param_bytes++;
        temp >>= 8;
    }
    if (param_bytes == 0) param_bytes = 1;
    if (param_bytes > 6) param_bytes = 6;  // 最多6字节
    
    // 直接逐字节比较地址的前 param_bytes 字节
    // param 是大端序存储，最高有效字节在低位地址
    for (uint i = 0; i < param_bytes; i++) {
        // 从 param 中提取第 i 个字节（从最高有效字节开始）
        int shift = (param_bytes - 1 - i) * 8;
        uchar expected_byte = (param >> shift) & 0xFF;
        if (address[i] != expected_byte) {
            return false;
        }
    }
    
    return true;
}

// 比较后缀
// param: 要匹配的后缀字节 (最多6字节)，按大端序存储
inline bool compare_suffix(const uchar address[20], ulong param) {
    // 确定 param 的有效字节数
    ulong temp = param;
    uint param_bytes = 0;
    while (temp > 0) {
        param_bytes++;
        temp >>= 8;
    }
    if (param_bytes == 0) param_bytes = 1;
    if (param_bytes > 6) param_bytes = 6;  // 最多6字节
    
    // 直接逐字节比较地址的后 param_bytes 字节
    // address[20 - param_bytes] 到 address[19] 是后缀部分
    for (uint i = 0; i < param_bytes; i++) {
        // 从 param 中提取第 i 个字节（从最高有效字节开始）
        int shift = (param_bytes - 1 - i) * 8;
        uchar expected_byte = (param >> shift) & 0xFF;
        if (address[20 - param_bytes + i] != expected_byte) {
            return false;
        }
    }
    
    return true;
}

// 统计前导零十六进制字符数
// 每个字节 = 2 个十六进制字符
inline uint count_leading_zeros(const uchar address[20]) {
    uint count = 0;
    for (int i = 0; i < 20; i++) {
        uchar byte = address[i];
        if (byte == 0) {
            count += 2;  // 00 = 2 个零字符
        } else if ((byte & 0xF0) == 0) {
            count += 1;  // 0x = 1 个零字符 (高 4 位为 0)
            break;
        } else {
            break;
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
