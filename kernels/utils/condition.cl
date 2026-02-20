// 条件匹配系统 (OpenCL)

#ifndef CONDITION_CL
#define CONDITION_CL

// 条件类型
#define COND_PREFIX  0x01
#define COND_SUFFIX  0x02
#define COND_PATTERN 0x03
#define COND_LEADING 0x04

// 比较前缀
// param: 要匹配的前缀字节 (最多6字节)
bool compare_prefix(const uchar address[20], ulong param) {
    // 提取地址前6字节进行比较 (大端序)
    // address[0] 是最高有效字节
    ulong addr_prefix = 0;
    for (int i = 0; i < 6; i++) {
        addr_prefix = (addr_prefix << 8) | address[i];
    }
    
    // 确定 param 的有效字节数
    ulong temp = param;
    uint param_bytes = 0;
    while (temp > 0) {
        param_bytes++;
        temp >>= 8;
    }
    if (param_bytes == 0) param_bytes = 1;
    if (param_bytes > 6) param_bytes = 6;  // 最多6字节
    
    // 创建掩码，只比较多字节
    // 例如：param_bytes=2，则比较前2字节 (48位)
    ulong mask = (param_bytes == 6) ? 0xFFFFFFFFFFFFFFFFULL 
                                   : ((1ULL << (param_bytes * 8)) - 1);
    mask <<= (6 - param_bytes) * 8;  // 左移到高有效位
    
    return (addr_prefix & mask) == (param << ((6 - param_bytes) * 8));
}

// 比较后缀
bool compare_suffix(const uchar address[20], ulong param) {
    // 提取地址后6字节进行比较 (大端序)
    // address[14] 是后缀的最高有效字节
    ulong addr_suffix = 0;
    for (int i = 14; i < 20; i++) {
        addr_suffix = (addr_suffix << 8) | address[i];
    }
    
    // 确定 param 的有效字节数
    ulong temp = param;
    uint param_bytes = 0;
    while (temp > 0) {
        param_bytes++;
        temp >>= 8;
    }
    if (param_bytes == 0) param_bytes = 1;
    if (param_bytes > 6) param_bytes = 6;  // 最多6字节
    
    // 创建掩码，只比较多字节
    // 例如：param_bytes=2，则比较后2字节 (低16位)
    ulong mask = (param_bytes == 6) ? 0xFFFFFFFFFFFFFFFFULL 
                                   : ((1ULL << (param_bytes * 8)) - 1);
    
    return (addr_suffix & mask) == param;
}

// 统计前导零字节数
uint count_leading_zeros(const uchar address[20]) {
    uint count = 0;
    for (int i = 0; i < 20; i++) {
        if (address[i] == 0) {
            count++;
        } else {
            break;
        }
    }
    return count;
}

// 检查条件
bool check_condition(const uchar address[20], ulong condition) {
    ushort type = (condition >> 48) & 0xFFFF;
    ulong param = condition & 0xFFFFFFFFFFFFULL;
    
    switch (type) {
        case COND_PREFIX:
            return compare_prefix(address, param);
        case COND_SUFFIX:
            return compare_suffix(address, param);
        case COND_LEADING:
            return count_leading_zeros(address) >= param;
        default:
            return false;
    }
}

#endif // CONDITION_CL
