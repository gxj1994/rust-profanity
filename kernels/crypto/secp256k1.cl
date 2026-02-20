// secp256k1 椭圆曲线运算 (OpenCL)
// 完整实现，用于以太坊地址生成

#ifndef SECP256K1_CL
#define SECP256K1_CL

// secp256k1 素数 p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
// = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// 小端序: d[0] 是最低有效位
__constant ulong SECP256K1_P[4] = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

// secp256k1 阶 n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
__constant ulong SECP256K1_N[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL
};

// p 的低 32 位: FFFFFC2F
__constant uint SECP256K1_P_LOW = 0xFFFFFC2F;

// 基点 G 的坐标
__constant ulong SECP256K1_GX[4] = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
};

__constant ulong SECP256K1_GY[4] = {
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

// 256位大数结构 (小端序: d[0] 是最低有效位)
typedef struct {
    ulong d[4];
} uint256_t;

// 512位大数结构 (用于乘法中间结果)
typedef struct {
    ulong d[8];
} uint512_t;

// 初始化 uint256 为零
void uint256_clear(uint256_t* a) {
    a->d[0] = 0;
    a->d[1] = 0;
    a->d[2] = 0;
    a->d[3] = 0;
}

// 从字节数组加载 uint256 (大端序)
void uint256_from_bytes(const uchar bytes[32], uint256_t* result) {
    for (int i = 0; i < 4; i++) {
        result->d[3 - i] = ((ulong)bytes[i * 8] << 56) |
                          ((ulong)bytes[i * 8 + 1] << 48) |
                          ((ulong)bytes[i * 8 + 2] << 40) |
                          ((ulong)bytes[i * 8 + 3] << 32) |
                          ((ulong)bytes[i * 8 + 4] << 24) |
                          ((ulong)bytes[i * 8 + 5] << 16) |
                          ((ulong)bytes[i * 8 + 6] << 8) |
                          ((ulong)bytes[i * 8 + 7]);
    }
}

// 将 uint256 保存到字节数组 (大端序)
void uint256_to_bytes(const uint256_t* a, uchar bytes[32]) {
    for (int i = 0; i < 4; i++) {
        bytes[i * 8] = (uchar)(a->d[3 - i] >> 56);
        bytes[i * 8 + 1] = (uchar)(a->d[3 - i] >> 48);
        bytes[i * 8 + 2] = (uchar)(a->d[3 - i] >> 40);
        bytes[i * 8 + 3] = (uchar)(a->d[3 - i] >> 32);
        bytes[i * 8 + 4] = (uchar)(a->d[3 - i] >> 24);
        bytes[i * 8 + 5] = (uchar)(a->d[3 - i] >> 16);
        bytes[i * 8 + 6] = (uchar)(a->d[3 - i] >> 8);
        bytes[i * 8 + 7] = (uchar)(a->d[3 - i]);
    }
}

// 比较两个 uint256: 返回 -1, 0, 1
int uint256_cmp(const uint256_t* a, const uint256_t* b) {
    for (int i = 3; i >= 0; i--) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return 1;
    }
    return 0;
}

// 检查是否为零
int uint256_is_zero(const uint256_t* a) {
    return (a->d[0] == 0 && a->d[1] == 0 && a->d[2] == 0 && a->d[3] == 0);
}

// 模加: result = (a + b) mod p
void mod_add(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    ulong carry = 0;
    ulong sum;
    
    for (int i = 0; i < 4; i++) {
        sum = a->d[i] + b->d[i] + carry;
        // 检测进位
        carry = (sum < a->d[i]) || (sum == a->d[i] && carry);
        result->d[i] = sum;
    }
    
    // 如果结果 >= p，减去 p
    // p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    // 简化为: 如果溢出或结果 >= p，需要减去 p
    if (carry || uint256_cmp(result, (const uint256_t*)SECP256K1_P) >= 0) {
        // 减去 p
        carry = 0;
        for (int i = 0; i < 4; i++) {
            ulong p_val = SECP256K1_P[i];
            ulong diff = result->d[i] - p_val - carry;
            carry = (result->d[i] < p_val + carry) ? 1 : 0;
            result->d[i] = diff;
        }
    }
}

// 模减: result = (a - b) mod p
void mod_sub(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    ulong borrow = 0;
    
    for (int i = 0; i < 4; i++) {
        ulong b_val = b->d[i] + borrow;
        borrow = (a->d[i] < b_val) ? 1 : 0;
        result->d[i] = a->d[i] - b_val;
    }
    
    // 如果借位，加上 p
    if (borrow) {
        ulong carry = 0;
        for (int i = 0; i < 4; i++) {
            ulong sum = result->d[i] + SECP256K1_P[i] + carry;
            carry = (sum < result->d[i]) ? 1 : 0;
            result->d[i] = sum;
        }
    }
}

// 模加: result = (a + b) mod n (用于BIP32)
void mod_add_n(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    ulong carry = 0;
    ulong sum;
    
    for (int i = 0; i < 4; i++) {
        sum = a->d[i] + b->d[i] + carry;
        carry = (sum < a->d[i]) || (sum == a->d[i] && carry);
        result->d[i] = sum;
    }
    
    // 如果结果 >= n，减去 n
    if (carry || uint256_cmp(result, (const uint256_t*)SECP256K1_N) >= 0) {
        carry = 0;
        for (int i = 0; i < 4; i++) {
            ulong n_val = SECP256K1_N[i];
            ulong diff = result->d[i] - n_val - carry;
            carry = (result->d[i] < n_val + carry) ? 1 : 0;
            result->d[i] = diff;
        }
    }
}

// 快速模约简用于 secp256k1 (p = 2^256 - delta)
// delta = 2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1 = 0x1000003D1
void mod_reduce_fast(const ulong t[8], uint256_t* result) {
    // 对于 p = 2^256 - delta，有: a mod p = (a_low + a_high * delta) mod p
    // 其中 a = a_high * 2^256 + a_low
    
    uint256_t low, high;
    for (int i = 0; i < 4; i++) {
        low.d[i] = t[i];
        high.d[i] = t[i + 4];
    }
    
    // 计算 high * delta (delta = 2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1)
    // 使用位移和加法: high * delta = high * (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1)
    uint256_t delta_high;
    uint256_clear(&delta_high);
    
    // high * 1
    for (int i = 0; i < 4; i++) delta_high.d[i] = high.d[i];
    
    // high * 2^4 = high << 4
    uint256_t t1;
    uint256_clear(&t1);
    ulong carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong new_carry = high.d[i] >> 60;
        t1.d[i] = (high.d[i] << 4) | carry;
        carry = new_carry;
    }
    mod_add(&delta_high, &t1, &delta_high);
    
    // high * 2^6 = high << 6
    uint256_clear(&t1);
    carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong new_carry = high.d[i] >> 58;
        t1.d[i] = (high.d[i] << 6) | carry;
        carry = new_carry;
    }
    mod_add(&delta_high, &t1, &delta_high);
    
    // high * 2^7 = high << 7
    uint256_clear(&t1);
    carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong new_carry = high.d[i] >> 57;
        t1.d[i] = (high.d[i] << 7) | carry;
        carry = new_carry;
    }
    mod_add(&delta_high, &t1, &delta_high);
    
    // high * 2^8 = high << 8
    uint256_clear(&t1);
    carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong new_carry = high.d[i] >> 56;
        t1.d[i] = (high.d[i] << 8) | carry;
        carry = new_carry;
    }
    mod_add(&delta_high, &t1, &delta_high);
    
    // high * 2^9 = high << 9
    uint256_clear(&t1);
    carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong new_carry = high.d[i] >> 55;
        t1.d[i] = (high.d[i] << 9) | carry;
        carry = new_carry;
    }
    mod_add(&delta_high, &t1, &delta_high);
    
    // high * 2^32: 这相当于将 high 左移 32 位，即 high.d[i] 在 32 位边界上移动
    // high * 2^32 = high << 32，相当于每个 dword 移动 1 个位置（考虑小端序）
    uint256_t high_shift32;
    high_shift32.d[0] = 0;
    high_shift32.d[1] = high.d[0];
    high_shift32.d[2] = high.d[1];
    high_shift32.d[3] = high.d[2];
    // 注意：high.d[3] 被丢弃（溢出）
    mod_add(&delta_high, &high_shift32, &delta_high);
    
    // result = low + delta_high
    mod_add(&low, &delta_high, result);
    
    // 可能需要再次约简
    if (uint256_cmp(result, (const uint256_t*)SECP256K1_P) >= 0) {
        uint256_t temp;
        mod_sub(result, (const uint256_t*)SECP256K1_P, &temp);
        *result = temp;
    }
}

// 模乘: result = (a * b) mod p
// 使用快速约简算法
void mod_mul(const uint256_t* a, const uint256_t* b, uint256_t* result) {
    // 512位中间结果
    ulong t[8] = {0};
    
    // 普通乘法
    for (int i = 0; i < 4; i++) {
        ulong carry = 0;
        for (int j = 0; j < 4; j++) {
            __uint128_t prod = (__uint128_t)a->d[i] * b->d[j] + t[i + j] + carry;
            t[i + j] = (ulong)prod;
            carry = (ulong)(prod >> 64);
        }
        t[i + 4] += carry;
    }
    
    // 快速模约简
    mod_reduce_fast(t, result);
}

// 模平方: result = a^2 mod p
void mod_sqr(const uint256_t* a, uint256_t* result) {
    mod_mul(a, a, result);
}

// 模逆元: result = a^(-1) mod p (使用费马小定理: a^(p-2) mod p)
void mod_inv(const uint256_t* a, uint256_t* result) {
    // p - 2 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
    // 使用二进制幂算法
    uint256_t base;
    for (int i = 0; i < 4; i++) {
        base.d[i] = a->d[i];
    }
    
    // 结果初始化为 1
    uint256_clear(result);
    result->d[0] = 1;
    
    // 指数 p-2 的二进制位
    // 从高位到低位
    int exponent_bits[256] = {
        // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        // 从高到低处理
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, // FFFFFFFF
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, // FFFFFFFF
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, // FFFFFFFF
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,0, // FFFFFFFE
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, // FFFFFFFF
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,0,0, // FFFFFC
        0,0,1,0,1,1,0,1  // 2D
    };
    
    for (int i = 0; i < 256; i++) {
        if (exponent_bits[i]) {
            mod_mul(result, &base, result);
        }
        mod_sqr(&base, &base);
    }
}

// 椭圆曲线点
typedef struct {
    uint256_t x;
    uint256_t y;
    int infinity;
} ec_point_t;

// 初始化无穷远点
ec_point_t point_infinity() {
    ec_point_t p;
    p.infinity = 1;
    uint256_clear(&p.x);
    uint256_clear(&p.y);
    return p;
}

// 点加倍: R = 2P
void point_double(const ec_point_t* p, ec_point_t* r) {
    if (p->infinity) {
        *r = point_infinity();
        return;
    }
    
    if (uint256_is_zero(&p->y)) {
        *r = point_infinity();
        return;
    }
    
    // lambda = (3*x^2) / (2*y) mod p
    uint256_t lambda, temp1, temp2, two_y;
    
    // temp1 = x^2
    mod_sqr(&p->x, &temp1);
    
    // temp2 = 3 * x^2 = x^2 + x^2 + x^2
    mod_add(&temp1, &temp1, &temp2);
    mod_add(&temp2, &temp1, &temp2);  // temp2 = 3*x^2
    
    // two_y = 2 * y
    mod_add(&p->y, &p->y, &two_y);
    
    // lambda = temp2 / two_y = temp2 * two_y^(-1)
    uint256_t inv_2y;
    mod_inv(&two_y, &inv_2y);
    mod_mul(&temp2, &inv_2y, &lambda);
    
    // x_r = lambda^2 - 2*x
    uint256_t lambda_sqr, two_x;
    mod_sqr(&lambda, &lambda_sqr);
    mod_add(&p->x, &p->x, &two_x);
    mod_sub(&lambda_sqr, &two_x, &r->x);
    
    // y_r = lambda * (x - x_r) - y
    uint256_t x_diff;
    mod_sub(&p->x, &r->x, &x_diff);
    mod_mul(&lambda, &x_diff, &temp1);
    mod_sub(&temp1, &p->y, &r->y);
    
    r->infinity = 0;
}

// 点加法: R = P + Q
void point_add(const ec_point_t* p, const ec_point_t* q, ec_point_t* r) {
    if (p->infinity) {
        *r = *q;
        return;
    }
    if (q->infinity) {
        *r = *p;
        return;
    }
    
    // 检查 P == Q
    if (uint256_cmp(&p->x, &q->x) == 0) {
        if (uint256_cmp(&p->y, &q->y) == 0) {
            // P == Q，使用点加倍
            point_double(p, r);
            return;
        } else {
            // P == -Q，返回无穷远点
            *r = point_infinity();
            return;
        }
    }
    
    // lambda = (y2 - y1) / (x2 - x1) mod p
    uint256_t lambda, y_diff, x_diff, inv_x_diff;
    
    mod_sub(&q->y, &p->y, &y_diff);
    mod_sub(&q->x, &p->x, &x_diff);
    mod_inv(&x_diff, &inv_x_diff);
    mod_mul(&y_diff, &inv_x_diff, &lambda);
    
    // x_r = lambda^2 - x1 - x2
    uint256_t lambda_sqr, temp;
    mod_sqr(&lambda, &lambda_sqr);
    mod_sub(&lambda_sqr, &p->x, &temp);
    mod_sub(&temp, &q->x, &r->x);
    
    // y_r = lambda * (x1 - x_r) - y1
    uint256_t x1_diff;
    mod_sub(&p->x, &r->x, &x1_diff);
    mod_mul(&lambda, &x1_diff, &temp);
    mod_sub(&temp, &p->y, &r->y);
    
    r->infinity = 0;
}

// 标量乘法: result = scalar * G (使用双倍-加法算法)
void scalar_mult_base(const uchar scalar[32], uchar result[65]) {
    ec_point_t r = point_infinity();
    
    // 预计算基点 G
    ec_point_t g;
    g.infinity = 0;
    for (int i = 0; i < 4; i++) {
        g.x.d[i] = ((const uint256_t*)SECP256K1_GX)->d[i];
        g.y.d[i] = ((const uint256_t*)SECP256K1_GY)->d[i];
    }
    
    // 双倍-加法算法 (从最高位开始)
    for (int i = 0; i < 32; i++) {
        uchar byte = scalar[i];
        for (int j = 7; j >= 0; j--) {
            // 点加倍
            ec_point_t doubled;
            point_double(&r, &doubled);
            r = doubled;
            
            // 如果当前位为 1，加上 G
            if ((byte >> j) & 1) {
                ec_point_t added;
                point_add(&r, &g, &added);
                r = added;
            }
        }
    }
    
    // 输出未压缩公钥格式: 0x04 + x(32字节) + y(32字节)
    result[0] = 0x04;
    uint256_to_bytes(&r.x, result + 1);
    uint256_to_bytes(&r.y, result + 33);
}

// 从私钥生成公钥
void private_to_public(const uchar private_key[32], uchar public_key[65]) {
    scalar_mult_base(private_key, public_key);
}

#endif // SECP256K1_CL
