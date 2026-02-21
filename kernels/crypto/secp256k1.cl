// secp256k1 椭圆曲线运算 (OpenCL)
// 基于经过验证的 32 位实现
// 使用 8 个 32 位字表示 256 位数字

#ifndef SECP256K1_CL
#define SECP256K1_CL

#define MP_WORDS 8

typedef uint mp_word;

typedef struct {
	mp_word d[MP_WORDS];
} mp_number;

// secp256k1 素数 p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
// = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// 小端序: d[0] 是最低有效位
__constant const mp_number mod = { 
    {0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff} 
};

// 基点 G 的坐标
// Gx = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
__constant const mp_number Gx = {
    {0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e}
};

// Gy = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
__constant const mp_number Gy = {
    {0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77}
};



// 计算乘法的高 32 位（使用内置函数）
// OpenCL 内置 mul_hi 函数可用

// 从字节数组加载 mp_number (大端序)
void mp_from_bytes(const uchar bytes[32], mp_number* result) {
    for (int i = 0; i < 8; i++) {
        int offset = i * 4;
        result->d[7 - i] = ((uint)bytes[offset] << 24) |
                           ((uint)bytes[offset + 1] << 16) |
                           ((uint)bytes[offset + 2] << 8) |
                           ((uint)bytes[offset + 3]);
    }
}

// 将 mp_number 保存到字节数组 (大端序)
void mp_to_bytes(const mp_number* a, uchar bytes[32]) {
    for (int i = 0; i < 8; i++) {
        int offset = i * 4;
        bytes[offset] = (uchar)(a->d[7 - i] >> 24);
        bytes[offset + 1] = (uchar)(a->d[7 - i] >> 16);
        bytes[offset + 2] = (uchar)(a->d[7 - i] >> 8);
        bytes[offset + 3] = (uchar)a->d[7 - i];
    }
}

// 检查是否为零
int mp_is_zero(const mp_number* a) {
    return (a->d[0] == 0 && a->d[1] == 0 && a->d[2] == 0 && a->d[3] == 0 &&
            a->d[4] == 0 && a->d[5] == 0 && a->d[6] == 0 && a->d[7] == 0);
}

// 多精度减法. 借位通过返回值信号
mp_word mp_sub(mp_number * const r, const mp_number * const a, const mp_number * const b) {
	mp_word t, c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		t = a->d[i] - b->d[i] - c;
		c = t > a->d[i] ? 1 : (t == a->d[i] ? c : 0);

		r->d[i] = t;
	}

	return c;
}

// 多精度减法模 M
void mp_mod_sub(mp_number * const r, const mp_number * const a, const mp_number * const b) {
	mp_word i, t, c = 0;

	for (i = 0; i < MP_WORDS; ++i) {
		t = a->d[i] - b->d[i] - c;
		// 正确的借位判断：如果 a < b + c，则产生借位
		c = (a->d[i] < b->d[i] + c) ? 1 : 0;

		r->d[i] = t;
	}

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r->d[i] += mod.d[i] + c;
			c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
		}
	}
}

// 多精度减法模 M of G_x from a number
void mp_mod_sub_gx(mp_number * const r, const mp_number * const a) {
	mp_word i, t, c = 0;

	t = a->d[0] - 0x16f81798; c = t < a->d[0] ? 0 : (t == a->d[0] ? c : 1); r->d[0] = t;
	t = a->d[1] - 0x59f2815b - c; c = t < a->d[1] ? 0 : (t == a->d[1] ? c : 1); r->d[1] = t;
	t = a->d[2] - 0x2dce28d9 - c; c = t < a->d[2] ? 0 : (t == a->d[2] ? c : 1); r->d[2] = t;
	t = a->d[3] - 0x029bfcdb - c; c = t < a->d[3] ? 0 : (t == a->d[3] ? c : 1); r->d[3] = t;
	t = a->d[4] - 0xce870b07 - c; c = t < a->d[4] ? 0 : (t == a->d[4] ? c : 1); r->d[4] = t;
	t = a->d[5] - 0x55a06295 - c; c = t < a->d[5] ? 0 : (t == a->d[5] ? c : 1); r->d[5] = t;
	t = a->d[6] - 0xf9dcbbac - c; c = t < a->d[6] ? 0 : (t == a->d[6] ? c : 1); r->d[6] = t;
	t = a->d[7] - 0x79be667e - c; c = t < a->d[7] ? 0 : (t == a->d[7] ? c : 1); r->d[7] = t;

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r->d[i] += mod.d[i] + c;
			c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
		}
	}
}

// 多精度减法模 M of G_y from a number
void mp_mod_sub_gy(mp_number * const r, const mp_number * const a) {
	mp_word i, t, c = 0;

	t = a->d[0] - 0xfb10d4b8; c = t < a->d[0] ? 0 : (t == a->d[0] ? c : 1); r->d[0] = t;
	t = a->d[1] - 0x9c47d08f - c; c = t < a->d[1] ? 0 : (t == a->d[1] ? c : 1); r->d[1] = t;
	t = a->d[2] - 0xa6855419 - c; c = t < a->d[2] ? 0 : (t == a->d[2] ? c : 1); r->d[2] = t;
	t = a->d[3] - 0xfd17b448 - c; c = t < a->d[3] ? 0 : (t == a->d[3] ? c : 1); r->d[3] = t;
	t = a->d[4] - 0x0e1108a8 - c; c = t < a->d[4] ? 0 : (t == a->d[4] ? c : 1); r->d[4] = t;
	t = a->d[5] - 0x5da4fbfc - c; c = t < a->d[5] ? 0 : (t == a->d[5] ? c : 1); r->d[5] = t;
	t = a->d[6] - 0x26a3c465 - c; c = t < a->d[6] ? 0 : (t == a->d[6] ? c : 1); r->d[6] = t;
	t = a->d[7] - 0x483ada77 - c; c = t < a->d[7] ? 0 : (t == a->d[7] ? c : 1); r->d[7] = t;

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r->d[i] += mod.d[i] + c;
			c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
		}
	}
}

// 多精度加法. 溢出通过返回值信号
mp_word mp_add(mp_number * const r, const mp_number * const a) {
	mp_word c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		r->d[i] += a->d[i] + c;
		c = r->d[i] < a->d[i] ? 1 : (r->d[i] == a->d[i] ? c : 0);
	}

	return c;
}

void mp_mod_add(mp_number * const r, const mp_number * const a, const mp_number * const b) {
	mp_word i, t, c = 0;
	for (i = 0; i < MP_WORDS; ++i) {
		t = a->d[i] + b->d[i] + c;
		c = t < a->d[i] ? 1 : (t == a->d[i] ? c : 0);

		r->d[i] = t;
	}

	if (c) {
		c = 0;
		for (i = 0; i < MP_WORDS; ++i) {
			r->d[i] -= mod.d[i] + c;
			c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
		}
	}
}

// 多精度加法 of the modulus. 溢出通过返回值信号
mp_word mp_add_mod(mp_number * const r) {
	mp_word c = 0;

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		r->d[i] += mod.d[i] + c;
		c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
	}

	return c;
}

// 多精度加法 of two numbers with one extra word each. 溢出通过返回值信号
mp_word mp_add_more(mp_number * const r, mp_word * const extraR, const mp_number * const a, const mp_word * const extraA) {
	const mp_word c = mp_add(r, a);
	*extraR += *extraA + c;
	return *extraR < *extraA ? 1 : (*extraR == *extraA ? c : 0);
}

// 多精度大于等于 (>=) 操作符
// 注意：此实现使用位掩码方式，适用于二进制扩展欧几里得算法中的比较
// 在 mp_mod_inverse 中，它用于比较两个数的大小关系
mp_word mp_gte(const mp_number * const a, const mp_number * const b) {
    mp_word l = 0, g = 0;

    for (mp_word i = 0; i < MP_WORDS; ++i) {
        if (a->d[i] < b->d[i]) l |= (1 << i);
        if (a->d[i] > b->d[i]) g |= (1 << i);
    }

    return g >= l;
}

// 右移一位，带额外字
void mp_shr_extra(mp_number * const r, mp_word * const e) {
	r->d[0] = (r->d[1] << 31) | (r->d[0] >> 1);
	r->d[1] = (r->d[2] << 31) | (r->d[1] >> 1);
	r->d[2] = (r->d[3] << 31) | (r->d[2] >> 1);
	r->d[3] = (r->d[4] << 31) | (r->d[3] >> 1);
	r->d[4] = (r->d[5] << 31) | (r->d[4] >> 1);
	r->d[5] = (r->d[6] << 31) | (r->d[5] >> 1);
	r->d[6] = (r->d[7] << 31) | (r->d[6] >> 1);
	r->d[7] = (*e << 31) | (r->d[7] >> 1);
	*e >>= 1;
}

// 右移一位
void mp_shr(mp_number * const r) {
	r->d[0] = (r->d[1] << 31) | (r->d[0] >> 1);
	r->d[1] = (r->d[2] << 31) | (r->d[1] >> 1);
	r->d[2] = (r->d[3] << 31) | (r->d[2] >> 1);
	r->d[3] = (r->d[4] << 31) | (r->d[3] >> 1);
	r->d[4] = (r->d[5] << 31) | (r->d[4] >> 1);
	r->d[5] = (r->d[6] << 31) | (r->d[5] >> 1);
	r->d[6] = (r->d[7] << 31) | (r->d[6] >> 1);
	r->d[7] >>= 1;
}

// 乘以一个字并加到现有数字，带额外字
mp_word mp_mul_word_add_extra(mp_number * const r, const mp_number * const a, const mp_word w, mp_word * const extra) {
	mp_word cM = 0; // 乘法进位
	mp_word cA = 0; // 加法进位
	mp_word tM = 0; // 乘法临时存储

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		tM = (a->d[i] * w + cM);
		cM = mul_hi(a->d[i], w) + (tM < cM);

		r->d[i] += tM + cA;
		cA = r->d[i] < tM ? 1 : (r->d[i] == tM ? cA : 0);
	}

	*extra += cM + cA;
	return *extra < cM ? 1 : (*extra == cM ? cA : 0);
}

// 模乘辅助函数
void mp_mul_mod_word_sub(mp_number * const r, const mp_word w, const bool withModHigher) {
	mp_number modhigher = { {0x00000000, 0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff} };

	mp_word cM = 0; // 乘法进位
	mp_word cS = 0; // 减法进位
	mp_word tS = 0; // 减法临时存储
	mp_word tM = 0; // 乘法临时存储
	mp_word cA = 0; // 加法进位

	for (mp_word i = 0; i < MP_WORDS; ++i) {
		tM = (mod.d[i] * w + cM);
		cM = mul_hi(mod.d[i], w) + (tM < cM);

		tM += (withModHigher ? modhigher.d[i] : 0) + cA;
		cA = tM < (withModHigher ? modhigher.d[i] : 0) ? 1 : (tM == (withModHigher ? modhigher.d[i] : 0) ? cA : 0);

		tS = r->d[i] - tM - cS;
		cS = tS > r->d[i] ? 1 : (tS == r->d[i] ? cS : 0);

		r->d[i] = tS;
	}
}

// 模乘
void mp_mod_mul(mp_number * const r, const mp_number * const X, const mp_number * const Y) {
	mp_number Z = { {0} };
	mp_word extraWord;

	for (int i = MP_WORDS - 1; i >= 0; --i) {
		// Z = Z * 2^32
		extraWord = Z.d[7]; Z.d[7] = Z.d[6]; Z.d[6] = Z.d[5]; Z.d[5] = Z.d[4]; 
		Z.d[4] = Z.d[3]; Z.d[3] = Z.d[2]; Z.d[2] = Z.d[1]; Z.d[1] = Z.d[0]; Z.d[0] = 0;

		// Z = Z + X * Y_i
		bool overflow = mp_mul_word_add_extra(&Z, X, Y->d[i], &extraWord);

		// Z = Z - qM
		mp_mul_mod_word_sub(&Z, extraWord, overflow);
	}

	*r = Z;
}

// 模逆元
void mp_mod_inverse(mp_number * const r) {
	mp_number A = { { 1 } };
	mp_number C = { { 0 } };
	mp_number v = mod;

	mp_word extraA = 0;
	mp_word extraC = 0;

	while (r->d[0] || r->d[1] || r->d[2] || r->d[3] || r->d[4] || r->d[5] || r->d[6] || r->d[7]) {
		while (!(r->d[0] & 1)) {
			mp_shr(r);
			if (A.d[0] & 1) {
				extraA += mp_add_mod(&A);
			}

			mp_shr_extra(&A, &extraA);
		}

		while (!(v.d[0] & 1)) {
			mp_shr(&v);
			if (C.d[0] & 1) {
				extraC += mp_add_mod(&C);
			}

			mp_shr_extra(&C, &extraC);
		}

		if (mp_gte(r, &v)) {
			mp_sub(r, r, &v);
			mp_add_more(&A, &extraA, &C, &extraC);
		}
		else {
			mp_sub(&v, &v, r);
			mp_add_more(&C, &extraC, &A, &extraA);
		}
	}

	mp_number mod_local = mod;
	while (extraC) {
		extraC -= mp_sub(&C, &C, &mod_local);
	}

	v = mod;
	mp_sub(r, &v, &C);
}

/* ------------------------------------------------------------------------ */
/* 椭圆曲线点和加法 - Jacobian 射影坐标优化                                   */
/* ------------------------------------------------------------------------ */
// 仿射坐标点
typedef struct {
	mp_number x;
	mp_number y;
} point;

/* ------------------------------------------------------------------------ */
/* 预计算基点 G 的倍数表 (窗口大小为4，16个点)                               */
/* PRECOMPUTED_G[i] = (2*i + 1) * G, i = 0..15                            */
/* 只存储奇数倍，偶数倍可以通过点加倍得到                                     */
/* 使用 Python fastecdsa 库计算生成                                          */
/* ------------------------------------------------------------------------ */
// 预计算表数据 - 使用宏简化初始化
#define MP_NUM(a0,a1,a2,a3,a4,a5,a6,a7) {{{a0,a1,a2,a3,a4,a5,a6,a7}}}

__constant const point PRECOMPUTED_G[16] = {
    // 1*G (索引 0)
    {MP_NUM(0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e),
     MP_NUM(0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77)},
    // 3*G (索引 1)
    {MP_NUM(0xbce036f9, 0x8601f113, 0x836f99b0, 0xb531c845, 0xf89d5229, 0x49344f85, 0x9258c310, 0xf9308a01),
     MP_NUM(0x84b8e672, 0x6cb9fd75, 0x34c2231b, 0x6500a999, 0x2a37f356, 0x0fe337e6, 0x632de814, 0x388f7b0f)},
    // 5*G (索引 2)
    {MP_NUM(0xb240efe4, 0xcba8d569, 0xdc619ab7, 0xe88b84bd, 0x0a5c5128, 0x55b4a725, 0x1a072093, 0x2f8bde4d),
     MP_NUM(0xa6ac62d6, 0xdca87d3a, 0xab0d6840, 0xf788271b, 0xa6c9c426, 0xd4dba9dd, 0x36e5e3d6, 0xd8ac2226)},
    // 7*G (索引 3)
    {MP_NUM(0xcac4f9bc, 0xe92bdded, 0x0330e39c, 0x3d419b7e, 0xf2ea7a0e, 0xa398f365, 0x6e5db4ea, 0x5cbdf064),
     MP_NUM(0x087264da, 0xa5082628, 0x13fde7b5, 0xa813d0b8, 0x861a54db, 0xa3178d6d, 0xba255960, 0x6aebca40)},
    // 9*G (索引 4)
    {MP_NUM(0xfc27ccbe, 0xc35f110d, 0x4c57e714, 0xe0979697, 0x9f559abd, 0x09ad178a, 0xf0c7f653, 0xacd484e2),
     MP_NUM(0xc64f9c37, 0x05cc262a, 0x375f8e0f, 0xadd888a4, 0x763b61e9, 0x64380971, 0xb0a7d9fd, 0xcc338921)},
    // 11*G (索引 5)
    {MP_NUM(0x5da008cb, 0xbbec1789, 0xe5c17891, 0x5649980b, 0x70c65aac, 0x5ef4246b, 0x58a9411e, 0x774ae7f8),
     MP_NUM(0xc953c61b, 0x301d74c9, 0xdff9d6a8, 0x372db1e2, 0xd7b7b365, 0x0243dd56, 0xeb6b5e19, 0xd984a032)},
    // 13*G (索引 6)
    {MP_NUM(0x19405aa8, 0xdeeddf8f, 0x610e58cd, 0xb075fbc6, 0xc3748651, 0xc7d1d205, 0xd975288b, 0xf28773c2),
     MP_NUM(0xdb03ed81, 0x29b5cb52, 0x521fa91f, 0x3a1a06da, 0x65cdaf47, 0x758212eb, 0x8d880a89, 0x0ab0902e)},
    // 15*G (索引 7)
    {MP_NUM(0xe27e080e, 0x44adbcf8, 0x3c85f79e, 0x31e5946f, 0x095ff411, 0x5a465ae3, 0x7d43ea96, 0xd7924d4f),
     MP_NUM(0xf6a26b58, 0xc504dc9f, 0xd896d3a5, 0xea40af2b, 0x28cc6def, 0x83842ec2, 0xa86c72a6, 0x581e2872)},
    // 17*G (索引 8)
    {MP_NUM(0x4a2d4a34, 0x66e4faa0, 0x79b97687, 0xeb9898ae, 0x07eacf21, 0xa420fee8, 0xdb677750, 0xdefdea4c),
     MP_NUM(0x9e56eb77, 0xcfb199f6, 0x4a95c0f6, 0xced1f4a0, 0xd2a93dae, 0xe997b0ea, 0x94635168, 0x4211ab06)},
    // 19*G (索引 9)
    {MP_NUM(0x38385b6c, 0x74756561, 0xd7e86d27, 0xf06acfeb, 0x444f4979, 0x93ef5cff, 0x97a443d2, 0x2b4ea0a7),
     MP_NUM(0xe5c09b7a, 0xb570c854, 0x50269763, 0x1a01f60c, 0x5a1c8613, 0xb343083b, 0x37945d93, 0x85e89bc0)},
    // 21*G (索引 10)
    {MP_NUM(0x25be59d5, 0x81340aef, 0x71f81071, 0x1d9ad402, 0x2ce33330, 0x4f93fa33, 0x4cdd1256, 0x352bbf4a),
     MP_NUM(0xcf81998c, 0x67bd3d8b, 0x71b1039c, 0x4a1b3b2e, 0x9dda3e1f, 0xd59c1825, 0x5348f534, 0x321eb407)},
    // 23*G (索引 11)
    {MP_NUM(0x4ecacc3f, 0xdc9cdadd, 0xeff5ff29, 0xe42ab8df, 0x59879124, 0x02300105, 0x6b38d11b, 0x2fa2104d),
     MP_NUM(0x532b7d67, 0x423ba76b, 0xfc882648, 0x181d70ec, 0x5bd5dd80, 0xb6456933, 0x295dd865, 0x02de1068)},
    // 25*G (索引 12)
    {MP_NUM(0xf5453714, 0x69ca0cd7, 0xe09572e2, 0x263c3d84, 0x66edda83, 0xab21a9b0, 0x09b4d68d, 0x9248279b),
     MP_NUM(0x97cb3402, 0xe54a32ce, 0x887912ff, 0x3fc0de2a, 0xdea2b1ff, 0x5d1aa71b, 0xf234aade, 0x73016f7b)},
    // 27*G (索引 13)
    {MP_NUM(0x3dee8729, 0x7e996d44, 0x4bf615c0, 0x2f570e14, 0xb0beb752, 0x8e70132f, 0xe3a8bf27, 0xdaed4f2b),
     MP_NUM(0x90be1c55, 0xab40e522, 0xf3afa726, 0x3f83c230, 0x7ef8d700, 0xd4a1aca8, 0x7d6c98e8, 0xa69dce4a)},
    // 29*G (索引 14)
    {MP_NUM(0x7d22e7db, 0xe6a3b5e8, 0xfdf281b0, 0x11ecd9e9, 0xcbb19f90, 0x8acf28d7, 0x065d812e, 0xc44d12c7),
     MP_NUM(0x0e0e6482, 0xa039063f, 0x1edf61c5, 0x0e106e86, 0xc982fdac, 0x76c45926, 0xce326cdc, 0x2119a460)},
    // 31*G (索引 15)
    {MP_NUM(0xd269e6b4, 0xb61c65cb, 0x36c28063, 0x152b6953, 0xded60853, 0xc89a20cf, 0xdc698504, 0x6a245bf6),
     MP_NUM(0x100d8a82, 0xfd5e6348, 0xd0423b6e, 0x8b33ba48, 0xf16a24ad, 0x8b3f5126, 0xc2bd4a70, 0xe022cf42)}
};

#undef MP_NUM

// 辅助函数：比较两个 mp_number
int mp_cmp(const mp_number* a, const mp_number* b) {
    for (int i = 7; i >= 0; i--) {
        if (a->d[i] < b->d[i]) return -1;
        if (a->d[i] > b->d[i]) return 1;
    }
    return 0;
}

// Jacobian 射影坐标点 (X, Y, Z) 对应仿射坐标 (X/Z^2, Y/Z^3)
typedef struct {
	mp_number X;
	mp_number Y;
	mp_number Z;
} jacobian_point;

// 初始化 Jacobian 点为无穷远点
void jacobian_set_infinity(jacobian_point* p) {
    p->X.d[0] = 1; p->X.d[1] = 0; p->X.d[2] = 0; p->X.d[3] = 0;
    p->X.d[4] = 0; p->X.d[5] = 0; p->X.d[6] = 0; p->X.d[7] = 0;
    p->Y.d[0] = 1; p->Y.d[1] = 0; p->Y.d[2] = 0; p->Y.d[3] = 0;
    p->Y.d[4] = 0; p->Y.d[5] = 0; p->Y.d[6] = 0; p->Y.d[7] = 0;
    p->Z.d[0] = 0; p->Z.d[1] = 0; p->Z.d[2] = 0; p->Z.d[3] = 0;
    p->Z.d[4] = 0; p->Z.d[5] = 0; p->Z.d[6] = 0; p->Z.d[7] = 0;
}

// 检查 Jacobian 点是否为无穷远点
int jacobian_is_infinity(const jacobian_point* p) {
    return mp_is_zero(&p->Z);
}

// 从仿射坐标创建 Jacobian 点 (支持 __constant 地址空间)
void affine_to_jacobian_c(jacobian_point* r, const __constant point* p) {
    r->X = p->x;
    r->Y = p->y;
    // Z = 1
    r->Z.d[0] = 1; r->Z.d[1] = 0; r->Z.d[2] = 0; r->Z.d[3] = 0;
    r->Z.d[4] = 0; r->Z.d[5] = 0; r->Z.d[6] = 0; r->Z.d[7] = 0;
}

// 从仿射坐标创建 Jacobian 点 (标准版本)
void affine_to_jacobian(jacobian_point* r, const point* p) {
    r->X = p->x;
    r->Y = p->y;
    // Z = 1
    r->Z.d[0] = 1; r->Z.d[1] = 0; r->Z.d[2] = 0; r->Z.d[3] = 0;
    r->Z.d[4] = 0; r->Z.d[5] = 0; r->Z.d[6] = 0; r->Z.d[7] = 0;
}

// Jacobian 点加倍: R = 2*P
// 使用标准 secp256k1 曲线点加倍公式 (a=0, b=7)
// 公式来源: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
// 对于 a=0 的曲线，简化为:
// XX = X1^2
// YY = Y1^2
// YYYY = YY^2
// ZZ = Z1^2
// S = 2*((X1+YY)^2 - XX - YYYY)
// M = 3*XX + a*ZZ^2 = 3*XX (因为 a=0)
// T = M^2 - 2*S
// X3 = T
// Y3 = M*(S-T) - 8*YYYY
// Z3 = 2*Y1*Z1
void jacobian_double(jacobian_point* r, const jacobian_point* p) {
    if (jacobian_is_infinity(p)) {
        *r = *p;
        return;
    }
    
    // 保存输入值，防止 r 和 p 指向同一地址时数据被覆盖
    jacobian_point in = *p;
    
    mp_number XX, YY, YYYY, ZZ, S, M, T;
    mp_number t1, t2;
    
    // XX = X1^2
    mp_mod_mul(&XX, &in.X, &in.X);
    // YY = Y1^2
    mp_mod_mul(&YY, &in.Y, &in.Y);
    // YYYY = YY^2
    mp_mod_mul(&YYYY, &YY, &YY);
    // ZZ = Z1^2
    mp_mod_mul(&ZZ, &in.Z, &in.Z);
    
    // S = 2*((X1+YY)^2 - XX - YYYY)
    mp_mod_add(&t1, &in.X, &YY);     // t1 = X1 + YY
    mp_mod_mul(&t2, &t1, &t1);       // t2 = (X1+YY)^2
    mp_mod_sub(&t1, &t2, &XX);       // t1 = (X1+YY)^2 - XX
    mp_mod_sub(&t2, &t1, &YYYY);     // t2 = (X1+YY)^2 - XX - YYYY
    mp_mod_add(&S, &t2, &t2);        // S = 2*((X1+YY)^2 - XX - YYYY)
    
    // M = 3*XX (因为 secp256k1 的 a=0)
    mp_mod_add(&t1, &XX, &XX);       // t1 = 2*XX
    mp_mod_add(&M, &t1, &XX);        // M = 3*XX
    
    // T = M^2 - 2*S
    mp_mod_mul(&t1, &M, &M);         // t1 = M^2
    mp_mod_add(&t2, &S, &S);         // t2 = 2*S
    mp_mod_sub(&T, &t1, &t2);        // T = M^2 - 2*S
    
    // X3 = T
    r->X = T;
    
    // Y3 = M*(S-T) - 8*YYYY
    mp_mod_sub(&t1, &S, &T);         // t1 = S - T
    mp_mod_mul(&t2, &M, &t1);        // t2 = M*(S-T)
    mp_number eight_YYYY;
    mp_mod_add(&eight_YYYY, &YYYY, &YYYY);  // 2*YYYY
    mp_mod_add(&t1, &eight_YYYY, &eight_YYYY); // 4*YYYY
    mp_mod_add(&eight_YYYY, &t1, &t1);     // 8*YYYY
    mp_mod_sub(&r->Y, &t2, &eight_YYYY);
    
    // Z3 = 2*Y1*Z1
    mp_mod_add(&t1, &in.Y, &in.Y);   // t1 = 2*Y1
    mp_mod_mul(&r->Z, &t1, &in.Z);   // Z3 = 2*Y1*Z1
}

// Jacobian 点加法: R = P + Q (Q 是仿射坐标点，Z=1)
// 混合加法公式 (madd-2007-bl) - 支持 __constant 地址空间
// 来源: http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl
void jacobian_add_affine_c(jacobian_point* r, const jacobian_point* p, const __constant point* q) {
    if (jacobian_is_infinity(p)) {
        affine_to_jacobian_c(r, q);
        return;
    }
    
    // 将 __constant point 复制到私有内存
    point q_private;
    q_private.x = q->x;
    q_private.y = q->y;
    
    // 检查 Q 是否为无穷远点
    mp_number zero = {{0,0,0,0,0,0,0,0}};
    if (mp_cmp(&q_private.x, &zero) == 0 && mp_cmp(&q_private.y, &zero) == 0) {
        *r = *p;
        return;
    }
    
    mp_number Z1Z1, Z1Z1Z1, U2, S2, H, HH, I, J, V;
    mp_number t1, t2;
    
    // Z1Z1 = Z1^2
    mp_mod_mul(&Z1Z1, &p->Z, &p->Z);
    // Z1Z1Z1 = Z1*Z1Z1
    mp_mod_mul(&Z1Z1Z1, &p->Z, &Z1Z1);
    // U2 = X2*Z1Z1
    mp_mod_mul(&U2, &q_private.x, &Z1Z1);
    // S2 = Y2*Z1Z1Z1
    mp_mod_mul(&S2, &q_private.y, &Z1Z1Z1);
    // H = U2-X1
    mp_mod_sub(&H, &U2, &p->X);
    
    // 检查 H 是否为 0（即 P 和 Q 有相同的 X 坐标）
    if (mp_cmp(&H, &zero) == 0) {
        // 需要判断 Y 的关系
        mp_number sumY;
        mp_mod_add(&sumY, &S2, &p->Y);  // sumY = S2 + Y1
        if (mp_cmp(&S2, &p->Y) == 0) {
            // S2 == Y1，则 Q = P，执行点加倍
            jacobian_double(r, p);
        } else if (mp_is_zero(&sumY)) {
            // S2 == -Y1，则 Q = -P，结果为无穷远点
            jacobian_set_infinity(r);
        } else {
            // 理论上不会发生，置为无穷远点
            jacobian_set_infinity(r);
        }
        return;
    }
    
    // HH = H^2
    mp_mod_mul(&HH, &H, &H);
    // I = 4*HH
    mp_mod_add(&t1, &HH, &HH);
    mp_mod_add(&I, &t1, &t1);
    // J = H*I
    mp_mod_mul(&J, &H, &I);
    // V = X1*I
    mp_mod_mul(&V, &p->X, &I);
    
    // t1 = 2*(S2-Y1)
    mp_mod_sub(&t1, &S2, &p->Y);
    mp_mod_add(&t2, &t1, &t1);
    
    // X3 = t2^2 - J - 2*V
    mp_mod_mul(&t1, &t2, &t2);
    mp_mod_sub(&t1, &t1, &J);
    mp_mod_sub(&t1, &t1, &V);
    mp_mod_sub(&r->X, &t1, &V);
    
    // Y3 = t2*(V-X3) - 2*Y1*J
    mp_mod_sub(&t1, &V, &r->X);
    mp_mod_mul(&V, &t2, &t1);
    mp_mod_mul(&t1, &p->Y, &J);
    mp_mod_add(&t2, &t1, &t1);
    mp_mod_sub(&r->Y, &V, &t2);
    
    // Z3 = (Z1+H)^2 - Z1Z1 - HH
    mp_mod_add(&t1, &p->Z, &H);
    mp_mod_mul(&t2, &t1, &t1);
    mp_mod_sub(&t1, &t2, &Z1Z1);
    mp_mod_sub(&r->Z, &t1, &HH);
}

// Jacobian 点加法: R = P + Q (Q 是仿射坐标点，Z=1) - 支持 __local 地址空间
// 这个版本直接使用 __local 内存中的预计算表，无需复制
void jacobian_add_affine_local(jacobian_point* r, const jacobian_point* p, const __local point* q) {
    if (jacobian_is_infinity(p)) {
        // 从 __local 复制到私有内存再转换
        point q_private;
        q_private.x = q->x;
        q_private.y = q->y;
        affine_to_jacobian(r, &q_private);
        return;
    }
    
    // 从 __local 复制到私有内存
    point q_private;
    q_private.x = q->x;
    q_private.y = q->y;
    
    // 检查 Q 是否为无穷远点
    mp_number zero = {{0,0,0,0,0,0,0,0}};
    if (mp_cmp(&q_private.x, &zero) == 0 && mp_cmp(&q_private.y, &zero) == 0) {
        *r = *p;
        return;
    }
    
    mp_number Z1Z1, Z1Z1Z1, U2, S2, H, HH, I, J, V;
    mp_number t1, t2;
    
    // Z1Z1 = Z1^2
    mp_mod_mul(&Z1Z1, &p->Z, &p->Z);
    // Z1Z1Z1 = Z1*Z1Z1
    mp_mod_mul(&Z1Z1Z1, &p->Z, &Z1Z1);
    // U2 = X2*Z1Z1
    mp_mod_mul(&U2, &q_private.x, &Z1Z1);
    // S2 = Y2*Z1Z1Z1
    mp_mod_mul(&S2, &q_private.y, &Z1Z1Z1);
    // H = U2-X1
    mp_mod_sub(&H, &U2, &p->X);
    
    // 检查 H 是否为 0（即 P 和 Q 有相同的 X 坐标）
    if (mp_cmp(&H, &zero) == 0) {
        // 需要判断 Y 的关系
        mp_number sumY;
        mp_mod_add(&sumY, &S2, &p->Y);  // sumY = S2 + Y1
        if (mp_cmp(&S2, &p->Y) == 0) {
            // S2 == Y1，则 Q = P，执行点加倍
            jacobian_double(r, p);
        } else if (mp_is_zero(&sumY)) {
            // S2 == -Y1，则 Q = -P，结果为无穷远点
            jacobian_set_infinity(r);
        } else {
            // 理论上不会发生，置为无穷远点
            jacobian_set_infinity(r);
        }
        return;
    }
    
    // HH = H^2
    mp_mod_mul(&HH, &H, &H);
    // I = 4*HH
    mp_mod_add(&t1, &HH, &HH);
    mp_mod_add(&I, &t1, &t1);
    // J = H*I
    mp_mod_mul(&J, &H, &I);
    // V = X1*I
    mp_mod_mul(&V, &p->X, &I);
    
    // t1 = 2*(S2-Y1)
    mp_mod_sub(&t1, &S2, &p->Y);
    mp_mod_add(&t2, &t1, &t1);
    
    // X3 = t2^2 - J - 2*V
    mp_mod_mul(&t1, &t2, &t2);
    mp_mod_sub(&t1, &t1, &J);
    mp_mod_sub(&t1, &t1, &V);
    mp_mod_sub(&r->X, &t1, &V);
    
    // Y3 = t2*(V-X3) - 2*Y1*J
    mp_mod_sub(&t1, &V, &r->X);
    mp_mod_mul(&V, &t2, &t1);
    mp_mod_mul(&t1, &p->Y, &J);
    mp_mod_add(&t2, &t1, &t1);
    mp_mod_sub(&r->Y, &V, &t2);
    
    // Z3 = (Z1+H)^2 - Z1Z1 - HH
    mp_mod_add(&t1, &p->Z, &H);
    mp_mod_mul(&t2, &t1, &t1);
    mp_mod_sub(&t1, &t2, &Z1Z1);
    mp_mod_sub(&r->Z, &t1, &HH);
}

// Jacobian 点加法: R = P + Q (Q 是仿射坐标点，Z=1) - 标准版本
void jacobian_add_affine(jacobian_point* r, const jacobian_point* p, const point* q) {
    if (jacobian_is_infinity(p)) {
        affine_to_jacobian(r, q);
        return;
    }
    
    // 检查 Q 是否为无穷远点
    mp_number zero = {{0,0,0,0,0,0,0,0}};
    if (mp_cmp(&q->x, &zero) == 0 && mp_cmp(&q->y, &zero) == 0) {
        *r = *p;
        return;
    }
    
    mp_number Z1Z1, Z1Z1Z1, U2, S2, H, HH, I, J, V;
    mp_number t1, t2;
    
    // Z1Z1 = Z1^2
    mp_mod_mul(&Z1Z1, &p->Z, &p->Z);
    // Z1Z1Z1 = Z1*Z1Z1
    mp_mod_mul(&Z1Z1Z1, &p->Z, &Z1Z1);
    // U2 = X2*Z1Z1
    mp_mod_mul(&U2, &q->x, &Z1Z1);
    // S2 = Y2*Z1Z1Z1
    mp_mod_mul(&S2, &q->y, &Z1Z1Z1);
    // H = U2-X1
    mp_mod_sub(&H, &U2, &p->X);
    
    // 检查 H 是否为 0（即 P 和 Q 有相同的 X 坐标）
    if (mp_cmp(&H, &zero) == 0) {
        // 需要判断 Y 的关系
        mp_number sumY;
        mp_mod_add(&sumY, &S2, &p->Y);  // sumY = S2 + Y1
        if (mp_cmp(&S2, &p->Y) == 0) {
            // S2 == Y1，则 Q = P，执行点加倍
            jacobian_double(r, p);
        } else if (mp_is_zero(&sumY)) {
            // S2 == -Y1，则 Q = -P，结果为无穷远点
            jacobian_set_infinity(r);
        } else {
            // 理论上不会发生，置为无穷远点
            jacobian_set_infinity(r);
        }
        return;
    }
    
    // HH = H^2
    mp_mod_mul(&HH, &H, &H);
    // I = 4*HH
    mp_mod_add(&t1, &HH, &HH);
    mp_mod_add(&I, &t1, &t1);
    // J = H*I
    mp_mod_mul(&J, &H, &I);
    // V = X1*I
    mp_mod_mul(&V, &p->X, &I);
    
    // t1 = 2*(S2-Y1)
    mp_mod_sub(&t1, &S2, &p->Y);
    mp_mod_add(&t2, &t1, &t1);
    
    // X3 = t2^2 - J - 2*V
    mp_mod_mul(&t1, &t2, &t2);
    mp_mod_sub(&t1, &t1, &J);
    mp_mod_sub(&t1, &t1, &V);
    mp_mod_sub(&r->X, &t1, &V);
    
    // Y3 = t2*(V-X3) - 2*Y1*J
    mp_mod_sub(&t1, &V, &r->X);
    mp_mod_mul(&V, &t2, &t1);
    mp_mod_mul(&t1, &p->Y, &J);
    mp_mod_add(&t2, &t1, &t1);
    mp_mod_sub(&r->Y, &V, &t2);
    
    // Z3 = (Z1+H)^2 - Z1Z1 - HH
    mp_mod_add(&t1, &p->Z, &H);
    mp_mod_mul(&t2, &t1, &t1);
    mp_mod_sub(&t1, &t2, &Z1Z1);
    mp_mod_sub(&r->Z, &t1, &HH);
}

// Jacobian 转仿射坐标
void jacobian_to_affine(point* r, const jacobian_point* p) {
    if (jacobian_is_infinity(p)) {
        // 无穷远点
        for (int i = 0; i < 8; i++) {
            r->x.d[i] = 0;
            r->y.d[i] = 0;
        }
        return;
    }
    
    // x = X / Z^2
    mp_number z_inv, z_inv2;
    z_inv = p->Z;
    mp_mod_inverse(&z_inv);          // z_inv = Z^-1
    mp_mod_mul(&z_inv2, &z_inv, &z_inv); // z_inv2 = Z^-2
    mp_mod_mul(&r->x, &p->X, &z_inv2);   // x = X * Z^-2
    
    // y = Y / Z^3
    mp_mod_mul(&z_inv2, &z_inv2, &z_inv); // z_inv2 = Z^-3
    mp_mod_mul(&r->y, &p->Y, &z_inv2);    // y = Y * Z^-3
}

// 椭圆曲线点加法
// 不处理共享 X 坐标的点
void point_add(point * const r, point * const p, point * const o) {
	mp_number tmp;
	mp_number newX;
	mp_number newY;

	mp_mod_sub(&tmp, &o->x, &p->x);

	mp_mod_inverse(&tmp);

	mp_mod_sub(&newX, &o->y, &p->y);
	mp_mod_mul(&tmp, &tmp, &newX);

	mp_mod_mul(&newX, &tmp, &tmp);
	mp_mod_sub(&newX, &newX, &p->x);
	mp_mod_sub(&newX, &newX, &o->x);

	mp_mod_sub(&newY, &p->x, &newX);
	mp_mod_mul(&newY, &newY, &tmp);
	mp_mod_sub(&newY, &newY, &p->y);

	r->x = newX;
	r->y = newY;
}

// 标量乘法: result = scalar * G
// 使用双倍-加法算法，基于仿射坐标
void scalar_mult_base(const uchar scalar[32], uchar result[65]) {
    point r;
    mp_from_bytes(scalar, &r.x);
    
    // 如果私钥为零，返回无穷远点
    if (mp_is_zero(&r.x)) {
        result[0] = 0x04;
        for (int i = 1; i < 65; i++) result[i] = 0;
        return;
    }
    
    // 使用双倍-加法算法
    // 预计算: G, 2G, 4G, 8G, ...
    point g;
    g.x = Gx;
    g.y = Gy;
    
    // 结果初始化为无穷远点
    mp_number rx = { {0} };
    mp_number ry = { {0} };
    
    // 从最高位到最低位处理
    for (int i = 0; i < 32; i++) {
        uchar byte = scalar[i];
        for (int j = 7; j >= 0; j--) {
            // 点加倍: r = 2*r
            if (!(rx.d[0] == 0 && rx.d[1] == 0 && rx.d[2] == 0 && rx.d[3] == 0 &&
                  rx.d[4] == 0 && rx.d[5] == 0 && rx.d[6] == 0 && rx.d[7] == 0)) {
                // r 不是无穷远点，执行点加倍
                point rp;
                rp.x = rx;
                rp.y = ry;
                
                // 使用点加倍公式
                mp_number lambda, temp1, temp2, two_y;
                
                // temp1 = x^2
                mp_mod_mul(&temp1, &rx, &rx);
                
                // temp2 = 3 * x^2
                mp_mod_add(&temp2, &temp1, &temp1);
                mp_mod_add(&temp2, &temp2, &temp1);
                
                // two_y = 2 * y
                mp_mod_add(&two_y, &ry, &ry);
                
                // lambda = temp2 / two_y = temp2 * two_y^(-1)
                mp_mod_inverse(&two_y);
                mp_mod_mul(&lambda, &temp2, &two_y);
                
                // x_r = lambda^2 - 2*x
                mp_number lambda_sqr, two_x;
                mp_mod_mul(&lambda_sqr, &lambda, &lambda);
                mp_mod_add(&two_x, &rx, &rx);
                mp_mod_sub(&rx, &lambda_sqr, &two_x);
                
                // y_r = lambda * (x - x_r) - y
                mp_number x_diff;
                mp_mod_sub(&x_diff, &rp.x, &rx);
                mp_mod_mul(&temp1, &lambda, &x_diff);
                mp_mod_sub(&ry, &temp1, &rp.y);
            }
            
            // 如果当前位为 1，加上 G
            if ((byte >> j) & 1) {
                if (rx.d[0] == 0 && rx.d[1] == 0 && rx.d[2] == 0 && rx.d[3] == 0 &&
                    rx.d[4] == 0 && rx.d[5] == 0 && rx.d[6] == 0 && rx.d[7] == 0) {
                    // r 是无穷远点，直接设为 G
                    rx = g.x;
                    ry = g.y;
                } else {
                    // r = r + G
                    point rp, gp;
                    rp.x = rx;
                    rp.y = ry;
                    gp.x = g.x;
                    gp.y = g.y;
                    
                    point added;
                    point_add(&added, &rp, &gp);
                    rx = added.x;
                    ry = added.y;
                }
            }
        }
    }
    
    // 输出未压缩公钥格式: 0x04 + x(32字节) + y(32字节)
    result[0] = 0x04;
    mp_to_bytes(&rx, result + 1);
    mp_to_bytes(&ry, result + 33);
}

// 使用 Jacobian 射影坐标的标量乘法: result = scalar * G
// 基础版本：双倍-加法算法，每次点加/倍乘都涉及模乘和模逆（仅在最后转换时调用一次模逆）
void scalar_mult_base_jacobian(const uchar scalar[32], uchar result[65]) {
    // 如果私钥为零，返回无穷远点
    mp_number priv_key;
    mp_from_bytes(scalar, &priv_key);
    if (mp_is_zero(&priv_key)) {
        result[0] = 0x04;
        for (int i = 1; i < 65; i++) result[i] = 0;
        return;
    }
    
    // 基点 G 的仿射坐标
    point g_affine;
    g_affine.x = Gx;
    g_affine.y = Gy;
    
    // 结果初始化为无穷远点（Jacobian 坐标）
    jacobian_point r;
    jacobian_set_infinity(&r);
    
    // 从最高位到最低位处理
    for (int i = 0; i < 32; i++) {
        uchar byte = scalar[i];
        for (int j = 7; j >= 0; j--) {
            // 点加倍: r = 2*r (使用 Jacobian 坐标)
            if (!jacobian_is_infinity(&r)) {
                jacobian_double(&r, &r);
            }
            
            // 如果当前位为 1，加上 G
            if ((byte >> j) & 1) {
                if (jacobian_is_infinity(&r)) {
                    // r 是无穷远点，直接设为 G
                    affine_to_jacobian(&r, &g_affine);
                } else {
                    // r = r + G (混合加法)
                    jacobian_add_affine(&r, &r, &g_affine);
                }
            }
        }
    }
    
    // 转换回仿射坐标
    point result_affine;
    jacobian_to_affine(&result_affine, &r);
    
    // 输出未压缩公钥格式: 0x04 + x(32字节) + y(32字节)
    result[0] = 0x04;
    mp_to_bytes(&result_affine.x, result + 1);
    mp_to_bytes(&result_affine.y, result + 33);
}

// 使用预计算表的窗口标量乘法: result = scalar * G
// 优化版本：4-bit 窗口，使用预计算的奇数倍点表
// PRECOMPUTED_G[i] = (2*i + 1) * G, i = 0..15
// 将256位标量分成64个4-bit窗口，每窗口处理4次点加倍 + 1次点加
void scalar_mult_base_jacobian_windowed(const uchar scalar[32], uchar result[65]) {
    // 如果私钥为零，返回无穷远点
    mp_number priv_key;
    mp_from_bytes(scalar, &priv_key);
    if (mp_is_zero(&priv_key)) {
        result[0] = 0x04;
        for (int i = 1; i < 65; i++) result[i] = 0;
        return;
    }
    
    // 结果初始化为无穷远点（Jacobian 坐标）
    jacobian_point r;
    jacobian_set_infinity(&r);
    
    // 从最高位开始处理（大端序）
    // 256位 = 64个4-bit窗口，从最高有效窗口开始
    for (int i = 0; i < 32; i++) {
        // 每个字节分成两个4-bit窗口
        // 高4位
        uchar high_nibble = (scalar[i] >> 4) & 0x0F;
        // 低4位
        uchar low_nibble = scalar[i] & 0x0F;
        
        // 处理高4位窗口
        // 4次点加倍
        for (int j = 0; j < 4; j++) {
            if (!jacobian_is_infinity(&r)) {
                jacobian_double(&r, &r);
            }
        }
        // 如果窗口值非零，加上对应的预计算点
        if (high_nibble != 0) {
            // 将窗口值映射到预计算表索引
            // 窗口值 1..15 对应索引 0..7 (奇数: 1,3,5,...,15)
            // 窗口值 2..14 对应偶数，需要通过奇数点加倍得到
            uchar idx = (high_nibble - 1) >> 1;  // (high_nibble - 1) / 2
            if (high_nibble & 1) {
                // 奇数：直接使用预计算表
                if (jacobian_is_infinity(&r)) {
                    affine_to_jacobian_c(&r, &PRECOMPUTED_G[idx]);
                } else {
                    jacobian_add_affine_c(&r, &r, &PRECOMPUTED_G[idx]);
                }
            } else {
                // 偶数：使用预计算点加倍
                // 例如 2*G = 2*(1*G)，4*G = 2*(2*G) 等
                // 这里简化处理：使用 (high_nibble/2) * G 然后加倍
                jacobian_point temp;
                affine_to_jacobian_c(&temp, &PRECOMPUTED_G[idx]);
                jacobian_double(&temp, &temp);
                if (jacobian_is_infinity(&r)) {
                    r = temp;
                } else {
                    // 将 temp 转回仿射坐标再混合加法
                    point temp_affine;
                    jacobian_to_affine(&temp_affine, &temp);
                    jacobian_add_affine(&r, &r, &temp_affine);
                }
            }
        }
        
        // 处理低4位窗口
        // 4次点加倍
        for (int j = 0; j < 4; j++) {
            if (!jacobian_is_infinity(&r)) {
                jacobian_double(&r, &r);
            }
        }
        // 如果窗口值非零，加上对应的预计算点
        if (low_nibble != 0) {
            uchar idx = (low_nibble - 1) >> 1;
            if (low_nibble & 1) {
                // 奇数
                if (jacobian_is_infinity(&r)) {
                    affine_to_jacobian_c(&r, &PRECOMPUTED_G[idx]);
                } else {
                    jacobian_add_affine_c(&r, &r, &PRECOMPUTED_G[idx]);
                }
            } else {
                // 偶数
                jacobian_point temp;
                affine_to_jacobian_c(&temp, &PRECOMPUTED_G[idx]);
                jacobian_double(&temp, &temp);
                if (jacobian_is_infinity(&r)) {
                    r = temp;
                } else {
                    point temp_affine;
                    jacobian_to_affine(&temp_affine, &temp);
                    jacobian_add_affine(&r, &r, &temp_affine);
                }
            }
        }
    }
    
    // 转换回仿射坐标
    point result_affine;
    jacobian_to_affine(&result_affine, &r);
    
    // 输出未压缩公钥格式: 0x04 + x(32字节) + y(32字节)
    result[0] = 0x04;
    mp_to_bytes(&result_affine.x, result + 1);
    mp_to_bytes(&result_affine.y, result + 33);
}

// 从私钥生成公钥
void private_to_public(const uchar private_key[32], uchar public_key[65]) {
    scalar_mult_base_jacobian(private_key, public_key);
}

// 测试函数：比较两种标量乘法的结果
// 返回 0 如果结果相同，1 如果不同
int test_scalar_mult_comparison(const uchar scalar[32]) {
    uchar result_affine[65];
    uchar result_jacobian[65];
    
    scalar_mult_base(scalar, result_affine);
    scalar_mult_base_jacobian(scalar, result_jacobian);
    
    for (int i = 0; i < 65; i++) {
        if (result_affine[i] != result_jacobian[i]) {
            return 1;  // 不同
        }
    }
    return 0;  // 相同
}

#endif // SECP256K1_CL
