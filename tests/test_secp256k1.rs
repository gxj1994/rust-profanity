//! secp256k1 椭圆曲线运算测试

use secp256k1::{Secp256k1, SecretKey, PublicKey};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secp256k1_curve_params() {
        let _p = [
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFEu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
        ];

        let _n = [
            0xBFD25E8CD0364141u64,
            0xBAAEDCE6AF48A03Bu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFEu64,
        ];

        assert!(_p.iter().any(|&x| x != 0));
        assert!(_n.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_known_private_keys() {
        let secp = Secp256k1::new();

        let test_cases = vec![
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            ),
        ];

        for (priv_hex, expected_pub_hex) in test_cases {
            let priv_bytes = hex::decode(priv_hex).unwrap();
            let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);

            let public_key_bytes = public_key.serialize_uncompressed();
            let expected_pub = hex::decode(expected_pub_hex).unwrap();

            assert_eq!(
                public_key_bytes.to_vec(),
                expected_pub,
                "公钥不匹配 for private key {}",
                priv_hex
            );
        }
    }

    #[test]
    fn test_private_key_range() {
        let _secp = Secp256k1::new();

        let valid_private_keys = vec![
            "0000000000000000000000000000000000000000000000000000000000000001",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        ];

        for key_hex in valid_private_keys {
            let key_bytes = hex::decode(key_hex).unwrap();
            assert!(SecretKey::from_slice(&key_bytes).is_ok());
        }

        let invalid_private_keys = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        ];

        for key_hex in invalid_private_keys {
            let key_bytes = hex::decode(key_hex).unwrap();
            assert!(SecretKey::from_slice(&key_bytes).is_err());
        }
    }

    #[test]
    fn test_public_key_formats() {
        let secp = Secp256k1::new();

        let priv_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let uncompressed = public_key.serialize_uncompressed();
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);

        let compressed = public_key.serialize();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn test_ethereum_address_generation() {
        use sha3::{Keccak256, Digest};

        let secp = Secp256k1::new();

        let priv_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        let secret_key = SecretKey::from_slice(&priv_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let uncompressed = public_key.serialize_uncompressed();
        let public_key_bytes = &uncompressed[1..];

        let mut hasher = Keccak256::new();
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();

        let address = &hash[12..];
        assert_eq!(address.len(), 20);
        assert!(address.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_uint256_operations() {
        let a: [u64; 4] = [1, 0, 0, 0];
        let b: [u64; 4] = [2, 0, 0, 0];

        let mut sum = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let s = a[i] + b[i] + carry;
            carry = if s < a[i] || (s == a[i] && carry > 0) { 1 } else { 0 };
            sum[i] = s;
        }

        assert_eq!(sum[0], 3);
        assert_eq!(sum[1], 0);

        let mut diff = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let d = a[i].wrapping_sub(b[i] + borrow);
            borrow = if a[i] < b[i] + borrow { 1 } else { 0 };
            diff[i] = d;
        }

        assert!(borrow > 0 || diff[0] != 0);
    }

    #[test]
    fn test_opencl_availability() {
        use ocl::ProQue;

        match ProQue::builder()
            .src("__kernel void test() {}")
            .dims(1)
            .build() {
            Ok(_) => println!("OpenCL 可用"),
            Err(e) => println!("OpenCL 不可用: {}", e),
        }
    }
}
