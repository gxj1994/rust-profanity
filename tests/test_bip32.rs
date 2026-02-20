//! BIP32 密钥派生测试

use secp256k1::{SecretKey, PublicKey, Secp256k1};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_to_public() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let public_key_bytes = public_key.serialize_uncompressed();
        assert_eq!(public_key_bytes.len(), 65);
        assert_eq!(public_key_bytes[0], 0x04);

        let expected_public = hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        ).unwrap();
        assert_eq!(public_key_bytes.to_vec(), expected_public);
    }

    #[test]
    fn test_private_to_public_2() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        ).unwrap();

        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let public_key_bytes = public_key.serialize_uncompressed();
        assert_eq!(public_key_bytes.len(), 65);
        assert!(public_key_bytes[1..33].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_invalid_private_key() {
        let invalid_key = [0u8; 32];
        assert!(SecretKey::from_slice(&invalid_key).is_err());
    }

    #[test]
    fn test_key_serialization() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        ).unwrap();
        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let secret_bytes = secret_key.secret_bytes();
        let public_bytes = public_key.serialize_uncompressed();

        let recovered_secret = SecretKey::from_slice(&secret_bytes).unwrap();
        let recovered_public = PublicKey::from_secret_key(&secp, &recovered_secret);

        assert_eq!(public_bytes.to_vec(), recovered_public.serialize_uncompressed().to_vec());
    }

    #[test]
    fn test_compressed_public_key() {
        let secp = Secp256k1::new();

        let private_key_bytes = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let compressed = public_key.serialize();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn test_hmac_sha512_master_key() {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = b"Bitcoin seed";

        let mut mac = HmacSha512::new_from_slice(key).unwrap();
        mac.update(&seed);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        assert_eq!(bytes.len(), 64);

        let _master_private_key = &bytes[..32];
        let _master_chain_code = &bytes[32..];
    }

    #[test]
    fn test_derivation_index() {
        let hardened_44: u32 = 0x8000002C;
        let hardened_60: u32 = 0x8000003C;
        let normal_0: u32 = 0x00000000;

        assert!(hardened_44 >= 0x80000000);
        assert!(hardened_60 >= 0x80000000);
        assert!(normal_0 < 0x80000000);

        assert_eq!(hardened_44, 2147483692);
        assert_eq!(hardened_60, 2147483708);
    }
}
