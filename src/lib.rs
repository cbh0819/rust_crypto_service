//! # rust_aes_lib
//!
//! 학습 목적의 순수 Rust AES 암호 라이브러리.
//! 외부 의존성 없이 AES-128/192/256과 6가지 운영 모드를 직접 구현합니다.
//!
//! ## 지원 운영 모드
//! | 모드 | 패딩 | 병렬 | 랜덤접근 | 용도 |
//! |------|------|------|----------|------|
//! | ECB  | ✅   | ✅   | ✅       | 학습 전용 (보안 취약) |
//! | CBC  | ✅   | ❌   | ❌       | 범용 블록 암호화 |
//! | CFB8 | ❌   | ❌   | ❌       | 바이트 스트림 |
//! | CFB128 | ❌ | ❌   | ❌       | 블록 스트림 |
//! | OFB  | ❌   | ❌   | ❌       | 오류 전파 없는 스트림 |
//! | CTR  | ❌   | ✅   | ✅       | 고성능 스트림 |
//!
//! ⚠️ **보안 경고**: 학습 목적 전용. 프로덕션에는 `ring`, `aes` crate 사용 권장.

mod constants;
mod gf;
mod key_schedule;
mod block;
mod padding;
mod modes;

// ── 공개 타입 ──
pub use key_schedule::KeySize;

// ── 저수준 블록 API ──
pub use block::{aes_encrypt_block, aes_decrypt_block};

// ── 운영 모드 API ──
pub use modes::{
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    cfb8_encrypt, cfb8_decrypt,
    cfb128_encrypt, cfb128_decrypt,
    ofb_encrypt, ofb_decrypt,
    ctr_encrypt, ctr_decrypt, ctr_process,
};

// ── 편의 함수 (AES-128) ──

pub fn aes128_ecb_encrypt(pt: &[u8], key: &[u8; 16]) -> Vec<u8> {
    ecb_encrypt(pt, key, KeySize::Aes128)
}
pub fn aes128_ecb_decrypt(ct: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    ecb_decrypt(ct, key, KeySize::Aes128)
}
pub fn aes128_cbc_encrypt(pt: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    cbc_encrypt(pt, key, KeySize::Aes128, iv)
}
pub fn aes128_cbc_decrypt(ct: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    cbc_decrypt(ct, key, KeySize::Aes128, iv)
}
pub fn aes128_cfb8_encrypt(pt: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    cfb8_encrypt(pt, key, KeySize::Aes128, iv)
}
pub fn aes128_cfb8_decrypt(ct: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    cfb8_decrypt(ct, key, KeySize::Aes128, iv)
}
pub fn aes128_cfb128_encrypt(pt: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    cfb128_encrypt(pt, key, KeySize::Aes128, iv)
}
pub fn aes128_cfb128_decrypt(ct: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    cfb128_decrypt(ct, key, KeySize::Aes128, iv)
}
pub fn aes128_ofb_encrypt(pt: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    ofb_encrypt(pt, key, KeySize::Aes128, iv)
}
pub fn aes128_ofb_decrypt(ct: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    ofb_decrypt(ct, key, KeySize::Aes128, iv)
}
pub fn aes128_ctr_encrypt(pt: &[u8], key: &[u8; 16], nonce: &[u8; 12]) -> Vec<u8> {
    ctr_encrypt(pt, key, KeySize::Aes128, nonce)
}
pub fn aes128_ctr_decrypt(ct: &[u8], key: &[u8; 16], nonce: &[u8; 12]) -> Vec<u8> {
    ctr_decrypt(ct, key, KeySize::Aes128, nonce)
}

// ── 편의 함수 (AES-256) ──

pub fn aes256_cbc_encrypt(pt: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    cbc_encrypt(pt, key, KeySize::Aes256, iv)
}
pub fn aes256_cbc_decrypt(ct: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    cbc_decrypt(ct, key, KeySize::Aes256, iv)
}
pub fn aes256_ctr_encrypt(pt: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    ctr_encrypt(pt, key, KeySize::Aes256, nonce)
}
pub fn aes256_ctr_decrypt(ct: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    ctr_decrypt(ct, key, KeySize::Aes256, nonce)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_all_modes_aes128_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x13u8; 16];
        let nonce = [0x37u8; 12];
        let msg = b"Integration test for all six AES modes!";

        // ECB
        let ct = aes128_ecb_encrypt(msg, &key);
        assert_eq!(aes128_ecb_decrypt(&ct, &key).unwrap(), msg);

        // CBC
        let ct = aes128_cbc_encrypt(msg, &key, &iv);
        assert_eq!(aes128_cbc_decrypt(&ct, &key, &iv).unwrap(), msg);

        // CFB8
        let ct = aes128_cfb8_encrypt(msg, &key, &iv);
        assert_eq!(aes128_cfb8_decrypt(&ct, &key, &iv), msg.as_ref());

        // CFB128
        let ct = aes128_cfb128_encrypt(msg, &key, &iv);
        assert_eq!(aes128_cfb128_decrypt(&ct, &key, &iv), msg.as_ref());

        // OFB
        let ct = aes128_ofb_encrypt(msg, &key, &iv);
        assert_eq!(aes128_ofb_decrypt(&ct, &key, &iv), msg.as_ref());

        // CTR
        let ct = aes128_ctr_encrypt(msg, &key, &nonce);
        assert_eq!(aes128_ctr_decrypt(&ct, &key, &nonce), msg.as_ref());
    }

    #[test]
    fn test_aes256_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let nonce = [0u8; 12];
        let msg = b"AES-256 all modes test!";

        let ct = aes256_cbc_encrypt(msg, &key, &iv);
        assert_eq!(aes256_cbc_decrypt(&ct, &key, &iv).unwrap(), msg);

        let ct = aes256_ctr_encrypt(msg, &key, &nonce);
        assert_eq!(aes256_ctr_decrypt(&ct, &key, &nonce), msg.as_ref());
    }

    #[test]
    fn test_stream_modes_no_padding() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let nonce = [0u8; 12];
        // 블록 크기의 배수가 아닌 입력
        let msg = b"13 bytes msg!";

        let cfb8_ct = aes128_cfb8_encrypt(msg, &key, &iv);
        let cfb_ct = aes128_cfb128_encrypt(msg, &key, &iv);
        let ofb_ct = aes128_ofb_encrypt(msg, &key, &iv);
        let ctr_ct = aes128_ctr_encrypt(msg, &key, &nonce);

        // 스트림 모드: 출력 길이 = 입력 길이 (패딩 없음)
        assert_eq!(cfb8_ct.len(), msg.len());
        assert_eq!(cfb_ct.len(), msg.len());
        assert_eq!(ofb_ct.len(), msg.len());
        assert_eq!(ctr_ct.len(), msg.len());
    }
}

// ── SHA-2 / SHA-3 ──
mod sha2;
mod sha3;

pub use sha2::{sha224, sha256, sha384, sha512, to_hex};
pub use sha3::{sha3_224, sha3_256, sha3_384, sha3_512};

// ── AES-GCM / AES-CCM ──
mod gcm;
mod ccm;

pub use gcm::{aes_gcm_encrypt, aes_gcm_decrypt, GcmEncrypted, GcmError};
pub use ccm::{aes_ccm_encrypt, aes_ccm_decrypt, CcmEncrypted, CcmError};

// ── HMAC / CMAC ──
mod hmac;
mod cmac;

pub use hmac::{
    hmac, hmac_verify, HashAlgorithm,
    hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512,
    hmac_sha3_224, hmac_sha3_256, hmac_sha3_384, hmac_sha3_512,
};
pub use cmac::{aes_cmac, aes_cmac_verify};
