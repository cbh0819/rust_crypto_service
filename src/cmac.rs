//! CMAC (Cipher-based Message Authentication Code) 구현
//! NIST SP 800-38B / RFC 4493 준수
//!
//! AES를 기반으로 한 MAC 알고리즘.
//! CBC-MAC의 보안 취약점을 개선한 버전.
//!
//! 알고리즘:
//!   1. K1, K2 서브키 생성 (AES(key, 0^128) 기반)
//!   2. 메시지를 16바이트 블록으로 분할
//!   3. 마지막 블록에 K1 또는 K2 XOR
//!   4. CBC-MAC 계산

use crate::block::aes_encrypt_block;
use crate::key_schedule::KeySize;

// ═══════════════════════════════════════════════════════
// CMAC 서브키 생성
// ═══════════════════════════════════════════════════════

/// GF(2^128) 위의 x 곱셈 (CMAC 서브키 생성용)
/// CMAC의 기약 다항식: x^128 + x^7 + x^2 + x + 1 (Rb = 0x87)
fn gf128_double(block: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let msb = (block[0] & 0x80) != 0;
    // 왼쪽 시프트 1비트
    for i in 0..15 {
        result[i] = (block[i] << 1) | (block[i+1] >> 7);
    }
    result[15] = block[15] << 1;
    // MSB가 1이었으면 Rb(0x87) XOR
    if msb {
        result[15] ^= 0x87;
    }
    result
}

/// CMAC 서브키 K1, K2 생성
fn generate_subkeys(key: &[u8], key_size: KeySize) -> ([u8; 16], [u8; 16]) {
    // L = AES(key, 0^128)
    let l = aes_encrypt_block(&[0u8; 16], key, key_size);
    let k1 = gf128_double(&l);
    let k2 = gf128_double(&k1);
    (k1, k2)
}

// ═══════════════════════════════════════════════════════
// CMAC 계산
// ═══════════════════════════════════════════════════════

/// AES-CMAC 계산 (16바이트 태그)
///
/// # 인자
/// - `key`: AES 키
/// - `key_size`: AES-128/192/256
/// - `message`: 인증할 메시지 (임의 길이)
pub fn aes_cmac(key: &[u8], key_size: KeySize, message: &[u8]) -> [u8; 16] {
    let (k1, k2) = generate_subkeys(key, key_size);

    // 메시지를 16바이트 블록으로 분할
    let n_blocks = if message.is_empty() { 1 } else { (message.len() + 15) / 16 };
    let last_complete = !message.is_empty() && message.len() % 16 == 0;

    let mut x = [0u8; 16];

    for i in 0..n_blocks {
        let is_last = i == n_blocks - 1;

        let mut m_block = [0u8; 16];
        if is_last {
            if last_complete {
                // 마지막 블록이 완전한 경우: K1 XOR
                let start = i * 16;
                m_block.copy_from_slice(&message[start..start + 16]);
                for j in 0..16 { m_block[j] ^= k1[j]; }
            } else {
                // 마지막 블록이 불완전한 경우: 10* 패딩 후 K2 XOR
                let start = i * 16;
                let remaining = &message[start..];
                m_block[..remaining.len()].copy_from_slice(remaining);
                m_block[remaining.len()] = 0x80; // 1비트 + 0패딩
                for j in 0..16 { m_block[j] ^= k2[j]; }
            }
        } else {
            let start = i * 16;
            m_block.copy_from_slice(&message[start..start + 16]);
        }

        // CBC-MAC 단계: X = AES(X XOR M_i)
        for j in 0..16 { x[j] ^= m_block[j]; }
        x = aes_encrypt_block(&x, key, key_size);
    }

    x
}

/// CMAC 검증 (상수 시간 비교)
pub fn aes_cmac_verify(key: &[u8], key_size: KeySize, message: &[u8], tag: &[u8; 16]) -> bool {
    let expected = aes_cmac(key, key_size, message);
    expected.iter().zip(tag.iter())
        .fold(0u8, |acc, (&a, &b)| acc | (a ^ b)) == 0
}

// ═══════════════════════════════════════════════════════
// 테스트 (NIST SP 800-38B 부록 D 공식 벡터)
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::to_hex;

    const KEY128: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];

    // NIST SP 800-38B D.1 — 빈 메시지
    #[test]
    fn test_cmac_nist_d1_empty() {
        let tag = aes_cmac(&KEY128, KeySize::Aes128, &[]);
        assert_eq!(to_hex(&tag), "bb1d6929e95937287fa37d129b756746");
    }

    // NIST SP 800-38B D.2 — 16바이트 메시지 (정확히 1블록)
    #[test]
    fn test_cmac_nist_d2_one_block() {
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let tag = aes_cmac(&KEY128, KeySize::Aes128, &msg);
        assert_eq!(to_hex(&tag), "070a16b46b4d4144f79bdd9dd04a287c");
    }

    // NIST SP 800-38B D.3 — 40바이트 메시지 (불완전 마지막 블록)
    #[test]
    fn test_cmac_nist_d3_partial_block() {
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let tag = aes_cmac(&KEY128, KeySize::Aes128, &msg);
        assert_eq!(to_hex(&tag), "dfa66747de9ae63030ca32611497c827");
    }

    // NIST SP 800-38B D.4 — 64바이트 메시지 (완전한 4블록)
    #[test]
    fn test_cmac_nist_d4_four_blocks() {
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let tag = aes_cmac(&KEY128, KeySize::Aes128, &msg);
        assert_eq!(to_hex(&tag), "51f0bebf7e3b9d92fc49741779363cfe");
    }

    // AES-256 CMAC
    #[test]
    fn test_cmac_aes256() {
        let key = [0u8; 32];
        let msg = b"AES-256 CMAC test";
        let tag1 = aes_cmac(&key, KeySize::Aes256, msg);
        let tag2 = aes_cmac(&key, KeySize::Aes256, msg);
        assert_eq!(tag1, tag2); // 재현성
        assert_eq!(tag1.len(), 16);
    }

    // 검증 함수 테스트
    #[test]
    fn test_cmac_verify_valid() {
        let msg = b"verify this message";
        let tag = aes_cmac(&KEY128, KeySize::Aes128, msg);
        assert!(aes_cmac_verify(&KEY128, KeySize::Aes128, msg, &tag));
    }

    #[test]
    fn test_cmac_verify_tampered() {
        let msg = b"original message";
        let tag = aes_cmac(&KEY128, KeySize::Aes128, msg);
        assert!(!aes_cmac_verify(&KEY128, KeySize::Aes128, b"tampered message", &tag));
    }

    // 서브키 생성 검증 (NIST D.1 서브키)
    #[test]
    fn test_cmac_subkeys_nist() {
        let (k1, k2) = generate_subkeys(&KEY128, KeySize::Aes128);
        assert_eq!(to_hex(&k1), "fbeed618357133667c85e08f7236a8de");
        assert_eq!(to_hex(&k2), "f7ddac306ae266ccf90bc11ee46d513b");
    }

    // 메시지 변조 탐지
    #[test]
    fn test_cmac_detects_bit_flip() {
        let msg = b"important data!!";
        let tag = aes_cmac(&KEY128, KeySize::Aes128, msg);
        let mut tampered = msg.to_vec();
        tampered[0] ^= 0x01;
        assert!(!aes_cmac_verify(&KEY128, KeySize::Aes128, &tampered, &tag));
    }
}
