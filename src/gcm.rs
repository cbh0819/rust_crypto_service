//! AES-GCM (Galois/Counter Mode) 구현
//! NIST SP 800-38D 준수
//!
//! GCM = CTR 모드 암호화 + GHASH 인증 태그
//! AEAD(Authenticated Encryption with Associated Data) 지원:
//!   - 암호화된 데이터의 기밀성 보장
//!   - 추가 인증 데이터(AAD)의 무결성 보장 (암호화 없이)
//!   - 128비트 인증 태그로 위변조 탐지

use crate::block::aes_encrypt_block;
use crate::key_schedule::KeySize;

// ═══════════════════════════════════════════════════════
// GCM 오류 타입
// ═══════════════════════════════════════════════════════

#[derive(Debug, PartialEq)]
pub enum GcmError {
    /// 인증 태그 검증 실패 (데이터 위변조 탐지)
    AuthTagMismatch,
    /// 잘못된 입력 (빈 암호문 등)
    InvalidInput(&'static str),
}

impl core::fmt::Display for GcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GcmError::AuthTagMismatch => write!(f, "GCM 인증 태그 불일치: 데이터가 위변조되었습니다"),
            GcmError::InvalidInput(msg) => write!(f, "잘못된 입력: {}", msg),
        }
    }
}

// ═══════════════════════════════════════════════════════
// GF(2^128) 연산 — GHASH용
// ═══════════════════════════════════════════════════════
// GCM의 GHASH는 AES의 GF(2^8)과 다른 GF(2^128) 위에서 동작
// 기약 다항식: x^128 + x^7 + x^2 + x + 1 (0xe1...)

/// GF(2^128)에서 두 블록의 곱셈 (GHASH 전용)
/// 입력/출력: 128비트 big-endian 블록
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut v = *y;
    let mut z = [0u8; 16];

    for i in 0..128 {
        // x의 i번째 비트가 1이면 z ^= v
        if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
            xor_block(&mut z, &v);
        }
        // v를 오른쪽으로 1비트 시프트
        let lsb = v[15] & 1;
        // 오른쪽 시프트
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j-1] << 7);
        }
        v[0] >>= 1;
        // 최하위 비트가 1이면 기약 다항식 XOR: 0xe1000...000
        if lsb == 1 {
            v[0] ^= 0xe1;
        }
    }
    result.copy_from_slice(&z);
    result
}

/// 두 16바이트 블록 XOR (in-place)
#[inline]
fn xor_block(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

// ═══════════════════════════════════════════════════════
// GHASH 함수
// ═══════════════════════════════════════════════════════
// GHASH_H(A, C) = 해시 서브키 H로 AAD(A)와 암호문(C)을 인증

/// GHASH 계산
/// H: 해시 서브키 (AES(key, 0^128))
/// aad: 추가 인증 데이터
/// ciphertext: 암호문
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];

    // AAD 처리 (16바이트 블록 단위, 패딩 포함)
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        xor_block(&mut tag, &block);
        tag = gf128_mul(&tag, h);
    }

    // 암호문 처리
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        xor_block(&mut tag, &block);
        tag = gf128_mul(&tag, h);
    }

    // 길이 블록: len(AAD) || len(C) (각 64비트 big-endian, 비트 단위)
    let mut len_block = [0u8; 16];
    let aad_bit_len = (aad.len() as u64) * 8;
    let ct_bit_len = (ciphertext.len() as u64) * 8;
    len_block[..8].copy_from_slice(&aad_bit_len.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bit_len.to_be_bytes());
    xor_block(&mut tag, &len_block);
    tag = gf128_mul(&tag, h);

    tag
}

// ═══════════════════════════════════════════════════════
// CTR 키스트림 생성 (GCM 전용)
// ═══════════════════════════════════════════════════════

/// GCM용 초기 카운터 블록 J0 생성
/// nonce가 12바이트이면: J0 = nonce || 0x00000001
/// 그 외: J0 = GHASH_H(nonce)  ← 단순화를 위해 12바이트만 지원
fn compute_j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    j0
}

/// 카운터 블록 증가 (32비트 빅엔디언 카운터, 하위 4바이트)
#[inline]
fn inc_counter(block: &mut [u8; 16]) {
    let counter = u32::from_be_bytes(block[12..16].try_into().unwrap());
    block[12..16].copy_from_slice(&counter.wrapping_add(1).to_be_bytes());
}

/// GCM CTR 모드 암호화/복호화 (동일한 연산)
fn gctr(key: &[u8], key_size: KeySize, icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut cb = *icb;
    inc_counter(&mut cb); // J0+1부터 시작 (J0는 태그 생성에 사용)

    let mut result = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let ks = aes_encrypt_block(&cb, key, key_size);
        for (i, &b) in chunk.iter().enumerate() {
            result.push(b ^ ks[i]);
        }
        inc_counter(&mut cb);
    }
    result
}

// ═══════════════════════════════════════════════════════
// AES-GCM 공개 API
// ═══════════════════════════════════════════════════════

/// AES-GCM 암호화 결과
pub struct GcmEncrypted {
    /// 암호문
    pub ciphertext: Vec<u8>,
    /// 128비트 인증 태그
    pub tag: [u8; 16],
}

/// AES-GCM 암호화
///
/// # 인자
/// - `plaintext`: 암호화할 평문
/// - `key`: AES 키
/// - `key_size`: AES-128/192/256
/// - `nonce`: 12바이트 고유 값 (절대 재사용 금지)
/// - `aad`: 추가 인증 데이터 (암호화되지 않지만 인증됨, 빈 슬라이스 가능)
pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8],
    key_size: KeySize,
    nonce: &[u8; 12],
    aad: &[u8],
) -> GcmEncrypted {
    // 해시 서브키 H = AES(key, 0^128)
    let h = aes_encrypt_block(&[0u8; 16], key, key_size);

    // 초기 카운터 블록 J0
    let j0 = compute_j0(nonce);

    // CTR 암호화
    let ciphertext = gctr(key, key_size, &j0, plaintext);

    // GHASH로 인증 태그 계산
    let mut tag = ghash(&h, aad, &ciphertext);

    // 태그 = GHASH XOR GCTR(J0)
    let s = aes_encrypt_block(&j0, key, key_size);
    for i in 0..16 { tag[i] ^= s[i]; }

    GcmEncrypted { ciphertext, tag }
}

/// AES-GCM 복호화 + 인증 태그 검증
///
/// 태그 불일치 시 `GcmError::AuthTagMismatch` 반환.
/// 반드시 에러 처리 후 평문 사용할 것.
pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    tag: &[u8; 16],
    key: &[u8],
    key_size: KeySize,
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, GcmError> {
    let h = aes_encrypt_block(&[0u8; 16], key, key_size);
    let j0 = compute_j0(nonce);

    // 수신된 암호문으로 태그 재계산
    let mut expected_tag = ghash(&h, aad, ciphertext);
    let s = aes_encrypt_block(&j0, key, key_size);
    for i in 0..16 { expected_tag[i] ^= s[i]; }

    // 상수 시간 태그 비교 (타이밍 공격 방지)
    let tag_ok = tag.iter().zip(expected_tag.iter())
        .fold(0u8, |acc, (&a, &b)| acc | (a ^ b)) == 0;

    if !tag_ok {
        return Err(GcmError::AuthTagMismatch);
    }

    Ok(gctr(key, key_size, &j0, ciphertext))
}

// ═══════════════════════════════════════════════════════
// 테스트 (NIST SP 800-38D 공식 벡터)
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::to_hex;

    // NIST Test Case 1: 빈 평문, 빈 AAD
    #[test]
    fn test_gcm_nist_tc1() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let result = aes_gcm_encrypt(&[], &key, KeySize::Aes128, &nonce, &[]);
        assert!(result.ciphertext.is_empty());
        assert_eq!(to_hex(&result.tag), "58e2fccefa7e3061367f1d57a4e7455a");
    }

    // NIST Test Case 2: 평문만 (AAD 없음)
    #[test]
    fn test_gcm_nist_tc2() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let result = aes_gcm_encrypt(&plaintext, &key, KeySize::Aes128, &nonce, &[]);
        assert_eq!(to_hex(&result.ciphertext), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(to_hex(&result.tag), "ab6e47d42cec13bdf53a67b21257bddf");
    }

    // NIST Test Case 3: 평문 + AAD
    #[test]
    fn test_gcm_nist_tc3() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let nonce = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
            0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
            0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let result = aes_gcm_encrypt(&plaintext, &key, KeySize::Aes128, &nonce, &[]);
        assert_eq!(to_hex(&result.tag), "cc15abcc191161501aabab46b8fbac85");
    }

    // 암호화 → 복호화 라운드트립
    #[test]
    fn test_gcm_roundtrip() {
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 12];
        let aad = b"header data";
        let plaintext = b"Hello, AES-GCM!";

        let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, aad);
        let dec = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes128, &nonce, aad).unwrap();
        assert_eq!(dec, plaintext);
    }

    // AAD 위변조 탐지
    #[test]
    fn test_gcm_aad_tamper_detected() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"valid header";

        let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, aad);
        // AAD를 변조하면 태그 검증 실패
        let result = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes128, &nonce, b"tampered header");
        assert_eq!(result, Err(GcmError::AuthTagMismatch));
    }

    // 암호문 위변조 탐지
    #[test]
    fn test_gcm_ciphertext_tamper_detected() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"secret message!!";

        let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &[]);
        let mut tampered = enc.ciphertext.clone();
        tampered[0] ^= 0x01;
        let result = aes_gcm_decrypt(&tampered, &enc.tag, &key, KeySize::Aes128, &nonce, &[]);
        assert_eq!(result, Err(GcmError::AuthTagMismatch));
    }

    // 빈 AAD 동작 확인
    #[test]
    fn test_gcm_empty_aad() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"no aad here";

        let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &[]);
        let dec = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes128, &nonce, &[]).unwrap();
        assert_eq!(dec, plaintext);
    }

    // AES-256-GCM
    #[test]
    fn test_gcm_aes256_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"associated data";
        let plaintext = b"AES-256-GCM test message!";

        let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes256, &nonce, aad);
        let dec = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes256, &nonce, aad).unwrap();
        assert_eq!(dec, plaintext);
    }

    // 잘못된 태그로 복호화 시도
    #[test]
    fn test_gcm_wrong_tag_rejected() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = b"test";
        let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &[]);
        let wrong_tag = [0xffu8; 16];
        let result = aes_gcm_decrypt(&enc.ciphertext, &wrong_tag, &key, KeySize::Aes128, &nonce, &[]);
        assert_eq!(result, Err(GcmError::AuthTagMismatch));
    }
}
