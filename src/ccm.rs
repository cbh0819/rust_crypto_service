//! AES-CCM (Counter with CBC-MAC) 구현
//! NIST SP 800-38C / RFC 3610 준수
//!
//! CCM = CTR 모드 암호화 + CBC-MAC 인증
//! AEAD 방식이지만 GCM과 달리 순차 처리만 가능 (병렬 불가)
//!
//! 파라미터:
//!   - nonce(N): 7~13바이트 (L = 15 - len(N), 2~8바이트)
//!   - tag 길이(t): 4, 6, 8, 10, 12, 14, 16바이트 중 선택
//!   - 평문 최대 길이: 2^(8*L) 바이트

use crate::block::aes_encrypt_block;
use crate::key_schedule::KeySize;

// ═══════════════════════════════════════════════════════
// CCM 오류 타입
// ═══════════════════════════════════════════════════════

#[derive(Debug, PartialEq)]
pub enum CcmError {
    /// 인증 태그 검증 실패
    AuthTagMismatch,
    /// 잘못된 파라미터
    InvalidParam(&'static str),
}

impl core::fmt::Display for CcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CcmError::AuthTagMismatch => write!(f, "CCM 인증 태그 불일치"),
            CcmError::InvalidParam(msg) => write!(f, "잘못된 CCM 파라미터: {}", msg),
        }
    }
}

// ═══════════════════════════════════════════════════════
// CCM 파라미터 검증
// ═══════════════════════════════════════════════════════

/// CCM 파라미터 검증
fn validate_params(nonce: &[u8], tag_len: usize) -> Result<(), CcmError> {
    if nonce.len() < 7 || nonce.len() > 13 {
        return Err(CcmError::InvalidParam("nonce는 7~13바이트여야 함"));
    }
    if tag_len < 4 || tag_len > 16 || tag_len % 2 != 0 {
        return Err(CcmError::InvalidParam("tag 길이는 4~16 짝수여야 함"));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════
// CBC-MAC 계산
// ═══════════════════════════════════════════════════════

/// CCM CBC-MAC 포맷팅 블록 B0 생성
/// Flags | Nonce | Q (평문 길이)
fn format_b0(nonce: &[u8], aad_len: usize, pt_len: usize, tag_len: usize) -> [u8; 16] {
    let mut b0 = [0u8; 16];
    let l = 15 - nonce.len(); // 길이 필드 바이트 수 (2~8)
    let t = (tag_len - 2) / 2; // 인코딩된 태그 길이

    // Flags 바이트: 비트7=0, 비트6=aad존재, 비트5-3=t, 비트2-0=l-1
    let has_aad = if aad_len > 0 { 1u8 } else { 0u8 };
    b0[0] = (has_aad << 6) | ((t as u8) << 3) | ((l - 1) as u8);

    // Nonce
    b0[1..1 + nonce.len()].copy_from_slice(nonce);

    // 평문 길이 Q (l바이트, big-endian)
    let mut q = pt_len;
    for i in (15 - l + 1..=15).rev() {
        b0[i] = (q & 0xff) as u8;
        q >>= 8;
    }

    b0
}

/// AAD 인코딩 블록 생성 (CBC-MAC에 포함)
fn encode_aad(aad: &[u8]) -> Vec<u8> {
    if aad.is_empty() {
        return Vec::new();
    }
    let mut encoded = Vec::new();
    // aad 길이 인코딩 (65280 미만은 2바이트)
    let len = aad.len();
    if len < 0xff00 {
        encoded.push((len >> 8) as u8);
        encoded.push((len & 0xff) as u8);
    } else {
        // 더 큰 길이는 6바이트 인코딩 (학습 범위에서 단순화)
        encoded.extend_from_slice(&[0xff, 0xfe]);
        encoded.extend_from_slice(&(len as u32).to_be_bytes());
    }
    encoded.extend_from_slice(aad);
    // 16바이트 블록 경계에 맞게 0 패딩
    while encoded.len() % 16 != 0 {
        encoded.push(0x00);
    }
    encoded
}

/// CBC-MAC 계산
fn cbc_mac(key: &[u8], key_size: KeySize, blocks: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    for chunk in blocks.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 { x[i] ^= block[i]; }
        x = aes_encrypt_block(&x, key, key_size);
    }
    x
}

/// CCM 전체 CBC-MAC 입력 구성 및 태그 계산
fn compute_cbc_mac(
    key: &[u8],
    key_size: KeySize,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> [u8; 16] {
    let mut mac_input = Vec::new();

    // B0 블록
    mac_input.extend_from_slice(&format_b0(nonce, aad.len(), plaintext.len(), tag_len));

    // AAD 인코딩
    mac_input.extend_from_slice(&encode_aad(aad));

    // 평문 (16바이트 패딩)
    mac_input.extend_from_slice(plaintext);
    while mac_input.len() % 16 != 0 {
        mac_input.push(0x00);
    }

    cbc_mac(key, key_size, &mac_input)
}

// ═══════════════════════════════════════════════════════
// CTR 키스트림 생성 (CCM 전용)
// ═══════════════════════════════════════════════════════

/// CCM CTR 카운터 블록 A_i 생성
/// Flags | Nonce | Counter(i)
fn format_counter_block(nonce: &[u8], counter: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    let l = 15 - nonce.len();
    a[0] = (l - 1) as u8; // Flags: l-1
    a[1..1 + nonce.len()].copy_from_slice(nonce);
    // 카운터 (l바이트, big-endian)
    let mut c = counter;
    for i in (15 - l + 1..=15).rev() {
        a[i] = (c & 0xff) as u8;
        c >>= 8;
    }
    a
}

/// CCM CTR 암호화/복호화
fn ccm_ctr(key: &[u8], key_size: KeySize, nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let a = format_counter_block(nonce, i + 1); // A_1부터 시작 (A_0는 태그용)
        let ks = aes_encrypt_block(&a, key, key_size);
        for (j, &b) in chunk.iter().enumerate() {
            result.push(b ^ ks[j]);
        }
    }
    result
}

/// 태그 마스킹 (S_0 = AES(A_0) 앞 tag_len 바이트)
fn compute_s0(key: &[u8], key_size: KeySize, nonce: &[u8]) -> [u8; 16] {
    let a0 = format_counter_block(nonce, 0);
    aes_encrypt_block(&a0, key, key_size)
}

// ═══════════════════════════════════════════════════════
// AES-CCM 공개 API
// ═══════════════════════════════════════════════════════

/// AES-CCM 암호화 결과
pub struct CcmEncrypted {
    /// 암호문
    pub ciphertext: Vec<u8>,
    /// 인증 태그 (tag_len 바이트)
    pub tag: Vec<u8>,
}

/// AES-CCM 암호화
///
/// # 인자
/// - `plaintext`: 암호화할 평문
/// - `key`: AES 키
/// - `key_size`: AES-128/192/256
/// - `nonce`: 7~13바이트 고유 값
/// - `aad`: 추가 인증 데이터 (빈 슬라이스 가능)
/// - `tag_len`: 인증 태그 길이 (4/6/8/10/12/14/16)
pub fn aes_ccm_encrypt(
    plaintext: &[u8],
    key: &[u8],
    key_size: KeySize,
    nonce: &[u8],
    aad: &[u8],
    tag_len: usize,
) -> Result<CcmEncrypted, CcmError> {
    validate_params(nonce, tag_len)?;

    // CBC-MAC으로 인증 태그 계산
    let t = compute_cbc_mac(key, key_size, nonce, aad, plaintext, tag_len);

    // S_0 = AES(A_0)로 태그 마스킹
    let s0 = compute_s0(key, key_size, nonce);
    let mut tag = Vec::with_capacity(tag_len);
    for i in 0..tag_len {
        tag.push(t[i] ^ s0[i]);
    }

    // CTR 모드로 평문 암호화
    let ciphertext = ccm_ctr(key, key_size, nonce, plaintext);

    Ok(CcmEncrypted { ciphertext, tag })
}

/// AES-CCM 복호화 + 인증 태그 검증
pub fn aes_ccm_decrypt(
    ciphertext: &[u8],
    tag: &[u8],
    key: &[u8],
    key_size: KeySize,
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CcmError> {
    validate_params(nonce, tag.len())?;

    // CTR 복호화
    let plaintext = ccm_ctr(key, key_size, nonce, ciphertext);

    // CBC-MAC 재계산 (복호화된 평문으로)
    let t = compute_cbc_mac(key, key_size, nonce, aad, &plaintext, tag.len());

    // S_0으로 태그 마스킹 해제 후 비교
    let s0 = compute_s0(key, key_size, nonce);
    let expected: Vec<u8> = (0..tag.len()).map(|i| t[i] ^ s0[i]).collect();

    // 상수 시간 비교
    let tag_ok = tag.iter().zip(expected.iter())
        .fold(0u8, |acc, (&a, &b)| acc | (a ^ b)) == 0;

    if !tag_ok {
        return Err(CcmError::AuthTagMismatch);
    }

    Ok(plaintext)
}

// ═══════════════════════════════════════════════════════
// 테스트 (NIST SP 800-38C 공식 벡터)
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::to_hex;

    // NIST SP 800-38C 부록 C.1 (Example 1)
    #[test]
    fn test_ccm_nist_c1() {
        let key = [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
            0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
        ];
        let nonce = [0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5];
        let aad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let plaintext = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e];
        let expected_ct = "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384";
        let expected_tag = "50198bbc";

        let enc = aes_ccm_encrypt(&plaintext, &key, KeySize::Aes128, &nonce, &aad, 4).unwrap();
        assert_eq!(to_hex(&enc.ciphertext), expected_ct);
        assert_eq!(to_hex(&enc.tag), expected_tag);
    }

    // 라운드트립 테스트
    #[test]
    fn test_ccm_roundtrip_tag8() {
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 13];
        let aad = b"header";
        let plaintext = b"Hello, AES-CCM!";

        let enc = aes_ccm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, aad, 8).unwrap();
        let dec = aes_ccm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes128, &nonce, aad).unwrap();
        assert_eq!(dec, plaintext);
    }

    // 태그 길이 16바이트
    #[test]
    fn test_ccm_roundtrip_tag16() {
        let key = [0u8; 16];
        let nonce = [0u8; 13];
        let plaintext = b"CCM with max tag length test!!";

        let enc = aes_ccm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &[], 16).unwrap();
        assert_eq!(enc.tag.len(), 16);
        let dec = aes_ccm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes128, &nonce, &[]).unwrap();
        assert_eq!(dec, plaintext);
    }

    // AES-256
    #[test]
    fn test_ccm_aes256_roundtrip() {
        let key = [0u8; 32];
        let nonce = [0u8; 13];
        let aad = b"aes256 ccm aad";
        let plaintext = b"AES-256-CCM message";

        let enc = aes_ccm_encrypt(plaintext, &key, KeySize::Aes256, &nonce, aad, 8).unwrap();
        let dec = aes_ccm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes256, &nonce, aad).unwrap();
        assert_eq!(dec, plaintext);
    }

    // 암호문 위변조 탐지
    #[test]
    fn test_ccm_ciphertext_tamper_detected() {
        let key = [0u8; 16];
        let nonce = [0u8; 13];
        let plaintext = b"tamper test!!";

        let enc = aes_ccm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &[], 8).unwrap();
        let mut tampered = enc.ciphertext.clone();
        tampered[0] ^= 0x01;
        let result = aes_ccm_decrypt(&tampered, &enc.tag, &key, KeySize::Aes128, &nonce, &[]);
        assert_eq!(result, Err(CcmError::AuthTagMismatch));
    }

    // AAD 위변조 탐지
    #[test]
    fn test_ccm_aad_tamper_detected() {
        let key = [0u8; 16];
        let nonce = [0u8; 13];
        let plaintext = b"secret";
        let aad = b"valid aad";

        let enc = aes_ccm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, aad, 8).unwrap();
        let result = aes_ccm_decrypt(&enc.ciphertext, &enc.tag, &key, KeySize::Aes128, &nonce, b"tampered aad");
        assert_eq!(result, Err(CcmError::AuthTagMismatch));
    }

    // 잘못된 파라미터 거부
    #[test]
    fn test_ccm_invalid_nonce_length() {
        let key = [0u8; 16];
        let short_nonce = [0u8; 6]; // 최소 7바이트 필요
        let result = aes_ccm_encrypt(b"test", &key, KeySize::Aes128, &short_nonce, &[], 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_ccm_invalid_tag_length() {
        let key = [0u8; 16];
        let nonce = [0u8; 13];
        let result = aes_ccm_encrypt(b"test", &key, KeySize::Aes128, &nonce, &[], 3); // 최소 4
        assert!(result.is_err());
    }
}
