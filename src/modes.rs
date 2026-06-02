use crate::block::{aes_encrypt_block, aes_decrypt_block};
use crate::key_schedule::KeySize;
use crate::padding::{pad, unpad, BLOCK_SIZE};

// ═══════════════════════════════════════════════════════
// ECB (Electronic Codebook)
// ═══════════════════════════════════════════════════════
// 각 블록을 독립적으로 암호화.
// ⚠️ 학습 전용: 동일 평문 블록 → 동일 암호문 블록 (패턴 노출)

/// ECB 암호화
pub fn ecb_encrypt(plaintext: &[u8], key: &[u8], key_size: KeySize) -> Vec<u8> {
    let padded = pad(plaintext);
    padded.chunks(BLOCK_SIZE)
        .flat_map(|chunk| {
            let block: [u8; 16] = chunk.try_into().unwrap();
            aes_encrypt_block(&block, key, key_size)
        })
        .collect()
}

/// ECB 복호화
pub fn ecb_decrypt(ciphertext: &[u8], key: &[u8], key_size: KeySize) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() % BLOCK_SIZE != 0 {
        return Err("ECB: 암호문 길이가 블록 크기의 배수가 아님");
    }
    let plaintext: Vec<u8> = ciphertext.chunks(BLOCK_SIZE)
        .flat_map(|chunk| {
            let block: [u8; 16] = chunk.try_into().unwrap();
            aes_decrypt_block(&block, key, key_size)
        })
        .collect();
    unpad(&plaintext)
}

// ═══════════════════════════════════════════════════════
// CBC (Cipher Block Chaining)
// ═══════════════════════════════════════════════════════
// 이전 암호문 블록과 XOR 후 암호화.
// IV는 16바이트, 매 암호화마다 랜덤 값 사용 권장.

/// CBC 암호화
pub fn cbc_encrypt(plaintext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    let padded = pad(plaintext);
    let mut prev = *iv;
    padded.chunks(BLOCK_SIZE)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            for i in 0..16 { block[i] = chunk[i] ^ prev[i]; }
            let enc = aes_encrypt_block(&block, key, key_size);
            prev = enc;
            enc
        })
        .collect()
}

/// CBC 복호화
pub fn cbc_decrypt(ciphertext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.is_empty() || ciphertext.len() % BLOCK_SIZE != 0 {
        return Err("CBC: 암호문 길이가 블록 크기의 배수가 아님");
    }
    let mut prev = *iv;
    let plaintext: Vec<u8> = ciphertext.chunks(BLOCK_SIZE)
        .flat_map(|chunk| {
            let block: [u8; 16] = chunk.try_into().unwrap();
            let dec = aes_decrypt_block(&block, key, key_size);
            let mut plain = [0u8; 16];
            for i in 0..16 { plain[i] = dec[i] ^ prev[i]; }
            prev = block;
            plain
        })
        .collect();
    unpad(&plaintext)
}

// ═══════════════════════════════════════════════════════
// CFB8 (Cipher Feedback, 8-bit segment)
// ═══════════════════════════════════════════════════════
// 1바이트 단위 스트림 암호화.
// Shift register: 암호화한 IV의 최상위 바이트 XOR 평문 1바이트 → 암호문
// 암호문을 shift register 오른쪽에 삽입.
// 패딩 불필요 (스트림 모드).

/// CFB8 암호화
pub fn cfb8_encrypt(plaintext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    let mut shift_reg = *iv;
    plaintext.iter().map(|&pt_byte| {
        // shift register를 암호화
        let enc = aes_encrypt_block(&shift_reg, key, key_size);
        // 최상위 1바이트와 XOR
        let ct_byte = pt_byte ^ enc[0];
        // shift register를 왼쪽으로 1바이트 시프트, 암호문 바이트를 오른쪽에 삽입
        shift_reg.rotate_left(1);
        shift_reg[15] = ct_byte;
        ct_byte
    }).collect()
}

/// CFB8 복호화
pub fn cfb8_decrypt(ciphertext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    let mut shift_reg = *iv;
    ciphertext.iter().map(|&ct_byte| {
        let enc = aes_encrypt_block(&shift_reg, key, key_size);
        let pt_byte = ct_byte ^ enc[0];
        // 복호화도 암호문 바이트를 shift register에 삽입 (암호화와 동일)
        shift_reg.rotate_left(1);
        shift_reg[15] = ct_byte;
        pt_byte
    }).collect()
}

// ═══════════════════════════════════════════════════════
// CFB128 (Cipher Feedback, 128-bit segment)
// ═══════════════════════════════════════════════════════
// 16바이트 블록 단위 CFB.
// 암호화한 shift register와 평문 블록 전체를 XOR.
// CFB8보다 효율적, 마지막 블록은 필요한 바이트만 사용 (패딩 불필요).

/// CFB128 암호화
pub fn cfb128_encrypt(plaintext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    let mut shift_reg = *iv;
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    for chunk in plaintext.chunks(BLOCK_SIZE) {
        let enc = aes_encrypt_block(&shift_reg, key, key_size);
        let mut ct_block = [0u8; 16];
        for (i, &pt_byte) in chunk.iter().enumerate() {
            ct_block[i] = pt_byte ^ enc[i];
        }
        ciphertext.extend_from_slice(&ct_block[..chunk.len()]);
        // 마지막 블록이 16바이트 미만이면 암호문 바이트만큼만 shift
        if chunk.len() == BLOCK_SIZE {
            shift_reg = ct_block;
        } else {
            // 마지막 불완전 블록: shift register 앞부분 제거, 암호문 삽입
            let ct_partial = &ct_block[..chunk.len()];
            let remaining = BLOCK_SIZE - chunk.len();
            shift_reg.rotate_left(chunk.len());
            shift_reg[remaining..].copy_from_slice(ct_partial);
        }
    }
    ciphertext
}

/// CFB128 복호화
pub fn cfb128_decrypt(ciphertext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    let mut shift_reg = *iv;
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        let enc = aes_encrypt_block(&shift_reg, key, key_size);
        let mut pt_block = [0u8; 16];
        let mut ct_block = [0u8; 16];
        for (i, &ct_byte) in chunk.iter().enumerate() {
            pt_block[i] = ct_byte ^ enc[i];
            ct_block[i] = ct_byte;
        }
        plaintext.extend_from_slice(&pt_block[..chunk.len()]);
        if chunk.len() == BLOCK_SIZE {
            shift_reg = ct_block;
        } else {
            let remaining = BLOCK_SIZE - chunk.len();
            shift_reg.rotate_left(chunk.len());
            shift_reg[remaining..].copy_from_slice(&ct_block[..chunk.len()]);
        }
    }
    plaintext
}

// ═══════════════════════════════════════════════════════
// OFB (Output Feedback)
// ═══════════════════════════════════════════════════════
// 키스트림을 IV → 암호화 → 암호화 → ... 로 독립적으로 생성.
// 평문/암호문이 키스트림 생성에 영향을 주지 않음.
// 장점: 비트 오류가 해당 위치에만 영향 (오류 전파 없음).
// 패딩 불필요 (스트림 모드).

/// OFB 암호화 (암호화와 복호화가 동일한 연산)
pub fn ofb_encrypt(plaintext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    ofb_process(plaintext, key, key_size, iv)
}

/// OFB 복호화 (ofb_encrypt와 동일)
pub fn ofb_decrypt(ciphertext: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    ofb_process(ciphertext, key, key_size, iv)
}

fn ofb_process(data: &[u8], key: &[u8], key_size: KeySize, iv: &[u8; 16]) -> Vec<u8> {
    let mut output_block = *iv;
    let mut result = Vec::with_capacity(data.len());

    for chunk in data.chunks(BLOCK_SIZE) {
        // IV(또는 이전 출력)를 암호화하여 키스트림 블록 생성
        output_block = aes_encrypt_block(&output_block, key, key_size);
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ output_block[i]);
        }
    }
    result
}

// ═══════════════════════════════════════════════════════
// CTR (Counter)
// ═══════════════════════════════════════════════════════
// Nonce + Counter를 암호화하여 키스트림 생성 후 XOR.
// 병렬 처리 가능, 랜덤 접근 가능.
// Nonce(12바이트) + Counter(4바이트) = 16바이트 counter block.
// 패딩 불필요 (스트림 모드).

/// CTR 암호화 (암호화와 복호화가 동일한 연산)
pub fn ctr_encrypt(plaintext: &[u8], key: &[u8], key_size: KeySize, nonce: &[u8; 12]) -> Vec<u8> {
    ctr_process(plaintext, key, key_size, nonce, 0)
}

/// CTR 복호화
pub fn ctr_decrypt(ciphertext: &[u8], key: &[u8], key_size: KeySize, nonce: &[u8; 12]) -> Vec<u8> {
    ctr_process(ciphertext, key, key_size, nonce, 0)
}

/// CTR 처리 (시작 카운터 지정 가능 — 랜덤 접근용)
pub fn ctr_process(data: &[u8], key: &[u8], key_size: KeySize, nonce: &[u8; 12], start_counter: u32) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());

    for (block_idx, chunk) in data.chunks(BLOCK_SIZE).enumerate() {
        let counter = start_counter.wrapping_add(block_idx as u32);
        // Counter block: nonce(12바이트) || counter(4바이트, big-endian)
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(nonce);
        counter_block[12..].copy_from_slice(&counter.to_be_bytes());

        let keystream = aes_encrypt_block(&counter_block, key, key_size);
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
    }
    result
}

// ═══════════════════════════════════════════════════════
// 테스트
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    const KEY128: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    const IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const NONCE: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                              0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];

    // ── ECB ──
    #[test]
    fn test_ecb_roundtrip() {
        let pt = b"ECB roundtrip test message here!";
        let ct = ecb_encrypt(pt, &KEY128, KeySize::Aes128);
        assert_eq!(ecb_decrypt(&ct, &KEY128, KeySize::Aes128).unwrap(), pt);
    }

    #[test]
    fn test_ecb_nist() {
        // NIST SP 800-38A ECB-AES128 첫 번째 블록
        let pt = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                  0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let expected = [0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
                        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97];
        let ct = ecb_encrypt(&pt, &KEY128, KeySize::Aes128);
        assert_eq!(&ct[..16], &expected);
    }

    // ── CBC ──
    #[test]
    fn test_cbc_roundtrip() {
        let pt = b"CBC roundtrip test message here!";
        let ct = cbc_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(cbc_decrypt(&ct, &KEY128, KeySize::Aes128, &IV).unwrap(), pt);
    }

    #[test]
    fn test_cbc_nist() {
        // NIST SP 800-38A CBC-AES128 첫 번째 블록
        let pt = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                  0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let expected = [0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
                        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d];
        let ct = cbc_encrypt(&pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(&ct[..16], &expected);
    }

    // ── CFB8 ──
    #[test]
    fn test_cfb8_roundtrip() {
        let pt = b"CFB8 stream mode test";
        let ct = cfb8_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(cfb8_decrypt(&ct, &KEY128, KeySize::Aes128, &IV), pt);
    }

    #[test]
    fn test_cfb8_nist() {
        // NIST SP 800-38A CFB8-AES128 처음 2바이트
        let pt = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                  0xae, 0x2d];
        let expected_first = [0x3b, 0x79];
        let ct = cfb8_encrypt(&pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(&ct[..2], &expected_first);
    }

    #[test]
    fn test_cfb8_no_padding_needed() {
        // CFB8은 임의 길이 입력 처리 가능
        let pt = b"odd";
        let ct = cfb8_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(ct.len(), 3); // 패딩 없이 동일 길이
        assert_eq!(cfb8_decrypt(&ct, &KEY128, KeySize::Aes128, &IV), pt);
    }

    // ── CFB128 ──
    #[test]
    fn test_cfb128_roundtrip() {
        let pt = b"CFB128 block feedback mode test!";
        let ct = cfb128_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(cfb128_decrypt(&ct, &KEY128, KeySize::Aes128, &IV), pt);
    }

    #[test]
    fn test_cfb128_nist() {
        // NIST SP 800-38A CFB128-AES128 첫 번째 블록
        let pt = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                  0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let expected = [0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,
                        0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a];
        let ct = cfb128_encrypt(&pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(&ct[..16], &expected);
    }

    #[test]
    fn test_cfb128_partial_block() {
        // 마지막 블록이 16바이트 미만인 경우
        let pt = b"partial block!"; // 14바이트
        let ct = cfb128_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(ct.len(), 14);
        assert_eq!(cfb128_decrypt(&ct, &KEY128, KeySize::Aes128, &IV), pt);
    }

    // ── OFB ──
    #[test]
    fn test_ofb_roundtrip() {
        let pt = b"OFB output feedback mode test!!!";
        let ct = ofb_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(ofb_decrypt(&ct, &KEY128, KeySize::Aes128, &IV), pt);
    }

    #[test]
    fn test_ofb_nist() {
        // NIST SP 800-38A OFB-AES128 첫 번째 블록
        let pt = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                  0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let expected = [0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,
                        0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a];
        let ct = ofb_encrypt(&pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(&ct[..16], &expected);
    }

    #[test]
    fn test_ofb_encrypt_eq_decrypt() {
        // OFB는 암호화와 복호화가 완전히 동일한 연산
        let pt = b"symmetric operation test";
        let ct = ofb_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        let ct2 = ofb_decrypt(pt, &KEY128, KeySize::Aes128, &IV);
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ofb_no_error_propagation() {
        // 암호문 1비트 오류 → 복호화 시 해당 위치 1비트만 오류
        let pt = b"error propagation test!!";
        let mut ct = ofb_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        ct[0] ^= 0x01; // 첫 바이트 1비트 반전
        let recovered = ofb_decrypt(&ct, &KEY128, KeySize::Aes128, &IV);
        // 첫 바이트만 다르고 나머지는 동일해야 함
        assert_ne!(recovered[0], pt[0]);
        assert_eq!(&recovered[1..], &pt[1..]);
    }

    // ── CTR ──
    #[test]
    fn test_ctr_roundtrip() {
        let pt = b"CTR counter mode test message!!!";
        let ct = ctr_encrypt(pt, &KEY128, KeySize::Aes128, &NONCE);
        assert_eq!(ctr_decrypt(&ct, &KEY128, KeySize::Aes128, &NONCE), pt);
    }

    #[test]
    fn test_ctr_partial_block() {
        // 임의 길이 입력 처리
        let pt = b"short";
        let ct = ctr_encrypt(pt, &KEY128, KeySize::Aes128, &NONCE);
        assert_eq!(ct.len(), 5);
        assert_eq!(ctr_decrypt(&ct, &KEY128, KeySize::Aes128, &NONCE), pt);
    }

    #[test]
    fn test_ctr_encrypt_eq_decrypt() {
        // CTR은 암호화와 복호화가 동일한 연산
        let pt = b"CTR symmetric test";
        let ct = ctr_encrypt(pt, &KEY128, KeySize::Aes128, &NONCE);
        let ct2 = ctr_decrypt(pt, &KEY128, KeySize::Aes128, &NONCE);
        assert_eq!(ct, ct2);
    }

    #[test]
    fn test_ctr_random_access() {
        // CTR은 블록 단위 랜덤 접근 가능
        let pt: Vec<u8> = (0..48).collect(); // 3블록
        let ct = ctr_encrypt(&pt, &KEY128, KeySize::Aes128, &NONCE);

        // 두 번째 블록(block_idx=1)만 별도로 복호화
        let block2_ct: [u8; 16] = ct[16..32].try_into().unwrap();
        let keystream = {
            let mut cb = [0u8; 16];
            cb[..12].copy_from_slice(&NONCE);
            cb[12..].copy_from_slice(&1u32.to_be_bytes()); // counter=1
            crate::block::aes_encrypt_block(&cb, &KEY128, KeySize::Aes128)
        };
        let block2_pt: Vec<u8> = block2_ct.iter().zip(keystream.iter()).map(|(a,b)| a^b).collect();
        assert_eq!(block2_pt, &pt[16..32]);
    }

    #[test]
    fn test_ctr_different_nonce_different_ciphertext() {
        let pt = b"same plaintext!!";
        let nonce2 = [0xffu8; 12];
        let ct1 = ctr_encrypt(pt, &KEY128, KeySize::Aes128, &NONCE);
        let ct2 = ctr_encrypt(pt, &KEY128, KeySize::Aes128, &nonce2);
        assert_ne!(ct1, ct2);
    }

    // ── 공통 ──
    #[test]
    fn test_all_modes_different_ciphertext() {
        // 동일 평문에 대해 각 모드는 서로 다른 암호문을 생성해야 함
        let pt = b"mode comparison test data here!!";
        let ecb_ct  = ecb_encrypt(pt, &KEY128, KeySize::Aes128);
        let cbc_ct  = cbc_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        let cfb8_ct = cfb8_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        let cfb_ct  = cfb128_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        let ofb_ct  = ofb_encrypt(pt, &KEY128, KeySize::Aes128, &IV);
        let ctr_ct  = ctr_encrypt(pt, &KEY128, KeySize::Aes128, &NONCE);

        assert_ne!(ecb_ct, cbc_ct);
        assert_ne!(cbc_ct, cfb8_ct);
        assert_ne!(cfb_ct, ofb_ct);
        assert_ne!(ofb_ct, ctr_ct);
    }
}
