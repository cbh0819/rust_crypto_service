use crate::constants::{SBOX, INV_SBOX};
use crate::gf::{gf_mul, xtime};
use crate::key_schedule::{KeySize, key_expansion, get_round_key};

/// AES State: 4x4 바이트 행렬
/// state[row][col] 형태로 접근
pub type State = [[u8; 4]; 4];

/// 바이트 슬라이스(16바이트)를 State 행렬로 변환
/// AES 명세: 열 우선(column-major) 순서로 배치
pub fn bytes_to_state(block: &[u8]) -> State {
    let mut state = [[0u8; 4]; 4];
    for col in 0..4 {
        for row in 0..4 {
            state[row][col] = block[col * 4 + row];
        }
    }
    state
}

/// State 행렬을 바이트 슬라이스로 변환
pub fn state_to_bytes(state: &State) -> [u8; 16] {
    let mut block = [0u8; 16];
    for col in 0..4 {
        for row in 0..4 {
            block[col * 4 + row] = state[row][col];
        }
    }
    block
}

/// SubBytes: S-Box를 이용한 바이트 치환
pub fn sub_bytes(state: &mut State) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }
}

/// InvSubBytes: 역 S-Box를 이용한 바이트 치환 (복호화용)
pub fn inv_sub_bytes(state: &mut State) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {
            *byte = INV_SBOX[*byte as usize];
        }
    }
}

/// ShiftRows: 각 행을 왼쪽으로 회전
/// 행 0: 0칸, 행 1: 1칸, 행 2: 2칸, 행 3: 3칸
pub fn shift_rows(state: &mut State) {
    // 행 1: 1칸 왼쪽 회전
    state[1].rotate_left(1);
    // 행 2: 2칸 왼쪽 회전
    state[2].rotate_left(2);
    // 행 3: 3칸 왼쪽 회전 (= 1칸 오른쪽 회전)
    state[3].rotate_left(3);
}

/// InvShiftRows: 각 행을 오른쪽으로 회전 (복호화용)
pub fn inv_shift_rows(state: &mut State) {
    state[1].rotate_right(1);
    state[2].rotate_right(2);
    state[3].rotate_right(3);
}

/// MixColumns: 각 열에 GF(2^8) 행렬 곱셈 적용
/// 곱셈 행렬:
/// | 2 3 1 1 |
/// | 1 2 3 1 |
/// | 1 1 2 3 |
/// | 3 1 1 2 |
pub fn mix_columns(state: &mut State) {
    for col in 0..4 {
        let s0 = state[0][col];
        let s1 = state[1][col];
        let s2 = state[2][col];
        let s3 = state[3][col];

        state[0][col] = xtime(s0) ^ gf_mul(s1, 3) ^ s2 ^ s3;
        state[1][col] = s0 ^ xtime(s1) ^ gf_mul(s2, 3) ^ s3;
        state[2][col] = s0 ^ s1 ^ xtime(s2) ^ gf_mul(s3, 3);
        state[3][col] = gf_mul(s0, 3) ^ s1 ^ s2 ^ xtime(s3);
    }
}

/// InvMixColumns: MixColumns의 역 연산 (복호화용)
/// 역 곱셈 행렬:
/// | 14  11  13   9 |
/// |  9  14  11  13 |
/// | 13   9  14  11 |
/// | 11  13   9  14 |
pub fn inv_mix_columns(state: &mut State) {
    for col in 0..4 {
        let s0 = state[0][col];
        let s1 = state[1][col];
        let s2 = state[2][col];
        let s3 = state[3][col];

        state[0][col] = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09);
        state[1][col] = gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d);
        state[2][col] = gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b);
        state[3][col] = gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e);
    }
}

/// AddRoundKey: 라운드 키와 XOR
pub fn add_round_key(state: &mut State, round_key: &[u8]) {
    for col in 0..4 {
        for row in 0..4 {
            state[row][col] ^= round_key[col * 4 + row];
        }
    }
}

/// AES 단일 블록 암호화 (16바이트)
pub fn aes_encrypt_block(plaintext: &[u8; 16], key: &[u8], key_size: KeySize) -> [u8; 16] {
    let expanded = key_expansion(key, key_size);
    let nr = key_size.rounds();

    let mut state = bytes_to_state(plaintext);

    // 초기 라운드 키 추가
    add_round_key(&mut state, get_round_key(&expanded, 0));

    // 메인 라운드 (1 ~ Nr-1)
    for round in 1..nr {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, get_round_key(&expanded, round));
    }

    // 최종 라운드 (MixColumns 없음)
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, get_round_key(&expanded, nr));

    state_to_bytes(&state)
}

/// AES 단일 블록 복호화 (16바이트)
pub fn aes_decrypt_block(ciphertext: &[u8; 16], key: &[u8], key_size: KeySize) -> [u8; 16] {
    let expanded = key_expansion(key, key_size);
    let nr = key_size.rounds();

    let mut state = bytes_to_state(ciphertext);

    // 마지막 라운드 키부터 시작
    add_round_key(&mut state, get_round_key(&expanded, nr));

    // 역 메인 라운드 (Nr-1 → 1)
    for round in (1..nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, get_round_key(&expanded, round));
        inv_mix_columns(&mut state);
    }

    // 최종 역 라운드
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, get_round_key(&expanded, 0));

    state_to_bytes(&state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_state_roundtrip() {
        let block: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let state = bytes_to_state(&block);
        let recovered = state_to_bytes(&state);
        assert_eq!(block, recovered);
    }

    #[test]
    fn test_sub_bytes_known() {
        // 0x00 → SBOX[0] = 0x63
        let mut state = [[0u8; 4]; 4];
        sub_bytes(&mut state);
        assert_eq!(state[0][0], 0x63);
    }

    #[test]
    fn test_sub_inv_sub_bytes() {
        let original: State = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08],
        ];
        let mut state = original;
        sub_bytes(&mut state);
        inv_sub_bytes(&mut state);
        assert_eq!(state, original, "SubBytes → InvSubBytes는 항등 변환이어야 함");
    }

    #[test]
    fn test_shift_inv_shift_rows() {
        let original: State = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0x27, 0xbf, 0xb4, 0x41],
            [0x11, 0x98, 0x5d, 0x52],
            [0xae, 0xf1, 0xe5, 0x30],
        ];
        let mut state = original;
        shift_rows(&mut state);
        inv_shift_rows(&mut state);
        assert_eq!(state, original, "ShiftRows → InvShiftRows는 항등 변환이어야 함");
    }

    #[test]
    fn test_shift_rows_nist() {
        // NIST FIPS 197 부록 B - ShiftRows 전후 값
        let mut state: State = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0x27, 0xbf, 0xb4, 0x41],
            [0x11, 0x98, 0x5d, 0x52],
            [0xae, 0xf1, 0xe5, 0x30],
        ];
        shift_rows(&mut state);
        // 행 0: 변화 없음
        assert_eq!(state[0], [0xd4, 0xe0, 0xb8, 0x1e]);
        // 행 1: 1칸 왼쪽 회전
        assert_eq!(state[1], [0xbf, 0xb4, 0x41, 0x27]);
        // 행 2: 2칸 왼쪽 회전
        assert_eq!(state[2], [0x5d, 0x52, 0x11, 0x98]);
        // 행 3: 3칸 왼쪽 회전
        assert_eq!(state[3], [0x30, 0xae, 0xf1, 0xe5]);
    }

    #[test]
    fn test_mix_inv_mix_columns() {
        let original: State = [
            [0xd4, 0xbf, 0x5d, 0x30],
            [0xe0, 0xb4, 0x52, 0xae],
            [0xb8, 0x41, 0x11, 0xf1],
            [0x1e, 0x27, 0x98, 0xe5],
        ];
        let mut state = original;
        mix_columns(&mut state);
        inv_mix_columns(&mut state);
        assert_eq!(state, original, "MixColumns → InvMixColumns는 항등 변환이어야 함");
    }

    /// NIST FIPS 197 부록 B - 전체 암호화 테스트
    #[test]
    fn test_aes128_encrypt_nist() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d,
            0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32,
        ];
        let ciphertext = aes_encrypt_block(&plaintext, &key, KeySize::Aes128);
        assert_eq!(ciphertext, expected);
    }

    /// NIST FIPS 197 복호화 테스트
    #[test]
    fn test_aes128_decrypt_nist() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d,
            0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97,
            0x19, 0x6a, 0x0b, 0x32,
        ];
        let expected: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2,
            0xe0, 0x37, 0x07, 0x34,
        ];
        let plaintext = aes_decrypt_block(&ciphertext, &key, KeySize::Aes128);
        assert_eq!(plaintext, expected);
    }

    /// 암호화 후 복호화 = 원본 (AES-128)
    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        let key = [0x00u8; 16];
        let plaintext = [0x42u8; 16];
        let ciphertext = aes_encrypt_block(&plaintext, &key, KeySize::Aes128);
        let recovered = aes_decrypt_block(&ciphertext, &key, KeySize::Aes128);
        assert_eq!(plaintext, recovered);
    }

    /// AES-256 NIST 테스트 벡터
    #[test]
    fn test_aes256_encrypt_nist() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca,
            0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90,
            0x4b, 0x49, 0x60, 0x89,
        ];
        let ciphertext = aes_encrypt_block(&plaintext, &key, KeySize::Aes256);
        assert_eq!(ciphertext, expected);
    }
}
