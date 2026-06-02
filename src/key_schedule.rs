use crate::constants::{SBOX, RCON};

/// AES 키 길이
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeySize {
    Aes128, // 128비트 = 16바이트, 10라운드
    Aes192, // 192비트 = 24바이트, 12라운드
    Aes256, // 256비트 = 32바이트, 14라운드
}

impl KeySize {
    /// 키 바이트 수 (Nk: 키 워드 수)
    pub fn key_len(&self) -> usize {
        match self {
            KeySize::Aes128 => 16,
            KeySize::Aes192 => 24,
            KeySize::Aes256 => 32,
        }
    }

    /// 라운드 수 (Nr)
    pub fn rounds(&self) -> usize {
        match self {
            KeySize::Aes128 => 10,
            KeySize::Aes192 => 12,
            KeySize::Aes256 => 14,
        }
    }

    /// 키 워드 수 (Nk = key_len / 4)
    pub fn nk(&self) -> usize {
        self.key_len() / 4
    }
}

/// 4바이트 워드에 S-Box 치환 적용
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ]
}

/// 4바이트 워드를 1바이트 왼쪽 회전
fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

/// AES 키 스케줄 (키 확장)
/// 입력 키로부터 라운드 키 배열 생성
/// 반환값: (Nr+1) * 4 개의 워드 = (라운드 수 + 1) * 16바이트
pub fn key_expansion(key: &[u8], key_size: KeySize) -> Vec<u8> {
    let nk = key_size.nk();       // 키 워드 수
    let nr = key_size.rounds();   // 라운드 수
    let total_words = 4 * (nr + 1); // 전체 확장 키 워드 수

    // 워드 배열 (각 워드 = 4바이트)
    let mut w: Vec<[u8; 4]> = Vec::with_capacity(total_words);

    // 처음 Nk개 워드는 원래 키에서 직접 복사
    for i in 0..nk {
        w.push([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
    }

    // 나머지 워드 생성
    for i in nk..total_words {
        let mut temp = w[i - 1];

        if i % nk == 0 {
            // RotWord → SubWord → XOR RCON
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            // AES-256에서만 추가 SubWord 적용
            temp = sub_word(temp);
        }

        // W[i] = W[i-Nk] XOR temp
        let prev = w[i - nk];
        w.push([
            prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3],
        ]);
    }

    // 워드 배열을 평탄화하여 바이트 슬라이스로 반환
    w.into_iter().flatten().collect()
}

/// 특정 라운드의 라운드 키 추출 (16바이트 블록)
pub fn get_round_key(expanded_key: &[u8], round: usize) -> &[u8] {
    &expanded_key[round * 16..(round + 1) * 16]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_key_expansion_length() {
        let key = [0u8; 16];
        let expanded = key_expansion(&key, KeySize::Aes128);
        // AES-128: (10+1) * 16 = 176바이트
        assert_eq!(expanded.len(), 176);
    }

    #[test]
    fn test_aes192_key_expansion_length() {
        let key = [0u8; 24];
        let expanded = key_expansion(&key, KeySize::Aes192);
        // AES-192: (12+1) * 16 = 208바이트
        assert_eq!(expanded.len(), 208);
    }

    #[test]
    fn test_aes256_key_expansion_length() {
        let key = [0u8; 32];
        let expanded = key_expansion(&key, KeySize::Aes256);
        // AES-256: (14+1) * 16 = 240바이트
        assert_eq!(expanded.len(), 240);
    }

    #[test]
    fn test_aes128_key_expansion_nist() {
        // NIST FIPS 197 부록 A.1 — AES-128 키 스케줄 검증
        let key = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88,
            0x09, 0xcf, 0x4f, 0x3c,
        ];
        let expanded = key_expansion(&key, KeySize::Aes128);

        // 라운드 키 1 검증 (w[4..7])
        let round1 = get_round_key(&expanded, 1);
        assert_eq!(round1, &[
            0xa0, 0xfa, 0xfe, 0x17,
            0x88, 0x54, 0x2c, 0xb1,
            0x23, 0xa3, 0x39, 0x39,
            0x2a, 0x6c, 0x76, 0x05,
        ]);
    }

    #[test]
    fn test_rot_word() {
        assert_eq!(rot_word([0x09, 0xcf, 0x4f, 0x3c]), [0xcf, 0x4f, 0x3c, 0x09]);
    }

    #[test]
    fn test_sub_word() {
        // 0x09 → SBOX[0x09] = 0x01
        let result = sub_word([0x09, 0xcf, 0x4f, 0x3c]);
        assert_eq!(result[0], SBOX[0x09]);
        assert_eq!(result[1], SBOX[0xcf]);
    }
}
