//! SHA-3 해시 함수 구현
//! NIST FIPS 202 준수 — Keccak-p[1600] 스폰지 구조
//! SHA3-224, SHA3-256, SHA3-384, SHA3-512 지원

// ═══════════════════════════════════════════════════════
// Keccak 상수
// ═══════════════════════════════════════════════════════

/// Keccak-f[1600] 라운드 상수 RC (24라운드)
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Keccak Rho 오프셋 (5×5 행렬, 행 우선)
const RHO: [u32; 25] = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
];

/// Keccak Pi 순열 인덱스
const PI: [usize; 25] = [
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
];

// ═══════════════════════════════════════════════════════
// Keccak-f[1600] 치환 함수
// ═══════════════════════════════════════════════════════

/// Keccak-f[1600]: 1600비트(25×u64) State에 24라운드 적용
fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..24 {
        // ── θ (Theta) ──
        // 각 열의 패리티 계산
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for i in 0..25 {
            state[i] ^= d[i % 5];
        }

        // ── ρ (Rho) + π (Pi) ──
        // ρ: 각 레인을 오프셋만큼 회전
        // π: 레인 위치 재배치
        let mut b = [0u64; 25];
        for i in 0..25 {
            b[PI[i]] = state[i].rotate_left(RHO[i]);
        }

        // ── χ (Chi) ──
        // 각 행에 비선형 변환 적용
        for y in 0..5 {
            for x in 0..5 {
                let i = y * 5 + x;
                state[i] = b[i] ^ ((!b[y*5 + (x+1)%5]) & b[y*5 + (x+2)%5]);
            }
        }

        // ── ι (Iota) ──
        // 라운드 상수 XOR
        state[0] ^= RC[round];
    }
}

// ═══════════════════════════════════════════════════════
// SHA-3 스폰지 구조
// ═══════════════════════════════════════════════════════

/// SHA-3 해시 범용 함수
/// rate: 블록 크기(바이트), output_len: 출력 길이(바이트)
/// SHA-3 도메인 분리 바이트: 0x06
fn sha3_hash(message: &[u8], rate: usize, output_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];

    // ── 흡수(Absorb) 단계 ──
    let mut padded = message.to_vec();

    // SHA-3 패딩: 메시지 || 0x06 || 0x00...0x00 || 0x80
    // (Keccak 원본은 0x01, SHA-3은 도메인 분리를 위해 0x06 사용)
    padded.push(0x06);
    while padded.len() % rate != 0 {
        padded.push(0x00);
    }
    // 마지막 바이트에 0x80 OR
    let last = padded.len() - 1;
    padded[last] |= 0x80;

    // rate 바이트 단위로 state에 XOR 후 Keccak-f 적용
    for block in padded.chunks(rate) {
        for (i, chunk) in block.chunks(8).enumerate() {
            if chunk.len() == 8 {
                state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
            } else {
                // 마지막 불완전 청크 처리
                let mut buf = [0u8; 8];
                buf[..chunk.len()].copy_from_slice(chunk);
                state[i] ^= u64::from_le_bytes(buf);
            }
        }
        keccak_f(&mut state);
    }

    // ── 압착(Squeeze) 단계 ──
    let mut output = Vec::with_capacity(output_len);
    let mut remaining = output_len;

    while remaining > 0 {
        let take = remaining.min(rate);
        for i in 0..(take + 7) / 8 {
            let bytes = state[i].to_le_bytes();
            let to_take = (take - i * 8).min(8);
            output.extend_from_slice(&bytes[..to_take]);
        }
        remaining = remaining.saturating_sub(take);
        if remaining > 0 {
            keccak_f(&mut state);
        }
    }

    output.truncate(output_len);
    output
}

// ═══════════════════════════════════════════════════════
// 공개 API
// ═══════════════════════════════════════════════════════

// SHA-3 rate = (1600 - 2*capacity) / 8
// SHA3-224: capacity=448, rate=144
// SHA3-256: capacity=512, rate=136
// SHA3-384: capacity=768, rate=104
// SHA3-512: capacity=1024, rate=72

/// SHA3-224 해시 계산 (28바이트)
pub fn sha3_224(message: &[u8]) -> [u8; 28] {
    let v = sha3_hash(message, 144, 28);
    v.try_into().unwrap()
}

/// SHA3-256 해시 계산 (32바이트)
pub fn sha3_256(message: &[u8]) -> [u8; 32] {
    let v = sha3_hash(message, 136, 32);
    v.try_into().unwrap()
}

/// SHA3-384 해시 계산 (48바이트)
pub fn sha3_384(message: &[u8]) -> [u8; 48] {
    let v = sha3_hash(message, 104, 48);
    v.try_into().unwrap()
}

/// SHA3-512 해시 계산 (64바이트)
pub fn sha3_512(message: &[u8]) -> [u8; 64] {
    let v = sha3_hash(message, 72, 64);
    v.try_into().unwrap()
}

// ═══════════════════════════════════════════════════════
// 테스트 (NIST FIPS 202 공식 벡터)
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::to_hex;

    // ── SHA3-256 ──
    #[test]
    fn test_sha3_256_empty() {
        let h = sha3_256(b"");
        assert_eq!(to_hex(&h), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    #[test]
    fn test_sha3_256_abc() {
        let h = sha3_256(b"abc");
        assert_eq!(to_hex(&h), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    #[test]
    fn test_sha3_256_long() {
        let h = sha3_256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(to_hex(&h), "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
    }

    // ── SHA3-224 ──
    #[test]
    fn test_sha3_224_empty() {
        let h = sha3_224(b"");
        assert_eq!(to_hex(&h), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    }

    #[test]
    fn test_sha3_224_abc() {
        let h = sha3_224(b"abc");
        assert_eq!(to_hex(&h), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    }

    // ── SHA3-384 ──
    #[test]
    fn test_sha3_384_empty() {
        let h = sha3_384(b"");
        assert_eq!(to_hex(&h), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    }

    #[test]
    fn test_sha3_384_abc() {
        let h = sha3_384(b"abc");
        assert_eq!(to_hex(&h), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    }

    // ── SHA3-512 ──
    #[test]
    fn test_sha3_512_empty() {
        let h = sha3_512(b"");
        assert_eq!(to_hex(&h), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    #[test]
    fn test_sha3_512_abc() {
        let h = sha3_512(b"abc");
        assert_eq!(to_hex(&h), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    }

    #[test]
    fn test_sha3_512_long() {
        let h = sha3_512(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(to_hex(&h), "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185");
    }
}
