//! SHA-2 해시 함수 구현
//! NIST FIPS 180-4 준수
//! SHA-224, SHA-256, SHA-384, SHA-512 지원

// ═══════════════════════════════════════════════════════
// SHA-256/224 상수
// ═══════════════════════════════════════════════════════

/// SHA-256 라운드 상수 K
/// 처음 64개 소수의 세제곱근 소수 부분
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 초기 해시값 H0
/// 처음 8개 소수의 제곱근 소수 부분
const H256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-224 초기 해시값 H0
/// 9~16번째 소수의 제곱근 소수 부분
const H224_INIT: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

// ═══════════════════════════════════════════════════════
// SHA-512/384 상수
// ═══════════════════════════════════════════════════════

/// SHA-512 라운드 상수 K (80개)
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-512 초기 해시값
const H512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// SHA-384 초기 해시값
const H384_INIT: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

// ═══════════════════════════════════════════════════════
// SHA-256 구현
// ═══════════════════════════════════════════════════════

#[inline] fn ch32(x: u32, y: u32, z: u32) -> u32  { (x & y) ^ (!x & z) }
#[inline] fn maj32(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
#[inline] fn sigma0_256(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
#[inline] fn sigma1_256(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
#[inline] fn gamma0_256(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3) }
#[inline] fn gamma1_256(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10) }

/// SHA-256 메시지 패딩
/// 메시지 뒤에 1비트, 0비트들, 64비트 길이를 붙여 512비트 배수로 만듦
fn sha256_pad(message: &[u8]) -> Vec<u8> {
    let bit_len = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80); // 1비트 + 7개 0비트
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    padded
}

/// SHA-256 단일 512비트 블록 압축
fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    // 메시지 스케줄 W[0..64]
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i*4..i*4+4].try_into().unwrap());
    }
    for i in 16..64 {
        w[i] = gamma1_256(w[i-2])
            .wrapping_add(w[i-7])
            .wrapping_add(gamma0_256(w[i-15]))
            .wrapping_add(w[i-16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let t1 = h.wrapping_add(sigma1_256(e))
                  .wrapping_add(ch32(e, f, g))
                  .wrapping_add(K256[i])
                  .wrapping_add(w[i]);
        let t2 = sigma0_256(a).wrapping_add(maj32(a, b, c));
        h = g; g = f; f = e;
        e = d.wrapping_add(t1);
        d = c; c = b; b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-256 해시 계산 (32바이트)
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut state = H256_INIT;
    let padded = sha256_pad(message);
    for block in padded.chunks(64) {
        sha256_compress(&mut state, block);
    }
    let mut digest = [0u8; 32];
    for (i, &word) in state.iter().enumerate() {
        digest[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// SHA-224 해시 계산 (28바이트)
/// SHA-256과 동일하지만 초기값이 다르고 출력을 224비트로 자름
pub fn sha224(message: &[u8]) -> [u8; 28] {
    let mut state = H224_INIT;
    let padded = sha256_pad(message);
    for block in padded.chunks(64) {
        sha256_compress(&mut state, block);
    }
    let mut digest = [0u8; 28];
    for (i, &word) in state[..7].iter().enumerate() {
        digest[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

// ═══════════════════════════════════════════════════════
// SHA-512 구현
// ═══════════════════════════════════════════════════════

#[inline] fn ch64(x: u64, y: u64, z: u64) -> u64  { (x & y) ^ (!x & z) }
#[inline] fn maj64(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
#[inline] fn sigma0_512(x: u64) -> u64 { x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39) }
#[inline] fn sigma1_512(x: u64) -> u64 { x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41) }
#[inline] fn gamma0_512(x: u64) -> u64 { x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7) }
#[inline] fn gamma1_512(x: u64) -> u64 { x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6) }

/// SHA-512 메시지 패딩 (1024비트 블록)
fn sha512_pad(message: &[u8]) -> Vec<u8> {
    let bit_len = (message.len() as u128).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0x00);
    }
    // 128비트 길이 필드 (상위 64비트는 항상 0 — 실용적 메시지 범위)
    padded.extend_from_slice(&((bit_len >> 64) as u64).to_be_bytes());
    padded.extend_from_slice(&(bit_len as u64).to_be_bytes());
    padded
}

/// SHA-512 단일 1024비트 블록 압축
fn sha512_compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes(block[i*8..i*8+8].try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = gamma1_512(w[i-2])
            .wrapping_add(w[i-7])
            .wrapping_add(gamma0_512(w[i-15]))
            .wrapping_add(w[i-16]);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..80 {
        let t1 = h.wrapping_add(sigma1_512(e))
                  .wrapping_add(ch64(e, f, g))
                  .wrapping_add(K512[i])
                  .wrapping_add(w[i]);
        let t2 = sigma0_512(a).wrapping_add(maj64(a, b, c));
        h = g; g = f; f = e;
        e = d.wrapping_add(t1);
        d = c; c = b; b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-512 해시 계산 (64바이트)
pub fn sha512(message: &[u8]) -> [u8; 64] {
    let mut state = H512_INIT;
    let padded = sha512_pad(message);
    for block in padded.chunks(128) {
        sha512_compress(&mut state, block);
    }
    let mut digest = [0u8; 64];
    for (i, &word) in state.iter().enumerate() {
        digest[i*8..i*8+8].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// SHA-384 해시 계산 (48바이트)
pub fn sha384(message: &[u8]) -> [u8; 48] {
    let mut state = H384_INIT;
    let padded = sha512_pad(message);
    for block in padded.chunks(128) {
        sha512_compress(&mut state, block);
    }
    let mut digest = [0u8; 48];
    for (i, &word) in state[..6].iter().enumerate() {
        digest[i*8..i*8+8].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

// ═══════════════════════════════════════════════════════
// 헬퍼
// ═══════════════════════════════════════════════════════

/// 바이트 배열을 16진수 문자열로 변환
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ═══════════════════════════════════════════════════════
// 테스트 (NIST FIPS 180-4 공식 벡터)
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    // ── SHA-256 ──
    #[test]
    fn test_sha256_empty() {
        let h = sha256(b"");
        assert_eq!(to_hex(&h), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_abc() {
        let h = sha256(b"abc");
        assert_eq!(to_hex(&h), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        // 정확한 NIST 벡터

    }

    #[test]
    fn test_sha256_long() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let h = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(to_hex(&h), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn test_sha256_multiblock() {
        // 1000000개의 'a' → 여러 블록
        let msg = vec![b'a'; 1_000_000];
        let h = sha256(&msg);
        assert_eq!(to_hex(&h), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    // ── SHA-224 ──
    #[test]
    fn test_sha224_empty() {
        let h = sha224(b"");
        assert_eq!(to_hex(&h), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    }

    #[test]
    fn test_sha224_abc() {
        let h = sha224(b"abc");
        assert_eq!(to_hex(&h), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    }

    #[test]
    fn test_sha224_long() {
        let h = sha224(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(to_hex(&h), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    }

    // ── SHA-512 ──
    #[test]
    fn test_sha512_empty() {
        let h = sha512(b"");
        assert_eq!(to_hex(&h), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn test_sha512_abc() {
        let h = sha512(b"abc");
        assert_eq!(to_hex(&h), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    #[test]
    fn test_sha512_long() {
        let h = sha512(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(to_hex(&h), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    }

    // ── SHA-384 ──
    #[test]
    fn test_sha384_empty() {
        let h = sha384(b"");
        assert_eq!(to_hex(&h), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }

    #[test]
    fn test_sha384_abc() {
        let h = sha384(b"abc");
        assert_eq!(to_hex(&h), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    }

    #[test]
    fn test_sha384_long() {
        let h = sha384(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(to_hex(&h), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    }
}
