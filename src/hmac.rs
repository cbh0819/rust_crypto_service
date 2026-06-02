//! HMAC (Hash-based Message Authentication Code) 구현
//! NIST FIPS 198-1 준수
//!
//! HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
//!   K': 블록 크기에 맞게 조정된 키
//!   ipad: 0x36 반복
//!   opad: 0x5c 반복

use crate::sha2::{sha224, sha256, sha384, sha512};
use crate::sha3::{sha3_224, sha3_256, sha3_384, sha3_512};

// ═══════════════════════════════════════════════════════
// HMAC 범용 구현
// ═══════════════════════════════════════════════════════

/// 지원하는 해시 함수 종류
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    /// 해시 함수의 블록 크기 (바이트)
    pub fn block_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha224  | HashAlgorithm::Sha256   => 64,
            HashAlgorithm::Sha384  | HashAlgorithm::Sha512   => 128,
            HashAlgorithm::Sha3_224 => 144,
            HashAlgorithm::Sha3_256 => 136,
            HashAlgorithm::Sha3_384 => 104,
            HashAlgorithm::Sha3_512 => 72,
        }
    }

    /// 해시 출력 길이 (바이트)
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha224  | HashAlgorithm::Sha3_224 => 28,
            HashAlgorithm::Sha256  | HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha384  | HashAlgorithm::Sha3_384 => 48,
            HashAlgorithm::Sha512  | HashAlgorithm::Sha3_512 => 64,
        }
    }

    /// 해시 함수 실행
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha224   => sha224(data).to_vec(),
            HashAlgorithm::Sha256   => sha256(data).to_vec(),
            HashAlgorithm::Sha384   => sha384(data).to_vec(),
            HashAlgorithm::Sha512   => sha512(data).to_vec(),
            HashAlgorithm::Sha3_224 => sha3_224(data).to_vec(),
            HashAlgorithm::Sha3_256 => sha3_256(data).to_vec(),
            HashAlgorithm::Sha3_384 => sha3_384(data).to_vec(),
            HashAlgorithm::Sha3_512 => sha3_512(data).to_vec(),
        }
    }
}

/// HMAC 범용 계산
///
/// # 인자
/// - `key`: HMAC 키 (임의 길이)
/// - `message`: 인증할 메시지
/// - `algo`: 사용할 해시 알고리즘
pub fn hmac(key: &[u8], message: &[u8], algo: HashAlgorithm) -> Vec<u8> {
    let block_size = algo.block_size();

    // 키 정규화: 블록 크기보다 길면 해시, 짧으면 0 패딩
    let mut k_prime = if key.len() > block_size {
        let mut v = algo.hash(key);
        v.resize(block_size, 0);
        v
    } else {
        let mut v = key.to_vec();
        v.resize(block_size, 0);
        v
    };

    // ipad = 0x36 XOR K', opad = 0x5c XOR K'
    let ipad: Vec<u8> = k_prime.iter().map(|&b| b ^ 0x36).collect();
    let opad: Vec<u8> = k_prime.iter().map(|&b| b ^ 0x5c).collect();

    // 내부 해시: H(K' XOR ipad || message)
    let mut inner = ipad;
    inner.extend_from_slice(message);
    let inner_hash = algo.hash(&inner);

    // 외부 해시: H(K' XOR opad || inner_hash)
    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    algo.hash(&outer)
}

// ═══════════════════════════════════════════════════════
// 타입별 편의 함수
// ═══════════════════════════════════════════════════════

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac(key, message, HashAlgorithm::Sha256).try_into().unwrap()
}

pub fn hmac_sha224(key: &[u8], message: &[u8]) -> [u8; 28] {
    hmac(key, message, HashAlgorithm::Sha224).try_into().unwrap()
}

pub fn hmac_sha384(key: &[u8], message: &[u8]) -> [u8; 48] {
    hmac(key, message, HashAlgorithm::Sha384).try_into().unwrap()
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    hmac(key, message, HashAlgorithm::Sha512).try_into().unwrap()
}

pub fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac(key, message, HashAlgorithm::Sha3_256).try_into().unwrap()
}

pub fn hmac_sha3_224(key: &[u8], message: &[u8]) -> [u8; 28] {
    hmac(key, message, HashAlgorithm::Sha3_224).try_into().unwrap()
}

pub fn hmac_sha3_384(key: &[u8], message: &[u8]) -> [u8; 48] {
    hmac(key, message, HashAlgorithm::Sha3_384).try_into().unwrap()
}

pub fn hmac_sha3_512(key: &[u8], message: &[u8]) -> [u8; 64] {
    hmac(key, message, HashAlgorithm::Sha3_512).try_into().unwrap()
}

/// HMAC 검증 (상수 시간 비교)
pub fn hmac_verify(key: &[u8], message: &[u8], tag: &[u8], algo: HashAlgorithm) -> bool {
    let expected = hmac(key, message, algo);
    if expected.len() != tag.len() { return false; }
    expected.iter().zip(tag.iter())
        .fold(0u8, |acc, (&a, &b)| acc | (a ^ b)) == 0
}

// ═══════════════════════════════════════════════════════
// 테스트 (NIST FIPS 198-1 / RFC 4231 공식 벡터)
// ═══════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::to_hex;

    // ── HMAC-SHA-256 (RFC 4231 Test Case 1) ──
    #[test]
    fn test_hmac_sha256_tc1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let result = hmac_sha256(&key, msg);
        assert_eq!(to_hex(&result), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    // RFC 4231 Test Case 2
    #[test]
    fn test_hmac_sha256_tc2() {
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";
        let result = hmac_sha256(key, msg);
        assert_eq!(to_hex(&result), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    // RFC 4231 Test Case 3 (긴 데이터)
    #[test]
    fn test_hmac_sha256_tc3() {
        let key = [0xaau8; 20];
        let msg = [0xddu8; 50];
        let result = hmac_sha256(&key, &msg);
        assert_eq!(to_hex(&result), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }

    // 키가 블록 크기보다 긴 경우 (RFC 4231 TC7)
    #[test]
    fn test_hmac_sha256_long_key() {
        let key = [0xaau8; 131]; // 131바이트 > 64바이트 블록
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let result = hmac_sha256(&key, msg);
        assert_eq!(to_hex(&result), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    // ── HMAC-SHA-512 (RFC 4231 Test Case 1) ──
    #[test]
    fn test_hmac_sha512_tc1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let result = hmac_sha512(&key, msg);
        assert_eq!(to_hex(&result), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

    // ── HMAC-SHA-384 (RFC 4231 Test Case 1) ──
    #[test]
    fn test_hmac_sha384_tc1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let result = hmac_sha384(&key, msg);
        assert_eq!(to_hex(&result), "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    }

    // ── HMAC-SHA-224 (RFC 4231 Test Case 1) ──
    #[test]
    fn test_hmac_sha224_tc1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let result = hmac_sha224(&key, msg);
        assert_eq!(to_hex(&result), "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
    }

    // ── HMAC-SHA3-256 ──
    #[test]
    fn test_hmac_sha3_256_basic() {
        let key = b"secret key";
        let msg = b"hello world";
        // 구현 일관성 테스트 (같은 입력 → 같은 출력)
        let r1 = hmac_sha3_256(key, msg);
        let r2 = hmac_sha3_256(key, msg);
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);
    }

    #[test]
    fn test_hmac_sha3_256_different_keys() {
        let msg = b"same message";
        let r1 = hmac_sha3_256(b"key1", msg);
        let r2 = hmac_sha3_256(b"key2", msg);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_hmac_sha3_512_basic() {
        let key = b"secret";
        let msg = b"message";
        let r = hmac_sha3_512(key, msg);
        assert_eq!(r.len(), 64);
        // 재현성 확인
        assert_eq!(r, hmac_sha3_512(key, msg));
    }

    // ── HMAC 검증 함수 ──
    #[test]
    fn test_hmac_verify_valid() {
        let key = b"my secret key";
        let msg = b"important message";
        let tag = hmac(key, msg, HashAlgorithm::Sha256);
        assert!(hmac_verify(key, msg, &tag, HashAlgorithm::Sha256));
    }

    #[test]
    fn test_hmac_verify_tampered_message() {
        let key = b"my secret key";
        let tag = hmac(key, b"original", HashAlgorithm::Sha256);
        assert!(!hmac_verify(key, b"tampered", &tag, HashAlgorithm::Sha256));
    }

    #[test]
    fn test_hmac_verify_tampered_tag() {
        let key = b"my secret key";
        let msg = b"message";
        let mut tag = hmac(key, msg, HashAlgorithm::Sha256);
        tag[0] ^= 0x01;
        assert!(!hmac_verify(key, msg, &tag, HashAlgorithm::Sha256));
    }

    // ── 빈 메시지/키 ──
    #[test]
    fn test_hmac_empty_message() {
        let result = hmac_sha256(b"key", b"");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hmac_empty_key() {
        let result = hmac_sha256(b"", b"message");
        assert_eq!(result.len(), 32);
    }
}
