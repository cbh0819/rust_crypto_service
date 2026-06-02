/// GF(2^8) 갈루아 필드 연산
/// AES는 기약 다항식 x^8 + x^4 + x^3 + x + 1 (0x11b) 위에서 동작

/// GF(2^8)에서 두 수의 곱셈
/// 러시아 농부 알고리즘 (반복적 곱셈) 사용
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    // AES 기약 다항식: x^8 + x^4 + x^3 + x + 1 = 0x1b (mod x^8)
    let irreducible: u8 = 0x1b;

    for _ in 0..8 {
        // b의 최하위 비트가 1이면 result에 a를 XOR
        if b & 1 != 0 {
            result ^= a;
        }
        // a의 최상위 비트 확인 (x^8 오버플로우 체크)
        let hi_bit = a & 0x80;
        // a를 왼쪽으로 1비트 시프트 (x를 곱함)
        a = a.wrapping_shl(1);
        // 오버플로우 발생 시 기약 다항식으로 reduction
        if hi_bit != 0 {
            a ^= irreducible;
        }
        // b를 오른쪽으로 1비트 시프트
        b >>= 1;
    }
    result
}

/// xtime: GF(2^8)에서 x를 곱하는 연산 (gf_mul(a, 2))
/// MixColumns에서 자주 사용
#[inline]
pub fn xtime(a: u8) -> u8 {
    if a & 0x80 != 0 {
        (a << 1) ^ 0x1b
    } else {
        a << 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_identity() {
        // 1을 곱하면 자기 자신
        assert_eq!(gf_mul(0x53, 0x01), 0x53);
        assert_eq!(gf_mul(0xff, 0x01), 0xff);
    }

    #[test]
    fn test_gf_mul_zero() {
        // 0을 곱하면 0
        assert_eq!(gf_mul(0x53, 0x00), 0x00);
    }

    #[test]
    fn test_gf_mul_known() {
        // NIST FIPS 197 부록 B 예시
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
    }

    #[test]
    fn test_xtime() {
        // xtime(0x57) = 0xae (오버플로우 없음)
        assert_eq!(xtime(0x57), 0xae);
        // xtime(0xae) = 0x47 (오버플로우 발생, XOR 0x1b)
        assert_eq!(xtime(0xae), 0x47);
    }

    #[test]
    fn test_gf_mul_commutativity() {
        // 교환 법칙
        for a in [0x00u8, 0x01, 0x53, 0x8d, 0xff] {
            for b in [0x00u8, 0x01, 0x83, 0x13, 0xca] {
                assert_eq!(gf_mul(a, b), gf_mul(b, a),
                    "gf_mul({:#04x}, {:#04x}) != gf_mul({:#04x}, {:#04x})", a, b, b, a);
            }
        }
    }
}
