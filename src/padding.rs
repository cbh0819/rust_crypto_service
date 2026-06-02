/// PKCS#7 패딩
/// 블록 크기에 맞게 데이터 끝에 패딩 바이트를 추가
/// 패딩 값 = 추가할 바이트 수 (1~block_size)
/// 이미 블록 크기의 배수이면 전체 블록을 패딩으로 추가

pub const BLOCK_SIZE: usize = 16;

/// 데이터에 PKCS#7 패딩 추가
pub fn pad(data: &[u8]) -> Vec<u8> {
    let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    padded
}

/// PKCS#7 패딩 제거
/// 잘못된 패딩이면 Err 반환
pub fn unpad(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() || data.len() % BLOCK_SIZE != 0 {
        return Err("잘못된 패딩: 데이터 길이가 블록 크기의 배수가 아님");
    }

    let padding_len = *data.last().unwrap() as usize;

    if padding_len == 0 || padding_len > BLOCK_SIZE {
        return Err("잘못된 패딩: 패딩 값이 범위를 벗어남");
    }

    // 모든 패딩 바이트가 동일한지 검증
    let start = data.len() - padding_len;
    if !data[start..].iter().all(|&b| b == padding_len as u8) {
        return Err("잘못된 패딩: 패딩 바이트가 일치하지 않음");
    }

    Ok(data[..start].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_partial_block() {
        // 13바이트 → 3바이트 패딩 추가
        let data = vec![0x61u8; 13];
        let padded = pad(&data);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[13..], &[0x03, 0x03, 0x03]);
    }

    #[test]
    fn test_pad_full_block() {
        // 16바이트 → 전체 블록(16바이트) 패딩 추가
        let data = vec![0x61u8; 16];
        let padded = pad(&data);
        assert_eq!(padded.len(), 32);
        assert_eq!(&padded[16..], &[0x10u8; 16]);
    }

    #[test]
    fn test_pad_empty() {
        // 빈 데이터 → 16바이트 패딩
        let padded = pad(&[]);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..], &[0x10u8; 16]);
    }

    #[test]
    fn test_unpad_valid() {
        // "abc" + 패딩 0x0d (13개) = 3 + 13 = 16바이트
        let mut data = vec![0x61u8, 0x62, 0x63];
        data.extend(vec![0x0du8; 13]);
        let unpadded = unpad(&data).unwrap();
        assert_eq!(unpadded, vec![0x61, 0x62, 0x63]);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        for len in 0..=32usize {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = pad(&data);
            let recovered = unpad(&padded).unwrap();
            assert_eq!(data, recovered, "길이 {}에서 패딩 라운드트립 실패", len);
        }
    }

    #[test]
    fn test_unpad_invalid_padding() {
        // 잘못된 패딩 값
        let mut data = vec![0x00u8; 16];
        data[15] = 0x05;
        data[14] = 0x05;
        // 나머지 패딩 바이트가 다름
        assert!(unpad(&data).is_err());
    }

    #[test]
    fn test_unpad_zero_padding() {
        // 패딩 값이 0이면 오류
        let data = vec![0x00u8; 16];
        assert!(unpad(&data).is_err());
    }
}
