# rust-aes-lib

순수 Rust로 구현한 학습용 AES 암호화 라이브러리입니다.  
외부 의존성 없이 AES 명세(NIST FIPS 197)를 밑바닥부터 직접 구현합니다.

> ⚠️ **학습 목적 전용** — 프로덕션 환경에서는 [`ring`](https://crates.io/crates/ring) 또는 [`aes`](https://crates.io/crates/aes) crate를 사용하세요.

---

## 지원 기능

### 키 크기
- AES-128 (16바이트 키, 10라운드)
- AES-192 (24바이트 키, 12라운드)
- AES-256 (32바이트 키, 14라운드)

### 운영 모드

| 모드    | 패딩   | 병렬 암호화 | 랜덤 접근 | 특징 |
|---------|--------|------------|-----------|------|
| ECB     | PKCS#7 | ✅ | ✅ | ⚠️ 학습 전용 (패턴 노출) |
| CBC     | PKCS#7 | ❌ | ❌ | 범용 블록 암호화 |
| CFB8    | 없음   | ❌ | ❌ | 1바이트 단위 스트림 |
| CFB128  | 없음   | ❌ | ❌ | 16바이트 단위 스트림 |
| OFB     | 없음   | ❌ | ❌ | 오류 비전파 스트림 |
| CTR     | 없음   | ✅ | ✅ | 고성능 스트림 |

---

## 빠른 시작

```rust
use rust_aes_lib::{aes128_cbc_encrypt, aes128_cbc_decrypt};
use rust_aes_lib::{aes128_ctr_encrypt, aes128_ctr_decrypt};

// CBC 모드
let key = [0u8; 16];
let iv  = [0u8; 16]; // 실제 사용 시 CSPRNG으로 생성
let plaintext = b"Hello, AES!";

let ciphertext = aes128_cbc_encrypt(plaintext, &key, &iv);
let recovered  = aes128_cbc_decrypt(&ciphertext, &key, &iv).unwrap();
assert_eq!(recovered, plaintext);

// CTR 모드 (패딩 불필요)
let nonce = [0u8; 12]; // 실제 사용 시 고유한 랜덤 값
let ct = aes128_ctr_encrypt(plaintext, &key, &nonce);
let pt = aes128_ctr_decrypt(&ct, &key, &nonce);
assert_eq!(pt, plaintext);
```

---

## 프로젝트 구조

```
src/
├── lib.rs           # 공개 API, 편의 함수, 통합 테스트
├── constants.rs     # S-Box, 역 S-Box, RCON 테이블
├── gf.rs            # GF(2⁸) 갈루아 필드 연산
├── key_schedule.rs  # AES 키 확장 알고리즘
├── block.rs         # AES 코어 (SubBytes, ShiftRows, MixColumns, AddRoundKey)
├── padding.rs       # PKCS#7 패딩
└── modes.rs         # 운영 모드 (ECB, CBC, CFB8, CFB128, OFB, CTR)
```

---

## 테스트 실행

```bash
cargo test
```

NIST FIPS 197 및 SP 800-38A 공식 테스트 벡터를 포함한 **51개 테스트** 전부 통과.

---

## 표준 준수

- **NIST FIPS 197** — AES 암호화 표준
- **NIST SP 800-38A** — 블록 암호 운영 모드 (ECB, CBC, CFB, OFB, CTR)

---

## 보안 참고사항

| 항목 | 상태 |
|------|------|
| 사이드 채널 대응 | ❌ 미구현 |
| 타이밍 공격 대응 | ❌ 미구현 |
| 보안 감사 | ❌ 미수행 |
| NIST 테스트 벡터 | ✅ 통과 |

---

## 라이선스

MIT
