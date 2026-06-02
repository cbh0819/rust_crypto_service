# HMAC and CMAC

**Date**: 2026-06-02  
**Standards**: NIST FIPS 198-1 (HMAC), NIST SP 800-38B (CMAC)  
**Result**: ✅ 115/115 tests passed (cumulative)

## Overview

| Feature | HMAC | CMAC |
|---------|------|------|
| Module | `src/hmac.rs` | `src/cmac.rs` |
| Primitive | Hash function (SHA-2/SHA-3) | AES block cipher |
| Tag size | Hash output length | 128-bit fixed |
| Standard | FIPS 198-1 / RFC 4231 | SP 800-38B / RFC 4493 |

---

## HMAC (Hash-based MAC)

### Algorithm
```
K'       = H(K) if len(K) > block_size, else K padded with 0x00
ipad     = K' XOR 0x36 (repeated)
opad     = K' XOR 0x5c (repeated)
HMAC     = H(opad || H(ipad || message))
```

### Supported Hash Algorithms

| Algorithm | Block Size | Output |
|-----------|-----------|--------|
| HMAC-SHA-224 | 64 bytes | 28 bytes |
| HMAC-SHA-256 | 64 bytes | 32 bytes |
| HMAC-SHA-384 | 128 bytes | 48 bytes |
| HMAC-SHA-512 | 128 bytes | 64 bytes |
| HMAC-SHA3-224 | 144 bytes | 28 bytes |
| HMAC-SHA3-256 | 136 bytes | 32 bytes |
| HMAC-SHA3-384 | 104 bytes | 48 bytes |
| HMAC-SHA3-512 | 72 bytes | 64 bytes |

### API
```rust
// Generic
let tag = hmac(key, message, HashAlgorithm::Sha256);
let ok  = hmac_verify(key, message, &tag, HashAlgorithm::Sha256);

// Typed convenience
let tag: [u8; 32] = hmac_sha256(key, message);
let tag: [u8; 64] = hmac_sha512(key, message);
let tag: [u8; 32] = hmac_sha3_256(key, message);
```

---

## CMAC (Cipher-based MAC)

Improves on raw CBC-MAC by using derived subkeys K1/K2 to prevent length-extension attacks.

### Algorithm
```
// Subkey generation
L  = AES(key, 0¹²⁸)
K1 = L << 1  (XOR 0x87 if MSB was 1)
K2 = K1 << 1 (XOR 0x87 if MSB was 1)

// MAC computation
- Split message into 16-byte blocks M1..Mn
- Last block complete   → Mn XOR K1
- Last block incomplete → Mn || 10* XOR K2
- Tag = CBC-MAC(key, M1 || ... || Mn*)
```

### API
```rust
let tag: [u8; 16] = aes_cmac(&key, KeySize::Aes128, message);
let ok = aes_cmac_verify(&key, KeySize::Aes128, message, &tag);
```

## NIST Test Vectors Verified

- RFC 4231 TC1–TC3, TC7 (HMAC-SHA-256/384/512/224)
- NIST SP 800-38B Appendix D.1–D.4 (CMAC-AES128)
- NIST SP 800-38B Appendix D.1 subkeys K1/K2

## Security Notes

- Tag comparison uses constant-time algorithm to prevent timing attacks
- HMAC key longer than block size is pre-hashed per spec
- CMAC 10* padding prevents length-extension attacks on CBC-MAC
