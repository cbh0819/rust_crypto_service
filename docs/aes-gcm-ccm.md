# AES-GCM and AES-CCM (AEAD Modes)

**Date**: 2026-06-02  
**Standards**: NIST SP 800-38D (GCM), NIST SP 800-38C (CCM)  
**Result**: ✅ 91/91 tests passed (cumulative)

## Overview

Both GCM and CCM are AEAD (Authenticated Encryption with Associated Data) modes:
- **Confidentiality**: plaintext is encrypted
- **Integrity**: ciphertext + AAD are authenticated via tag
- **AAD**: Additional Authenticated Data — authenticated but not encrypted

| Feature | GCM | CCM |
|---------|-----|-----|
| Module | `src/gcm.rs` | `src/ccm.rs` |
| Encryption | CTR | CTR |
| Authentication | GHASH (GF(2¹²⁸)) | CBC-MAC |
| Parallel encrypt | ✅ | ❌ |
| Nonce size | 12 bytes | 7–13 bytes |
| Tag size | 128-bit fixed | 4/6/8/10/12/14/16 bytes |
| Standard | SP 800-38D | SP 800-38C / RFC 3610 |

---

## AES-GCM

### Algorithm
```
H   = AES(key, 0¹²⁸)            // Hash subkey
J0  = Nonce || 0x00000001        // Initial counter block (12-byte nonce)
CT  = GCTR(key, J0, PT)          // CTR encryption (starts at J0+1)
Tag = GHASH(H, AAD, CT) XOR AES(key, J0)
```

### GHASH (GF(2¹²⁸) multiplication)
- Irreducible polynomial: x¹²⁸ + x⁷ + x² + x + 1
- Processes AAD blocks, then ciphertext blocks, then length block
- Timing-safe tag comparison to prevent oracle attacks

### API
```rust
let enc = aes_gcm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &aad);
// enc.ciphertext, enc.tag ([u8; 16])

let pt = aes_gcm_decrypt(&ciphertext, &tag, &key, KeySize::Aes128, &nonce, &aad)?;
// Err(GcmError::AuthTagMismatch) if tampered
```

---

## AES-CCM

### Algorithm
```
// Authentication (CBC-MAC)
B0     = Flags || Nonce || Q(plaintext length)
T      = CBC-MAC(key, B0 || encode(AAD) || PT)
Tag    = T[0..t] XOR AES(key, A0)   // A0 = counter block at i=0

// Encryption (CTR, starting at i=1)
CT     = PT XOR AES(key, A1), AES(key, A2), ...
```

### Parameters
- **Nonce**: 7–13 bytes (L = 15 - len(Nonce), L bytes for length field)
- **Tag length (t)**: 4, 6, 8, 10, 12, 14, or 16 bytes

### API
```rust
let enc = aes_ccm_encrypt(plaintext, &key, KeySize::Aes128, &nonce, &aad, 8)?;
// enc.ciphertext, enc.tag (8 bytes)

let pt = aes_ccm_decrypt(&ciphertext, &tag, &key, KeySize::Aes128, &nonce, &aad)?;
// Err(CcmError::AuthTagMismatch) if tampered
```

## NIST Test Vectors Verified

- NIST SP 800-38D TC1 (empty plaintext/AAD), TC2 (plaintext only), TC3 (with key)
- NIST SP 800-38C Appendix C.1
