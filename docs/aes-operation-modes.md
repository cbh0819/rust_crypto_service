# AES Operation Modes

**Date**: 2026-06-02  
**Standard**: NIST SP 800-38A  
**Result**: ✅ 51/51 tests passed

## Overview

Six AES operation modes implemented in `src/modes.rs`.

## Supported Modes

| Mode | Padding | Parallel | Random Access | Notes |
|------|---------|----------|---------------|-------|
| ECB | PKCS#7 | ✅ | ✅ | ⚠️ Learning only — pattern leakage |
| CBC | PKCS#7 | ❌ | ❌ | General purpose block encryption |
| CFB8 | None | ❌ | ❌ | 1-byte stream, shift register |
| CFB128 | None | ❌ | ❌ | 16-byte block stream |
| OFB | None | ❌ | ❌ | No error propagation |
| CTR | None | ✅ | ✅ | High performance, Nonce+Counter |

## Mode Details

### CFB8
```
CT[i] = PT[i] XOR AES(ShiftReg)[0]
ShiftReg = ShiftReg << 1 || CT[i]
```

### CFB128
```
CT[i..i+16] = PT[i..i+16] XOR AES(ShiftReg)
ShiftReg = CT[i..i+16]
```

### OFB
```
O[0] = IV,  O[i] = AES(O[i-1])   ← independent of plaintext/ciphertext
Result = data XOR O[i]            ← encrypt == decrypt
```

### CTR
```
CounterBlock = Nonce(12B) || Counter(4B, big-endian)
Keystream[i] = AES(Nonce || i)
Result[i]    = data[i] XOR Keystream[i]
```

## NIST Test Vectors Verified

- NIST SP 800-38A — ECB-AES128
- NIST SP 800-38A — CBC-AES128
- NIST SP 800-38A — CFB8-AES128
- NIST SP 800-38A — CFB128-AES128
- NIST SP 800-38A — OFB-AES128
