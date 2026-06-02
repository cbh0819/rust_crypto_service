# AES Block Cipher Implementation

**Date**: 2026-06-02  
**Standard**: NIST FIPS 197  
**Result**: ✅ 41/41 tests passed

## Overview

Pure Rust implementation of AES-128/192/256 block cipher with no external dependencies.

## Modules

| File | Description |
|------|-------------|
| `src/constants.rs` | S-Box, Inv S-Box, RCON lookup tables |
| `src/gf.rs` | GF(2⁸) Galois field arithmetic |
| `src/key_schedule.rs` | Key expansion for AES-128/192/256 |
| `src/block.rs` | Core AES operations (SubBytes, ShiftRows, MixColumns, AddRoundKey) |
| `src/padding.rs` | PKCS#7 padding/unpadding |

## Key Sizes

| Variant | Key Length | Rounds |
|---------|-----------|--------|
| AES-128 | 16 bytes | 10 |
| AES-192 | 24 bytes | 12 |
| AES-256 | 32 bytes | 14 |

## Core Operations

- **SubBytes**: S-Box byte substitution (GF(2⁸) multiplicative inverse + affine transform)
- **ShiftRows**: Cyclic row rotation (0/1/2/3 bytes)
- **MixColumns**: GF(2⁸) matrix multiplication
- **AddRoundKey**: XOR with round key
- **KeyExpansion**: RotWord → SubWord → XOR RCON

## NIST Test Vectors Verified

- NIST FIPS 197 Appendix A.1 — AES-128 key schedule
- NIST FIPS 197 Appendix B — AES-128 full encrypt/decrypt
- NIST FIPS 197 Appendix B — AES-256 encryption
