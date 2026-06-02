# SHA-2 and SHA-3 Hash Functions

**Date**: 2026-06-02  
**Standards**: NIST FIPS 180-4 (SHA-2), NIST FIPS 202 (SHA-3)  
**Result**: ✅ 74/74 tests passed

## Overview

| Module | Variants | Structure |
|--------|----------|-----------|
| `src/sha2.rs` | SHA-224, SHA-256, SHA-384, SHA-512 | Merkle–Damgård |
| `src/sha3.rs` | SHA3-224, SHA3-256, SHA3-384, SHA3-512 | Keccak sponge |

## SHA-2 (NIST FIPS 180-4)

SHA-256/224 and SHA-512/384 share the same compression function, differing only in initial values and output length.

| Variant | Block Size | Word Size | Rounds | Output |
|---------|-----------|-----------|--------|--------|
| SHA-224 | 512-bit | 32-bit | 64 | 224-bit |
| SHA-256 | 512-bit | 32-bit | 64 | 256-bit |
| SHA-384 | 1024-bit | 64-bit | 80 | 384-bit |
| SHA-512 | 1024-bit | 64-bit | 80 | 512-bit |

### Core Functions
```
Ch(x,y,z)  = (x AND y) XOR (NOT x AND z)
Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
Σ0(x) = ROTR²(x)  XOR ROTR¹³(x) XOR ROTR²²(x)  [SHA-256]
Σ1(x) = ROTR⁶(x)  XOR ROTR¹¹(x) XOR ROTR²⁵(x)  [SHA-256]
```

## SHA-3 (NIST FIPS 202) — Keccak Sponge

### Parameters

| Variant | Rate (bytes) | Capacity | Output |
|---------|-------------|----------|--------|
| SHA3-224 | 144 | 448-bit | 224-bit |
| SHA3-256 | 136 | 512-bit | 256-bit |
| SHA3-384 | 104 | 768-bit | 384-bit |
| SHA3-512 | 72 | 1024-bit | 512-bit |

### Keccak-f[1600] — 5 Permutation Steps (24 rounds)
```
θ (Theta) : Column parity XOR → diffusion
ρ (Rho)   : Per-lane bit rotation
π (Pi)    : Lane position rearrangement
χ (Chi)   : Non-linear row transformation (only non-linear step)
ι (Iota)  : Round constant XOR (breaks symmetry)
```

### SHA-3 Domain Separation
- SHA-3 padding byte: `0x06` (vs Keccak original `0x01`)
- Last byte of final block: OR with `0x80`

## NIST Test Vectors Verified

All variants tested against NIST FIPS 180-4 / FIPS 202 official vectors:
- Empty string, `"abc"`, long multi-block messages
- SHA-256: 1,000,000 × `'a'` (multi-block stress test)
