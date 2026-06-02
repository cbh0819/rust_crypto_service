# Integration Test Binary (unittest)

**Date**: 2026-06-02  
**File**: `src/bin/unittest.rs`  
**Result**: ✅ 135/135 tests passed

## Overview

Standalone binary that validates all crypto algorithm implementations after build.  
No external dependencies — pure Rust with ANSI terminal UI.

## Build & Run

```bash
# Debug build
cargo build --bin unittest
./target/debug/unittest

# Release build (faster execution)
cargo build --release --bin unittest
./target/release/unittest
```

## Exit Code

| Code | Meaning |
|------|---------|
| `0` | All tests passed |
| `1` | One or more tests failed |

## Test Suites (135 total)

| Suite | Tests | Parameter Coverage |
|-------|-------|--------------------|
| AES Block Cipher | 7 | AES-128/192/256, NIST FIPS 197 vectors |
| AES Operation Modes | 48 | ECB/CBC/CFB8/CFB128/OFB/CTR × 6 message lengths × AES-128/256 |
| AES-GCM | 20 | 5 message sizes × 3 AAD combos, tamper detection, NIST SP 800-38D |
| AES-CCM | 19 | 4 nonce lengths × 4 tag lengths, AES-256, NIST SP 800-38C |
| SHA-2 | 11 | SHA-224/256/384/512, NIST FIPS 180-4, 1M-byte stress |
| SHA-3 | 12 | SHA3-224/256/384/512, NIST FIPS 202, reproducibility |
| HMAC | 11 | SHA-2/SHA-3 all 8 variants, RFC 4231 vectors, verify function |
| CMAC | 7 | NIST SP 800-38B D.1–D.4, AES-256, verify function |

## Terminal Output

```
╔══════════════════════════════════════════════════════════════╗
║      rust_crypto_service — Integration Test Suite           ║
╚══════════════════════════════════════════════════════════════╝

▶ AES Block Cipher (7 tests)
  [████████████████████████████████] 100%  NIST FIPS 197 — AES-256 encrypt
  ✓ PASS  AES Block Cipher  7/7 passed  702µs
  ...

══════════════════════════════════════════════════════════════
  Final Summary
══════════════════════════════════════════════════════════════

  ✓  AES Block Cipher                     7/ 7
  ✓  AES Operation Modes                 48/48
  ...
  ✓  ALL TESTS PASSED    135/135 tests  110ms
```

## Design

- Each suite runs independent test cases via `test_case!` macro
- `check!` macro for assertions with descriptive error messages
- Constant-time tag comparison preserved in crypto primitives
- Failed tests print name + reason; passing tests are silent
- Timing measured per-test and aggregated per-suite
