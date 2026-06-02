//! rust_crypto_service 통합 테스트 실행 파일
//!
//! 빌드: cargo build --bin unittest
//! 실행: ./target/debug/unittest

use rust_aes_lib::*;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════
// ANSI 터미널 색상/스타일
// ═══════════════════════════════════════════════════════

const RESET:   &str = "\x1b[0m";
const BOLD:    &str = "\x1b[1m";
const DIM:     &str = "\x1b[2m";
const GREEN:   &str = "\x1b[32m";
const RED:     &str = "\x1b[31m";
const YELLOW:  &str = "\x1b[33m";
const CYAN:    &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const WHITE:   &str = "\x1b[97m";
const BG_DARK: &str = "\x1b[48;5;235m";

// ═══════════════════════════════════════════════════════
// 테스트 결과 구조체
// ═══════════════════════════════════════════════════════

struct TestResult {
    name: String,
    passed: bool,
    duration: Duration,
    detail: Option<String>,
}

struct SuiteResult {
    suite_name: String,
    results: Vec<TestResult>,
}

impl SuiteResult {
    fn passed(&self) -> usize { self.results.iter().filter(|r| r.passed).count() }
    fn failed(&self) -> usize { self.results.iter().filter(|r| !r.passed).count() }
    fn total(&self) -> usize { self.results.len() }
    fn all_passed(&self) -> bool { self.failed() == 0 }
    fn total_duration(&self) -> Duration {
        self.results.iter().map(|r| r.duration).sum()
    }
}

// ═══════════════════════════════════════════════════════
// 터미널 UI 헬퍼
// ═══════════════════════════════════════════════════════

fn clear_line() { print!("\r\x1b[2K"); }

fn print_header() {
    println!();
    println!("{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗{RESET}");
    println!("{BOLD}{CYAN}║      rust_crypto_service — Integration Test Suite           ║{RESET}");
    println!("{BOLD}{CYAN}╚══════════════════════════════════════════════════════════════╝{RESET}");
    println!();
}

fn print_suite_header(name: &str, total: usize) {
    println!("{BOLD}{MAGENTA}▶ {name}{RESET} {DIM}({total} tests){RESET}");
}

/// 진행률 바 출력 (현재/전체)
fn print_progress(current: usize, total: usize, test_name: &str) {
    let width = 30usize;
    let filled = (current * width) / total.max(1);
    let bar: String = (0..width)
        .map(|i| if i < filled { '█' } else { '░' })
        .collect();
    let pct = (current * 100) / total.max(1);
    clear_line();
    print!(
        "  {CYAN}[{bar}]{RESET} {DIM}{pct:3}%{RESET}  {DIM}{}{RESET}",
        truncate(test_name, 35)
    );
    use std::io::Write;
    std::io::stdout().flush().unwrap();
}

fn print_suite_result(suite: &SuiteResult) {
    clear_line();
    let status = if suite.all_passed() {
        format!("{GREEN}{BOLD}✓ PASS{RESET}")
    } else {
        format!("{RED}{BOLD}✗ FAIL{RESET}")
    };
    let dur = format_duration(suite.total_duration());
    println!(
        "  {status}  {BOLD}{}{RESET}  {DIM}{}/{} passed  {dur}{RESET}",
        suite.suite_name, suite.passed(), suite.total()
    );

    // 실패한 테스트만 상세 출력
    for r in suite.results.iter().filter(|r| !r.passed) {
        println!("    {RED}✗ {}{RESET}", r.name);
        if let Some(detail) = &r.detail {
            println!("      {DIM}{detail}{RESET}");
        }
    }
}

fn print_final_summary(suites: &[SuiteResult], total_dur: Duration) {
    let total_tests: usize = suites.iter().map(|s| s.total()).sum();
    let total_pass:  usize = suites.iter().map(|s| s.passed()).sum();
    let total_fail:  usize = suites.iter().map(|s| s.failed()).sum();
    let all_ok = total_fail == 0;

    println!();
    println!("{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}");
    println!("{BOLD}{WHITE}  Final Summary{RESET}");
    println!("{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}");
    println!();

    for suite in suites {
        let icon = if suite.all_passed() {
            format!("{GREEN}✓{RESET}")
        } else {
            format!("{RED}✗{RESET}")
        };
        println!(
            "  {icon}  {:<35} {DIM}{:>2}/{:>2}{RESET}",
            suite.suite_name, suite.passed(), suite.total()
        );
    }

    println!();
    let dur_str = format_duration(total_dur);

    if all_ok {
        println!("{BG_DARK}{GREEN}{BOLD}  ✓ ALL TESTS PASSED  {RESET}{DIM}  {total_pass}/{total_tests} tests  {dur_str}{RESET}");
    } else {
        println!("{BG_DARK}{RED}{BOLD}  ✗ SOME TESTS FAILED  {RESET}{DIM}  {total_pass}/{total_tests} passed, {total_fail} failed  {dur_str}{RESET}");
    }
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max-1]) }
}

fn format_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 { format!("{us}µs") }
    else if us < 1_000_000 { format!("{:.2}ms", us as f64 / 1000.0) }
    else { format!("{:.2}s", d.as_secs_f64()) }
}

// ═══════════════════════════════════════════════════════
// 테스트 매크로 헬퍼
// ═══════════════════════════════════════════════════════

macro_rules! test_case {
    ($results:expr, $name:expr, $body:expr) => {{
        let start = Instant::now();
        let outcome: Result<(), String> = (|| $body)();
        let duration = start.elapsed();
        $results.push(TestResult {
            name: $name.to_string(),
            passed: outcome.is_ok(),
            duration,
            detail: outcome.err(),
        });
    }};
}

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !($cond) { return Err($msg.to_string()); }
    };
    ($left:expr, ==, $right:expr) => {
        if $left != $right {
            return Err(format!("expected {:?}, got {:?}", $right, $left));
        }
    };
}

// ═══════════════════════════════════════════════════════
// 테스트 스위트 구현
// ═══════════════════════════════════════════════════════

// ─── 1. AES 블록 암호화 ───────────────────────────────

fn suite_aes_block() -> SuiteResult {
    let mut results = Vec::new();

    // 파라미터 셋: (키 크기, 평문, 설명)
    let param_sets: &[(KeySize, &[u8], &str)] = &[
        (KeySize::Aes128, &[0u8; 16],    "AES-128 zero key/pt"),
        (KeySize::Aes192, &[0x42u8; 16], "AES-192 pattern key/pt"),
        (KeySize::Aes256, &[0xffu8; 16], "AES-256 all-ones"),
        (KeySize::Aes128, &[0x13u8; 16], "AES-128 random-ish"),
        (KeySize::Aes256, &[0u8; 16],    "AES-256 zero key/pt"),
    ];

    let keys: &[&[u8]] = &[
        &[0u8; 16], &[0x42u8; 24], &[0xffu8; 32], &[0x13u8; 16], &[0u8; 32],
    ];

    for (i, &(ks, pt, desc)) in param_sets.iter().enumerate() {
        let key = keys[i];
        let pt_arr: [u8; 16] = pt.try_into().unwrap();
        let key_owned = key.to_vec();
        let desc_owned = desc.to_string();

        test_case!(results, format!("encrypt/decrypt roundtrip — {desc_owned}"), {
            let ct = aes_encrypt_block(&pt_arr, &key_owned, ks);
            let recovered = aes_decrypt_block(&ct, &key_owned, ks);
            check!(recovered == pt_arr, "복호화 결과가 원본과 다름");
            check!(ct != pt_arr || pt_arr == [0u8;16], "암호문이 평문과 같음");
            Ok(())
        });
    }

    // NIST FIPS 197 벡터 검증
    test_case!(results, "NIST FIPS 197 — AES-128 encrypt", {
        let key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
        let pt  = [0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34];
        let exp = [0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32];
        check!(aes_encrypt_block(&pt, &key, KeySize::Aes128), ==, exp);
        Ok(())
    });

    test_case!(results, "NIST FIPS 197 — AES-256 encrypt", {
        let key: [u8;32] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31];
        let pt  = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
        let exp = [0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89];
        check!(aes_encrypt_block(&pt, &key, KeySize::Aes256), ==, exp);
        Ok(())
    });

    SuiteResult { suite_name: "AES Block Cipher".to_string(), results }
}

// ─── 2. 운영 모드 ──────────────────────────────────────

fn suite_operation_modes() -> SuiteResult {
    let mut results = Vec::new();

    let key128 = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
    let key256 = [0u8; 32];
    let iv     = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0fu8];
    let nonce12: [u8; 12] = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b];

    // 테스트할 메시지 길이 셋 (블록 경계, 미만, 이상, 멀티블록)
    let messages: &[(&[u8], &str)] = &[
        (b"A",                           "1-byte"),
        (b"Hello, World!",               "13-byte (partial block)"),
        (b"Exactly sixteen!",            "16-byte (1 block)"),
        (b"This is 32 bytes of data!!!", "28-byte (partial 2nd block)"),
        (&[0x42u8; 64],                  "64-byte (4 blocks)"),
        (&[0x00u8; 100],                 "100-byte (multi-block)"),
    ];

    // ECB (패딩 있음, 블록 경계 메시지만)
    for &(msg, desc) in messages.iter().filter(|(m, _)| m.len() >= 16) {
        let msg = msg.to_vec();
        let desc = desc.to_string();
        test_case!(results, format!("ECB AES-128 roundtrip — {desc}"), {
            let ct = ecb_encrypt(&msg, &key128, KeySize::Aes128);
            let pt = ecb_decrypt(&ct, &key128, KeySize::Aes128).map_err(|e| e.to_string())?;
            check!(pt == msg, "ECB 복호화 불일치");
            Ok(())
        });
    }

    // CBC — 모든 메시지 길이
    for &(msg, desc) in messages {
        let msg = msg.to_vec();
        let desc = desc.to_string();
        test_case!(results, format!("CBC AES-128 roundtrip — {desc}"), {
            let ct = cbc_encrypt(&msg, &key128, KeySize::Aes128, &iv);
            let pt = cbc_decrypt(&ct, &key128, KeySize::Aes128, &iv).map_err(|e| e.to_string())?;
            check!(pt == msg, "CBC 복호화 불일치");
            Ok(())
        });
        let msg = msg.to_vec();
        let desc2 = desc.clone();
        test_case!(results, format!("CBC AES-256 roundtrip — {desc2}"), {
            let ct = cbc_encrypt(&msg, &key256, KeySize::Aes256, &iv);
            let pt = cbc_decrypt(&ct, &key256, KeySize::Aes256, &iv).map_err(|e| e.to_string())?;
            check!(pt == msg, "CBC-256 복호화 불일치");
            Ok(())
        });
    }

    // CFB8 / CFB128 / OFB / CTR — 스트림 모드 (패딩 없음)
    let stream_modes: &[(&str, fn(&[u8], &[u8], KeySize, &[u8; 16]) -> Vec<u8>, fn(&[u8], &[u8], KeySize, &[u8; 16]) -> Vec<u8>)] = &[
        ("CFB8",   cfb8_encrypt,   cfb8_decrypt),
        ("CFB128", cfb128_encrypt, cfb128_decrypt),
        ("OFB",    ofb_encrypt,    ofb_decrypt),
    ];

    for &(mode_name, enc_fn, dec_fn) in stream_modes {
        for &(msg, desc) in messages {
            let msg = msg.to_vec();
            let desc = desc.to_string();
            test_case!(results, format!("{mode_name} AES-128 roundtrip — {desc}"), {
                let ct = enc_fn(&msg, &key128, KeySize::Aes128, &iv);
                let pt = dec_fn(&ct, &key128, KeySize::Aes128, &iv);
                check!(pt == msg, format!("{mode_name} 복호화 불일치"));
                check!(ct.len() == msg.len(), "스트림 모드 길이 불일치");
                Ok(())
            });
        }
    }

    // CTR — nonce 기반
    for &(msg, desc) in messages {
        let msg = msg.to_vec();
        let desc = desc.to_string();
        test_case!(results, format!("CTR AES-128 roundtrip — {desc}"), {
            let ct = ctr_encrypt(&msg, &key128, KeySize::Aes128, &nonce12);
            let pt = ctr_decrypt(&ct, &key128, KeySize::Aes128, &nonce12);
            check!(pt == msg, "CTR 복호화 불일치");
            check!(ct.len() == msg.len(), "CTR 길이 불일치");
            Ok(())
        });
        let msg = msg.to_vec();
        test_case!(results, format!("CTR AES-256 roundtrip — {desc}"), {
            let ct = ctr_encrypt(&msg, &key256, KeySize::Aes256, &nonce12);
            let pt = ctr_decrypt(&ct, &key256, KeySize::Aes256, &nonce12);
            check!(pt == msg, "CTR-256 복호화 불일치");
            Ok(())
        });
    }

    // NIST SP 800-38A 벡터
    test_case!(results, "NIST SP 800-38A — CBC-AES128 block 1", {
        let pt  = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let exp = [0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d];
        let ct = cbc_encrypt(&pt, &key128, KeySize::Aes128, &iv);
        check!(&ct[..16], ==, &exp[..]);
        Ok(())
    });

    test_case!(results, "NIST SP 800-38A — CFB128-AES128 block 1", {
        let pt  = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a];
        let exp = [0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a];
        let ct = cfb128_encrypt(&pt, &key128, KeySize::Aes128, &iv);
        check!(&ct[..16], ==, &exp[..]);
        Ok(())
    });

    SuiteResult { suite_name: "AES Operation Modes".to_string(), results }
}

// ─── 3. AES-GCM ────────────────────────────────────────

fn suite_gcm() -> SuiteResult {
    let mut results = Vec::new();

    let key128 = [0u8; 16];
    let key256 = [0u8; 32];
    let nonce  = [0u8; 12];

    let messages: &[(&[u8], &str)] = &[
        (b"",                        "empty plaintext"),
        (b"short",                   "5-byte"),
        (b"Exactly sixteen!",        "16-byte"),
        (&[0xabu8; 48],              "48-byte (3 blocks)"),
        (&[0x00u8; 256],             "256-byte"),
    ];
    let aad_sets: &[(&[u8], &str)] = &[
        (b"",            "no AAD"),
        (b"header data", "11-byte AAD"),
        (&[0xffu8; 16],  "16-byte AAD"),
    ];

    // AES-128-GCM 파라미터 조합
    for &(msg, mdesc) in messages {
        for &(aad, adesc) in aad_sets {
            let msg = msg.to_vec(); let aad = aad.to_vec();
            let mdesc = mdesc.to_string(); let adesc = adesc.to_string();
            test_case!(results, format!("GCM AES-128 roundtrip — {mdesc} / {adesc}"), {
                let enc = aes_gcm_encrypt(&msg, &key128, KeySize::Aes128, &nonce, &aad);
                let dec = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key128, KeySize::Aes128, &nonce, &aad)
                    .map_err(|e| format!("{e}"))?;
                check!(dec == msg, "GCM 복호화 불일치");
                Ok(())
            });
        }
    }

    // AES-256-GCM
    test_case!(results, "GCM AES-256 roundtrip", {
        let msg = b"AES-256-GCM test message!";
        let aad = b"associated";
        let enc = aes_gcm_encrypt(msg, &key256, KeySize::Aes256, &nonce, aad);
        let dec = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key256, KeySize::Aes256, &nonce, aad)
            .map_err(|e| format!("{e}"))?;
        check!(dec == msg.to_vec(), "GCM-256 복호화 불일치");
        Ok(())
    });

    // 위변조 탐지
    test_case!(results, "GCM — ciphertext tamper detected", {
        let enc = aes_gcm_encrypt(b"secret", &key128, KeySize::Aes128, &nonce, b"aad");
        let mut tampered = enc.ciphertext.clone();
        tampered[0] ^= 0x01;
        let result = aes_gcm_decrypt(&tampered, &enc.tag, &key128, KeySize::Aes128, &nonce, b"aad");
        check!(result.is_err(), "위변조 탐지 실패");
        Ok(())
    });
    test_case!(results, "GCM — AAD tamper detected", {
        let enc = aes_gcm_encrypt(b"secret", &key128, KeySize::Aes128, &nonce, b"valid");
        let result = aes_gcm_decrypt(&enc.ciphertext, &enc.tag, &key128, KeySize::Aes128, &nonce, b"forged");
        check!(result.is_err(), "AAD 위변조 탐지 실패");
        Ok(())
    });

    // NIST 벡터
    test_case!(results, "NIST SP 800-38D — TC1 (empty, tag)", {
        let enc = aes_gcm_encrypt(&[], &key128, KeySize::Aes128, &nonce, &[]);
        let tag_hex: String = enc.tag.iter().map(|b| format!("{b:02x}")).collect();
        check!(tag_hex == "58e2fccefa7e3061367f1d57a4e7455a", format!("tag mismatch: {tag_hex}"));
        Ok(())
    });
    test_case!(results, "NIST SP 800-38D — TC2 (16-byte pt, no AAD)", {
        let pt = [0u8; 16];
        let enc = aes_gcm_encrypt(&pt, &key128, KeySize::Aes128, &nonce, &[]);
        let ct_hex: String = enc.ciphertext.iter().map(|b| format!("{b:02x}")).collect();
        check!(ct_hex == "0388dace60b6a392f328c2b971b2fe78", format!("ct mismatch: {ct_hex}"));
        Ok(())
    });

    SuiteResult { suite_name: "AES-GCM".to_string(), results }
}

// ─── 4. AES-CCM ────────────────────────────────────────

fn suite_ccm() -> SuiteResult {
    let mut results = Vec::new();

    let key128 = [0u8; 16];
    let key256 = [0u8; 32];

    // nonce 길이 7~13 모두 테스트
    let nonce_sets: &[(&[u8], &str)] = &[
        (&[0u8;  7], "nonce-7"),
        (&[0u8;  9], "nonce-9"),
        (&[0u8; 11], "nonce-11"),
        (&[0u8; 13], "nonce-13"),
    ];

    // tag 길이 셋
    let tag_lens = [4usize, 8, 12, 16];

    let msg = b"CCM integration test message!!";
    let aad = b"header";

    for &(nonce, ndesc) in nonce_sets {
        for &tlen in &tag_lens {
            let nonce = nonce.to_vec();
            let ndesc = ndesc.to_string();
            test_case!(results, format!("CCM AES-128 — {ndesc} / tag-{tlen}"), {
                let enc = aes_ccm_encrypt(msg, &key128, KeySize::Aes128, &nonce, aad, tlen)
                    .map_err(|e| format!("{e}"))?;
                check!(enc.tag.len() == tlen, "태그 길이 불일치");
                let dec = aes_ccm_decrypt(&enc.ciphertext, &enc.tag, &key128, KeySize::Aes128, &nonce, aad)
                    .map_err(|e| format!("{e}"))?;
                check!(dec == msg.to_vec(), "CCM 복호화 불일치");
                Ok(())
            });
        }
    }

    // AES-256-CCM
    test_case!(results, "CCM AES-256 roundtrip", {
        let nonce = [0u8; 13];
        let enc = aes_ccm_encrypt(b"AES-256 CCM", &key256, KeySize::Aes256, &nonce, b"aad", 8)
            .map_err(|e| format!("{e}"))?;
        let dec = aes_ccm_decrypt(&enc.ciphertext, &enc.tag, &key256, KeySize::Aes256, &nonce, b"aad")
            .map_err(|e| format!("{e}"))?;
        check!(dec == b"AES-256 CCM".to_vec(), "CCM-256 복호화 불일치");
        Ok(())
    });

    // 위변조 탐지
    test_case!(results, "CCM — ciphertext tamper detected", {
        let nonce = [0u8; 13];
        let enc = aes_ccm_encrypt(b"secret data", &key128, KeySize::Aes128, &nonce, b"", 8)
            .map_err(|e| format!("{e}"))?;
        let mut tampered = enc.ciphertext.clone();
        tampered[0] ^= 0x01;
        let result = aes_ccm_decrypt(&tampered, &enc.tag, &key128, KeySize::Aes128, &nonce, b"");
        check!(result.is_err(), "위변조 탐지 실패");
        Ok(())
    });

    // NIST SP 800-38C C.1
    test_case!(results, "NIST SP 800-38C — C.1", {
        let key = [0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf];
        let nonce = [0x00,0x00,0x00,0x03,0x02,0x01,0x00,0xa0,0xa1,0xa2,0xa3,0xa4,0xa5];
        let aad2 = [0x00u8,0x01,0x02,0x03,0x04,0x05,0x06,0x07];
        let pt = [0x08u8,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e];
        let enc = aes_ccm_encrypt(&pt, &key, KeySize::Aes128, &nonce, &aad2, 4)
            .map_err(|e| format!("{e}"))?;
        let ct_hex: String = enc.ciphertext.iter().map(|b| format!("{b:02x}")).collect();
        check!(ct_hex == "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384", format!("ct: {ct_hex}"));
        Ok(())
    });

    SuiteResult { suite_name: "AES-CCM".to_string(), results }
}

// ─── 5. SHA-2 ──────────────────────────────────────────

fn suite_sha2() -> SuiteResult {
    let mut results = Vec::new();

    let messages: &[(&[u8], &str)] = &[
        (b"",                                    "empty"),
        (b"abc",                                 "abc"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "448-bit"),
    ];

    // SHA-256
    let sha256_expected = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ];
    for (i, &(msg, desc)) in messages.iter().enumerate() {
        let msg = msg.to_vec(); let exp = sha256_expected[i]; let desc = desc.to_string();
        test_case!(results, format!("SHA-256 — {desc}"), {
            let h = sha256(&msg);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            check!(hex == exp, format!("got {hex}"));
            Ok(())
        });
    }

    // SHA-224
    let sha224_expected = [
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
    ];
    for (i, &(msg, desc)) in messages.iter().enumerate() {
        let msg = msg.to_vec(); let exp = sha224_expected[i]; let desc = desc.to_string();
        test_case!(results, format!("SHA-224 — {desc}"), {
            let h = sha224(&msg);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            check!(hex == exp, format!("got {hex}"));
            Ok(())
        });
    }

    // SHA-512
    let sha512_expected = [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ];
    let sha512_msgs = [&b""[..], &b"abc"[..]];
    let sha512_descs = ["empty", "abc"];
    for i in 0..2 {
        let msg = sha512_msgs[i].to_vec(); let exp = sha512_expected[i]; let desc = sha512_descs[i].to_string();
        test_case!(results, format!("SHA-512 — {desc}"), {
            let h = sha512(&msg);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            check!(hex == exp, format!("got {hex}"));
            Ok(())
        });
    }

    // SHA-384
    let sha384_expected = [
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ];
    for i in 0..2 {
        let msg = sha512_msgs[i].to_vec(); let exp = sha384_expected[i]; let desc = sha512_descs[i].to_string();
        test_case!(results, format!("SHA-384 — {desc}"), {
            let h = sha384(&msg);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            check!(hex == exp, format!("got {hex}"));
            Ok(())
        });
    }

    // 멀티블록 스트레스
    test_case!(results, "SHA-256 — 1,000,000 × 'a'", {
        let msg = vec![b'a'; 1_000_000];
        let h = sha256(&msg);
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        check!(hex == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", format!("got {hex}"));
        Ok(())
    });

    SuiteResult { suite_name: "SHA-2".to_string(), results }
}

// ─── 6. SHA-3 ──────────────────────────────────────────

fn suite_sha3() -> SuiteResult {
    let mut results = Vec::new();

    let variants: &[(&str, fn(&[u8]) -> String, &str, &str)] = &[
        ("SHA3-256", |m| { let h = sha3_256(m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
         "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("SHA3-224", |m| { let h = sha3_224(m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
         "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
        ("SHA3-384", |m| { let h = sha3_384(m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
         "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
        ("SHA3-512", |m| { let h = sha3_512(m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
         "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
    ];

    for &(name, hash_fn, empty_exp, abc_exp) in variants {
        let name = name.to_string();
        let empty_exp = empty_exp.to_string();
        let abc_exp = abc_exp.to_string();

        test_case!(results, format!("{name} — empty"), {
            let hex = hash_fn(b"");
            check!(hex == empty_exp, format!("got {hex}"));
            Ok(())
        });
        test_case!(results, format!("{name} — abc"), {
            let hex = hash_fn(b"abc");
            check!(hex == abc_exp, format!("got {hex}"));
            Ok(())
        });
        // 재현성 테스트
        test_case!(results, format!("{name} — reproducibility"), {
            let h1 = hash_fn(b"same input");
            let h2 = hash_fn(b"same input");
            check!(h1 == h2, "동일 입력에서 다른 해시값");
            let h3 = hash_fn(b"different input");
            check!(h1 != h3, "다른 입력에서 동일 해시값");
            Ok(())
        });
    }

    SuiteResult { suite_name: "SHA-3".to_string(), results }
}

// ─── 7. HMAC ───────────────────────────────────────────

fn suite_hmac() -> SuiteResult {
    let mut results = Vec::new();

    // RFC 4231 핵심 벡터
    let tc1_key = [0x0bu8; 20];
    let tc1_msg = b"Hi There";

    let hmac_variants: &[(&str, fn(&[u8], &[u8]) -> String, &str)] = &[
        ("HMAC-SHA-256", |k, m| { let h = hmac_sha256(k, m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ("HMAC-SHA-224", |k, m| { let h = hmac_sha224(k, m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"),
        ("HMAC-SHA-512", |k, m| { let h = hmac_sha512(k, m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
        ("HMAC-SHA-384", |k, m| { let h = hmac_sha384(k, m); h.iter().map(|b| format!("{b:02x}")).collect() },
         "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
    ];

    for &(name, hmac_fn, expected) in hmac_variants {
        let name = name.to_string();
        let exp = expected.to_string();
        test_case!(results, format!("{name} — RFC 4231 TC1"), {
            let hex = hmac_fn(&tc1_key, tc1_msg);
            check!(hex == exp, format!("got {hex}"));
            Ok(())
        });
    }

    // HMAC-SHA3 계열 — 재현성 + 길이 검증
    let sha3_variants: &[(&str, HashAlgorithm, usize)] = &[
        ("HMAC-SHA3-224", HashAlgorithm::Sha3_224, 28),
        ("HMAC-SHA3-256", HashAlgorithm::Sha3_256, 32),
        ("HMAC-SHA3-384", HashAlgorithm::Sha3_384, 48),
        ("HMAC-SHA3-512", HashAlgorithm::Sha3_512, 64),
    ];
    for &(name, algo, out_len) in sha3_variants {
        let name = name.to_string();
        test_case!(results, format!("{name} — length + reproducibility"), {
            let h1 = hmac(b"key", b"message", algo);
            let h2 = hmac(b"key", b"message", algo);
            check!(h1.len() == out_len, format!("길이 불일치: {}", h1.len()));
            check!(h1 == h2, "재현성 실패");
            Ok(())
        });
    }

    // 검증 함수
    test_case!(results, "HMAC-SHA-256 — verify valid", {
        let tag = hmac(b"key", b"msg", HashAlgorithm::Sha256);
        check!(hmac_verify(b"key", b"msg", &tag, HashAlgorithm::Sha256), "검증 실패");
        Ok(())
    });
    test_case!(results, "HMAC-SHA-256 — reject tampered", {
        let tag = hmac(b"key", b"msg", HashAlgorithm::Sha256);
        check!(!hmac_verify(b"key", b"TAMPERED", &tag, HashAlgorithm::Sha256), "위변조 탐지 실패");
        Ok(())
    });
    test_case!(results, "HMAC-SHA-256 — long key (>block size)", {
        let long_key = [0xaau8; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let h = hmac_sha256(&long_key, msg);
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        check!(hex == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", format!("got {hex}"));
        Ok(())
    });

    SuiteResult { suite_name: "HMAC".to_string(), results }
}

// ─── 8. CMAC ───────────────────────────────────────────

fn suite_cmac() -> SuiteResult {
    let mut results = Vec::new();

    let key128 = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
    let key256 = [0u8; 32];

    // NIST SP 800-38B D.1~D.4
    let nist_cases: &[(&[u8], &str, &str)] = &[
        (&[], "D.1 empty", "bb1d6929e95937287fa37d129b756746"),
        (&[0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a],
         "D.2 16-byte", "070a16b46b4d4144f79bdd9dd04a287c"),
        (&[0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
           0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
           0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11],
         "D.3 40-byte", "dfa66747de9ae63030ca32611497c827"),
        (&[0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
           0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
           0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
           0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10],
         "D.4 64-byte", "51f0bebf7e3b9d92fc49741779363cfe"),
    ];

    for &(msg, desc, expected) in nist_cases {
        let msg = msg.to_vec(); let desc = desc.to_string(); let exp = expected.to_string();
        test_case!(results, format!("NIST SP 800-38B — {desc}"), {
            let tag = aes_cmac(&key128, KeySize::Aes128, &msg);
            let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
            check!(hex == exp, format!("got {hex}"));
            Ok(())
        });
    }

    // AES-256 CMAC
    test_case!(results, "CMAC AES-256 — reproducibility", {
        let msg = b"AES-256 CMAC test";
        let t1 = aes_cmac(&key256, KeySize::Aes256, msg);
        let t2 = aes_cmac(&key256, KeySize::Aes256, msg);
        check!(t1 == t2, "재현성 실패");
        check!(t1.len() == 16, "태그 길이 불일치");
        Ok(())
    });

    // 검증 함수
    test_case!(results, "CMAC — verify valid", {
        let tag = aes_cmac(&key128, KeySize::Aes128, b"verify me");
        check!(aes_cmac_verify(&key128, KeySize::Aes128, b"verify me", &tag), "검증 실패");
        Ok(())
    });
    test_case!(results, "CMAC — reject tampered", {
        let tag = aes_cmac(&key128, KeySize::Aes128, b"original");
        check!(!aes_cmac_verify(&key128, KeySize::Aes128, b"tampered", &tag), "위변조 탐지 실패");
        Ok(())
    });

    SuiteResult { suite_name: "CMAC".to_string(), results }
}

// ═══════════════════════════════════════════════════════
// main
// ═══════════════════════════════════════════════════════

fn main() {
    print_header();

    // 실행할 스위트 목록
    let suite_fns: &[(&str, fn() -> SuiteResult)] = &[
        ("AES Block Cipher",   suite_aes_block),
        ("AES Operation Modes", suite_operation_modes),
        ("AES-GCM",            suite_gcm),
        ("AES-CCM",            suite_ccm),
        ("SHA-2",              suite_sha2),
        ("SHA-3",              suite_sha3),
        ("HMAC",               suite_hmac),
        ("CMAC",               suite_cmac),
    ];

    let total_test_count: usize = 200; // 예상 테스트 수 (진행률 표시용)
    let mut completed = 0usize;
    let mut all_suites: Vec<SuiteResult> = Vec::new();
    let global_start = Instant::now();

    for &(name, suite_fn) in suite_fns {
        // 스위트 실행 (진행률 업데이트하며)
        print_suite_header(name, 0);

        // 내부적으로 테스트 진행 표시
        print_progress(completed, total_test_count, name);
        let suite = suite_fn();

        completed += suite.total();
        print_progress(completed, total_test_count.max(completed), name);

        print_suite_result(&suite);
        all_suites.push(suite);
        println!();
    }

    let total_dur = global_start.elapsed();
    print_final_summary(&all_suites, total_dur);

    // 실패 시 exit code 1
    let any_failed = all_suites.iter().any(|s| !s.all_passed());
    if any_failed {
        std::process::exit(1);
    }
}
