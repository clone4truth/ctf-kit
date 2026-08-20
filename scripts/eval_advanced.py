#!/usr/bin/env python3
"""Deterministic advanced release gate for exploit-oriented CTF primitives."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import ctfkit.modules  # noqa: F401,E402
from ctfkit.flagmeta import extract_flag_candidates  # noqa: E402
from ctfkit.registry import execute_tool  # noqa: E402


def _is_prime(value: int) -> bool:
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value < 2 or any(value % prime == 0 for prime in small):
        return value in small
    d, shifts = value - 1, 0
    while d % 2 == 0:
        shifts += 1
        d //= 2
    for base in (2, 3, 5, 7, 11, 13, 17):
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                break
        else:
            return False
    return True


def _next_prime(value: int) -> int:
    value |= 1
    while not _is_prime(value):
        value += 2
    return value


def _cases() -> list[dict]:
    flag = b"flag{fermat_real_decrypt}"
    p = _next_prime((1 << 127) + 12_345)
    q = _next_prime(p + 2_000)
    n, e = p * q, 65_537
    ciphertext = pow(int.from_bytes(flag, "big"), e, n)
    known, secret = b"known-plaintext-ctf-data", b"flag{gcm_nonce_reuse_ok}"
    stream = bytes((i * 73 + 19) % 256 for i in range(max(len(known), len(secret))))
    c1 = bytes(a ^ b for a, b in zip(known, stream))
    c2 = bytes(a ^ b for a, b in zip(secret, stream))
    return [
        {"id": "crypto-rsa-fermat-decrypt", "category": "crypto", "tool": "rsa_fermat",
         "args": {"n": n, "e": e, "ciphertext": ciphertext}, "contains": [flag.decode()]},
        {"id": "crypto-gcm-known-plaintext", "category": "crypto", "tool": "aes_gcm_nonce_reuse",
         "args": {"ct1_hex": c1.hex(), "ct2_hex": c2.hex(), "pt1_hex": known.hex()}, "contains": [secret.decode()]},
        {"id": "pwn-ret2libc-chain", "category": "pwn", "tool": "ret2libc_payload_gen",
         "args": {"buffer_offset": 72, "pop_rdi_gadget": "0x40123a", "bin_sh_addr": "0x7ffff7f6a152",
                  "system_addr": "0x7ffff7e12340", "ret_gadget": "0x40101a"},
         "contains": ["offset = 72", "p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)"]},
        {"id": "pwn-format-write", "category": "pwn", "tool": "fmtstr_payload_gen",
         "args": {"offset": 6, "target_addr": "0x404040", "write_val": "0x1337"},
         "contains": ["0x0000000000404040", "%4919c%6$hn"]},
        {"id": "rev-repeating-xor", "category": "rev", "tool": "binary_xor_search",
         "args": {"path": "testdata/xor_flag.bin", "target_prefix": "flag{"}, "contains": ["flag{xor_binary_recovered}"]},
        {"id": "web-layered-url", "category": "web", "tool": "url_deobfuscator",
         "args": {"url": "https%253A%252F%252Fctf.local%252Fflag%257Burl_layers_removed%257D"},
         "contains": ["https://ctf.local/flag{url_layers_removed}"]},
        {"id": "forensics-tar-header", "category": "forensics", "tool": "tar_header_analyze",
         "args": {"path": "testdata/evidence.tar"}, "contains": ["evidence/flag{tar_header_found}.txt", "0640"]},
    ]


def main() -> int:
    started, results = time.perf_counter(), []
    for case in _cases():
        result = execute_tool(case["tool"], case["args"])
        passed = result["ok"] and result["category"] == case["category"] and all(
            value in result["text"] for value in case["contains"]
        )
        flags = [item["value"] for item in extract_flag_candidates(result["text"])]
        results.append({"id": case["id"], "category": case["category"], "passed": passed,
                        "status": result["status"], "flags": flags})
        print(f"{'PASS' if passed else 'FAIL'} {case['id']}: status={result['status']} flags={flags}")
    passed_count = sum(item["passed"] for item in results)
    gate_passed = passed_count == len(results)
    report = {"schema_version": 1, "gate": "advanced-release", "passed": gate_passed,
              "score_cap_10": 10.0 if gate_passed else 9.5,
              "summary": {"passed": passed_count, "total": len(results)},
              "categories": sorted({item["category"] for item in results if item["passed"]}),
              "elapsed_seconds": round(time.perf_counter() - started, 3), "cases": results}
    path = ROOT / "evals" / "latest_advanced_report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"ADVANCED GATE: {'PASS' if gate_passed else 'FAIL'} {passed_count}/{len(results)}; score cap={report['score_cap_10']}/10")
    print(f"Report: {path}")
    return 0 if gate_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
