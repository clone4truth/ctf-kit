"""Smoke test semua tool (tanpa framework). Jalankan: python tests/test_smoke.py"""
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
os.chdir(REPO_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import ctfkit.modules  # noqa
from ctfkit.registry import run_tool

TESTS = [
    ("decode_all", {"data": "aGVsbG8gY3RmIQ=="}),
    ("decode_base", {"encoded": "SSdtIGtpZGRpbmcgeW91ciBicmFpbiwgbGlrZSBhIHRyZWFzdHVyZSBoYXJkIGZpbmRpbmcu", "base": 64}),
    ("morse", {"text": ".... . .-.. .-.. ---"}),
    ("brainfuck", {"code": "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.", "input_str": ""}),
    ("encode_url", {"text": "hello world!", "decode": False}),
    ("encode_html_entities", {"text": "<script>alert(1)</script>", "decode": False}),
    ("encode_unicode_escapes", {"text": "flag{uni}", "decode": False}),
    ("caesar", {"text": "Spwwz Hzpwwoi", "shift": -1}),
    ("atbash", {"text": "Svool Dliow!"}),
    ("affine", {"text": "ufhkfwj", "a": -1, "b": 0}),
    ("vigenere", {"ciphertext": "LXFOPVEFRNHR", "key": "LEMON"}),
    ("beaufort", {"ciphertext": "XQIQMDQF", "key": "KEY"}),
    ("playfair", {"ciphertext": "BMODZBXDNABEKUDMUIXMMOUVIF", "key": "MONARCHY"}),
    ("hill", {"ciphertext": "WWVA", "a": 2, "b": 5, "c": 9, "d": 7}),
    ("columnar", {"ciphertext": "ECXTEETEAEAMX", "key": "KEY", "decrypt": True}),
    ("bacon", {"text": "BAABBAABAAABABBBAAAAABABB", "variant": "24"}),
    ("railfence", {"text": "WECRLTEERDSOEEFEAOCAIVDEN", "rails": 3, "decrypt": True}),
    ("vigenere_keylength", {"ciphertext": "DAZHIASXQWEPOIUYTRASDFGHJKLOIUYTREWQASDFGHJKLPOIUYTREWQ"}),
    ("rot47", {"text": "r~>E6@"}),
    ("frequency", {"text": "the quick brown fox jumps over the lazy dog"}),
    ("xor_brute", {"data_hex": "1b1e15101b1e15101b1e15101b1e15101b1e15101b1e1510", "key_length": 1}),
    ("xor_keyed", {"data_hex": "0102030405", "key_hex": "01"}),
    ("rsa_decrypt", {"n": 61 * 53, "e": 17, "ciphertext": pow(2, 17, 61 * 53)}),
    ("rsa_small_e", {"n": 1000000007, "e": 3, "ciphertext": 27}),
    ("hash_identify", {"hash_str": "e99a18c428cb38d5f260853678922e03"}),
    ("hash_generate", {"text": "flag", "algorithm": "md5"}),
    ("hash_crack_common", {"hash_hex": "7b4b55f98f7d1a2e9f6b1a1c2d3e4f5a"}),
    ("aes_cbc_bitflip", {"block_hex": "00112233445566778899aabbccddeeff", "original": "AAAAAAAAAAAAAAAA", "target": "admin=true;role=1x"}),
    ("stego_metadata", {"image_path": "testdata/meta2.png"}),
    ("stego_png_chunks", {"image_path": "testdata/meta2.png"}),
    ("stego_lsb", {"image_path": "testdata/lsb.png", "plane": "lsb", "channel": "rgb", "bit_order": "lsb-first", "max_bytes": 64}),
    ("stego_compare", {"path_a": "testdata/lsb.png", "path_b": "testdata/meta2.png"}),
    ("stego_gif_frames", {"gif_path": "testdata/test.gif", "out_dir": "testdata/gif_frames"}),
    ("file_type", {"path": "testdata/meta2.png"}),
    ("strings_extract", {"path": "testdata/blob.bin", "min_len": 5, "encoding": "both"}),
    ("hexdump", {"path": "testdata/blob.bin", "offset": 0, "length": 64, "group": 8}),
    ("carve", {"file_path": "testdata/blob.bin", "out_dir": "testdata/carved"}),
    ("zlib_hunt", {"file_path": "testdata/zlib.bin"}),
    ("entropy_map", {"file_path": "testdata/blob.bin", "block_size": 512}),
    ("pcap_http", {"pcap_path": "testdata/test.pcap", "max_flows": 5}),
    ("jwt_decode", {"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmbGFnIjoiZmxhZ3tqd3R9In0.abc"}),
    ("jwt_forge", {"header_json": '{"alg":"none","typ":"JWT"}', "payload_json": '{"user":"admin"}', "secret": ""}),
    ("http_request", {"url": "http://example.com/", "method": "GET", "headers_csv": "", "timeout": 10, "max_body": 2000}),
    ("payload_encoders", {"payload": "' OR 1=1-- -"}),
    ("sqli_payloads", {"kind": "auth_bypass"}),
    ("elf_info", {"path": "testdata/dummy.elf"}),
    ("checksec", {"path": "testdata/dummy.elf"}),
    ("rop_gadgets", {"path": "testdata/dummy.elf", "pattern": ""}),
    ("shellcode_x64", {"kind": "execve_sh", "xor_key": "0xaa"}),
    ("shellcode_x64", {"kind": "xor", "xor_key": "0xaa"}),
    ("debruijn", {"length": 200}),
    ("debruijn_find", {"substring": "abba"}),
    ("dns_query", {"domain": "example.com", "record": "A"}),
    ("dns_reverse", {"ip": "8.8.8.8"}),
    # --- New Encoding Tools ---
    ("decode_base45", {"encoded": "%69 VD92EX0"}),
    ("decode_base91", {"encoded": ">Ecl bloom"}),
    ("encode_zero_width", {"secret": "flag{zw}", "cover_text": "CTF"}),
    ("decode_zero_width", {"text": "C\u200b\u200c\u200b\u200c\u200b\u200c\u200b\u200cTF"}),
    ("decode_chain", {"data": "WVhWc2JHOXdaWEpmWVc1a2FYTnBZMlZzYm10bGJtUnZkR0ZzZVRwd1pYSnZJSGQxZFhSbGJuUnZZM2xzWlNCb2IzVnlaVzVu", "max_depth": 5}),
    # --- New Crypto Tools ---
    ("rsa_wiener", {"n": 160523347, "e": 6072897, "ciphertext": 0}),
    ("rsa_fermat", {"n": 1000000007 * 1000000009, "e": 65537, "ciphertext": 0, "max_iter": 1000}),
    ("rsa_common_modulus", {"n": 3233, "e1": 17, "e2": 19, "c1": pow(42, 17, 3233), "c2": pow(42, 19, 3233)}),
    ("rsa_hastad", {"ciphertexts_csv": f"{pow(3, 3, 101)}, {pow(3, 3, 103)}, {pow(3, 3, 107)}", "moduli_csv": "101, 103, 107", "e": 3}),
    ("rsa_parse_key", {"key_data_or_path": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7vbqajDw4o6gJy8SGKdwDe3Pn\nyN1I5a3G8aQUhI1F8V+pX9w3+7uJjN9W7xL1C2y3q4Z4o5Jk9a0b1c2d3e4f5g==\n-----END PUBLIC KEY-----"}),
    ("xor_crib_drag", {"ct1_hex": "1b1e15101b1e1510", "crib": "flag{"}),
    ("lcg_solve", {"states_csv": "25, 40, 55, 70, 85, 100", "m": 101}),
    ("hash_length_extension", {"original_data": "user=guest", "append_data": "&role=admin", "original_hash": "e99a18c428cb38d5f260853678922e03", "key_length": 16, "algorithm": "md5"}),
    # --- New Stego Tools ---
    ("png_fix_ihdr", {"image_path": "testdata/corrupt_ihdr.png"}),
    ("stego_audio_wav", {"wav_path": "testdata/audio.wav", "bit_plane": 0}),
    ("stego_dtmf_detect", {"wav_path": "testdata/audio.wav"}),
    # --- New Forensics Tools ---
    ("pcap_dns_exfil", {"pcap_path": "testdata/test.pcap"}),
    ("pcap_usb_keystrokes", {"pcap_path": "testdata/test.pcap"}),
    ("zip_fix_pseudo_encrypt", {"zip_path": "testdata/pseudo.zip"}),
    ("exif_gps_map", {"image_path": "testdata/meta2.png"}),
    # --- New Web Tools ---
    ("ssti_payloads", {"engine": "jinja2", "command": "id"}),
    ("revshell_generator", {"ip": "10.10.14.5", "port": 4444, "shell_type": "bash", "encoding": "raw"}),
    ("php_filter_chain", {"resource": "flag.php", "action": "base64"}),
    ("ssrf_obfuscator", {"ip_or_host": "127.0.0.1", "port": 80}),
    ("jwt_key_confusion", {"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.sig", "rsa_public_key_pem": "test_public_key_bytes"}),
    # --- New Rev & Pwn Tools ---
    ("pe_info", {"path": "testdata/dummy.exe"}),
    ("fmtstr_payload_gen", {"offset": 6, "target_addr": "0x404020", "write_val": "0x1337", "arch": "64"}),
    ("pwn_template", {"binary_path": "./vuln", "remote_host": "chall.ctf.org", "remote_port": 1337}),
    ("pyc_magic_info", {"pyc_path_or_hex": "a70d0d0a"}),
    ("shellcode_multi", {"arch": "x86", "kind": "execve_sh"}),
    # --- New Master Triage Tool ---
    ("triage_file", {"path": "testdata/meta2.png"}),
    # --- Autonomous Memory & Skill Tools ---
    ("remember_challenge", {"title": "Smoke Test Chall", "category": "crypto", "tool": "rsa_fermat", "flag": "flag{smoke_test}", "note": "factored close primes"}),
    ("recall_knowledge", {"query": "rsa fermat"}),
]

failed = 0
for name, args in TESTS:
    out = run_tool(name, args)
    ok = "ERROR" not in out
    if not ok:
        failed += 1
    print(f"{'OK  ' if ok else 'FAIL'} {name}: {out.splitlines()[0][:90] if out else ''}")

print(f"\n{len(TESTS) - failed}/{len(TESTS)} passed, {failed} failed")
if failed > 0:
    sys.exit(1)
