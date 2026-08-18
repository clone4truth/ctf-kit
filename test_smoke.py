"""Smoke test semua tool (tanpa framework). Jalankan: python test_smoke.py"""
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
]

failed = 0
for name, args in TESTS:
    out = run_tool(name, args)
    ok = "ERROR" not in out
    if not ok:
        failed += 1
    print(f"{'OK  ' if ok else 'FAIL'} {name}: {out.splitlines()[0][:90] if out else ''}")

print(f"\n{len(TESTS) - failed}/{len(TESTS)} passed, {failed} failed")