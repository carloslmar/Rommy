import os, struct, zlib, random
from rommyapp.formats import apply_patch

random.seed(1)
src = bytes(random.randrange(256) for _ in range(5000))

def enc(n):
    o = b''
    while True:
        x = n & 0x7f; n >>= 7
        if n == 0: return o + bytes([0x80 | x])
        o += bytes([x]); n -= 1

def test_ips():
    p = b'PATCH' + (10).to_bytes(3, 'big') + (3).to_bytes(2, 'big') + b'abc' \
        + (20).to_bytes(3, 'big') + b'\0\0' + (4).to_bytes(2, 'big') + b'Z' + b'EOF' + (100).to_bytes(3, 'big')
    t = bytearray(src[:100]); t[10:13] = b'abc'; t[20:24] = b'ZZZZ'
    assert apply_patch(p, src)[1] == bytes(t)

def test_bps():
    t = src[:500] + b'HELLO' + src[500:] + b'HELLO'
    body = b'BPS1' + enc(len(src)) + enc(len(t)) + enc(0)
    body += enc(499 << 2) + enc((4 << 2) | 1) + b'HELLO'
    body += enc((len(src) - 500 - 1) << 2 | 2) + enc(500 << 1)
    body += enc((4 << 2) | 3) + enc(500 << 1)
    body += struct.pack('<II', zlib.crc32(src), zlib.crc32(t))
    p = body + struct.pack('<I', zlib.crc32(body))
    fmt, out, w = apply_patch(p, src)
    assert out == t and not w, w

def test_ups():
    t = bytearray(src); t[5] ^= 0xFF; t[300] ^= 1; t[301] ^= 2; t = bytes(t)
    body = b'UPS1' + enc(len(src)) + enc(len(t)) + enc(5) + b'\xff\0' + enc(300 - 7) + b'\x01\x02\0'
    body += struct.pack('<II', zlib.crc32(src), zlib.crc32(t))
    p = body + struct.pack('<I', zlib.crc32(body))
    fmt, out, w = apply_patch(p, src)
    assert out == t and not w, w
    assert apply_patch(p, t)[1] == src          # reverse

def test_aps_n64():
    p = b'APS10' + b'\0\0' + bytes(50) + struct.pack('<I', 5000) + struct.pack('<IB', 7, 3) + b'xyz' \
        + struct.pack('<IB', 50, 0) + b'Q' + bytes([10])
    t = bytearray(src); t[7:10] = b'xyz'; t[50:60] = b'Q' * 10
    assert apply_patch(p, src)[1] == bytes(t)

def test_ppf3():
    p = b'PPF30' + b'\x02' + bytes(50) + bytes([0, 0, 0, 0]) + struct.pack('<QB', 9, 2) + b'hi'
    t = bytearray(src); t[9:11] = b'hi'
    assert apply_patch(p, src)[1] == bytes(t)

def test_xdelta():
    import shutil, subprocess, tempfile
    x = shutil.which('xdelta3')
    if not x:
        print('xdelta3 binary not found; skipped'); return
    t = src[:2000] + b'inserted bytes!' + src[2000:4000] + src[100:900] + bytes(300)
    with tempfile.TemporaryDirectory() as d:
        a, b, p = (os.path.join(d, n) for n in 'abp')
        open(a, 'wb').write(src); open(b, 'wb').write(t)
        subprocess.run([x, '-e', '-f', '-s', a, b, p], check=True)
        fmt, out, w = apply_patch(open(p, 'rb').read(), src)
    assert fmt == 'Xdelta' and out == t and not w, w

if __name__ == '__main__':
    for k, v in list(globals().items()):
        if k.startswith('test_'):
            v(); print('ok', k)
