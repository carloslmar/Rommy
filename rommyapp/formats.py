"""Pure-Python decoders for IPS, BPS, UPS, APS, PPF, RUP (NINJA2) and Xdelta (VCDIFF)."""
import hashlib
import lzma
import struct
import zlib

#Ok, jokes aside. This one was mostly AI. I didn't quite know how to work with ROM formats, and ended up fucking up the PPF patching.
#For real though, I corrupted my Snatcher ISO so bad, all I got was a black screen with broken pixels.
class PatchError(Exception):
    pass


class R:
    """Tiny byte reader."""
    def __init__(s, b, pos=0):
        s.b, s.p = b, pos

    def u8(s):
        v = s.b[s.p]; s.p += 1; return v

    def n(s, k):
        if s.p + k > len(s.b):
            raise IndexError
        v = s.b[s.p:s.p + k]; s.p += k; return v

    def le(s, k):
        return int.from_bytes(s.n(k), 'little')

    def eof(s):
        return s.p >= len(s.b)


def put(out, off, data):
    if off > len(out):
        out.extend(bytes(off - len(out)))
    out[off:off + len(data)] = data


def xor_into(out, off, data):
    if off >= len(out):
        return
    data = data[:len(out) - off]
    k = len(data)
    v = int.from_bytes(out[off:off + k], 'little') ^ int.from_bytes(data, 'little')
    out[off:off + k] = v.to_bytes(k, 'little')


def resize(b, n):
    b = bytearray(b[:n])
    b.extend(bytes(n - len(b)))
    return b


def chunk(b, o, n):
    c = bytes(b[o:o + n])
    return c + bytes(n - len(c))


# ---------------------------------------------------------------- IPS
def ips(p, rom):
    out, r = bytearray(rom), R(p, 5)
    while True:
        h = r.n(3)
        if h == b'EOF':
            if len(p) - r.p == 3:
                del out[int.from_bytes(r.n(3), 'big'):]
            break
        off = int.from_bytes(h, 'big')
        size = int.from_bytes(r.n(2), 'big')
        if size:
            data = r.n(size)
        else:
            cnt = int.from_bytes(r.n(2), 'big')
            data = r.n(1) * cnt
        put(out, off, data)
    return out, []


# ---------------------------------------------------------------- BPS / UPS
def vint(r):
    d, s = 0, 1
    while True:
        x = r.u8()
        d += (x & 0x7f) * s
        if x & 0x80:
            return d
        s <<= 7
        d += s


def bps(p, rom):
    end = len(p) - 12
    sc, tc, pc = struct.unpack_from('<III', p, end)
    if zlib.crc32(p[:end + 8]) != pc:
        raise PatchError('Patch file is corrupt (checksum mismatch).')
    r = R(p, 4)
    ssz, tsz = vint(r), vint(r)
    r.n(vint(r))
    warn = []
    if len(rom) != ssz or zlib.crc32(rom) != sc:
        warn.append('The ROM does not match the one this patch was made for.')
    out, o, sr, tr = bytearray(tsz), 0, 0, 0
    while r.p < end:
        d = vint(r)
        c, n = d & 3, (d >> 2) + 1
        if c == 0:
            out[o:o + n] = chunk(rom, o, n)
        elif c == 1:
            out[o:o + n] = r.n(n)
        elif c == 2:
            x = vint(r); sr += -(x >> 1) if x & 1 else x >> 1
            out[o:o + n] = chunk(rom, sr, n); sr += n
        else:
            x = vint(r); tr += -(x >> 1) if x & 1 else x >> 1
            for i in range(n):
                out[o + i] = out[tr + i]
            tr += n
        o += n
    if len(out) != tsz:
        raise PatchError('Patch produced a wrong-sized file.')
    if zlib.crc32(out) != tc:
        warn.append('Output checksum does not match the patch.')
    return out, warn


def ups(p, rom):
    end = len(p) - 12
    sc, tc, pc = struct.unpack_from('<III', p, end)
    if zlib.crc32(p[:-4]) != pc:
        raise PatchError('Patch file is corrupt (checksum mismatch).')
    r = R(p, 4)
    isz, osz = vint(r), vint(r)
    warn, rc = [], zlib.crc32(rom)
    if rc == tc and rc != sc:
        osz, tc = isz, sc
        warn.append('ROM is already patched; reverting the patch.')
    elif rc != sc:
        warn.append('The ROM does not match the one this patch was made for.')
    out, off = resize(rom, osz), 0
    while r.p < end:
        off += vint(r)
        while True:
            x = r.u8()
            if off < osz:
                out[off] ^= x
            off += 1
            if x == 0:
                break
    if zlib.crc32(out) != tc:
        warn.append('Output checksum does not match the patch.')
    return out, warn


# ---------------------------------------------------------------- APS
def aps(p, rom):
    if p[:5] == b'APS10':                       # N64 APS
        r = R(p, 5)
        htype = r.u8(); r.u8(); r.n(50)
        if htype == 1:
            r.n(17)
        out = resize(rom, r.le(4))
        while not r.eof():
            off, n = r.le(4), r.u8()
            if n == 0:
                v = r.n(1); n = r.u8(); data = v * n
            else:
                data = r.n(n)
            put(out, off, data)
    else:                                       # GBA APS
        r = R(p, 4)
        r.le(4)
        out = resize(rom, r.le(4))
        while not r.eof():
            off = r.le(4); r.n(4)
            xor_into(out, off, r.n(0x10000))
    return out, []


# ---------------------------------------------------------------- PPF
def ppf(p, rom):
    v = p[3] - 48
    if v not in (1, 2, 3):
        raise PatchError('Unknown PPF version.')
    tail = p.rfind(b'@BEGIN_FILE_ID.DIZ')
    body = p[:tail] if tail > 0 else p
    r, out, warn, ofs, undo = R(body, 5), bytearray(rom), [], 4, False
    r.u8(); r.n(50)
    if v == 2:
        if r.le(4) != len(rom):
            warn.append('ROM size differs from the one this patch expects.')
        r.n(1024)
    elif v == 3:
        r.u8(); block = r.u8(); undo = bool(r.u8()); r.u8(); ofs = 8
        if block:
            r.n(1024)
    while not r.eof():
        off, n = r.le(ofs), r.u8()
        put(out, off, r.n(n))
        if undo:
            r.n(n)
    return out, warn


# ---------------------------------------------------------------- RUP (NINJA2)
def rup(p, rom):
    r = R(p, 0x800)

    def vlv():
        return int.from_bytes(r.n(r.u8()), 'little')

    entries = []
    while not r.eof():
        c = r.u8()
        if c == 0:
            break
        if c == 1:
            r.n(vlv()); r.u8()
            e = dict(ssz=vlv(), tsz=vlv(), sm=r.n(16), tm=r.n(16), ov=b'', recs=[])
            if e['ssz'] != e['tsz']:
                r.u8()
                e['ov'] = bytes(b ^ 0xFF for b in r.n(vlv()))
            entries.append(e)
        elif c == 2:
            off = vlv()
            entries[-1]['recs'].append((off, r.n(vlv())))
        else:
            raise PatchError('Unknown RUP command.')
    if not entries:
        raise PatchError('RUP patch contains no files.')
    md5 = hashlib.md5(rom).digest()
    e = next((x for x in entries if x['sm'] == md5), None)
    warn = []
    if e is None:
        e = entries[0]
        warn.append('The ROM does not match the one this patch was made for.')

    def run(advance):
        out = bytearray(rom[:e['tsz']] if e['tsz'] <= len(rom) else rom + e['ov'])
        pos = 0
        for off, data in e['recs']:
            pos += off
            xor_into(out, pos, data)
            if advance:
                pos += len(data)
        return out
    out = run(True)
    if hashlib.md5(out).digest() != e['tm']:
        alt = run(False)                         # tolerate the other offset convention
        if hashlib.md5(alt).digest() == e['tm']:
            out = alt
        else:
            warn.append('Output checksum does not match the patch.')
    return out, warn


# ---------------------------------------------------------------- Xdelta / VCDIFF
def _table():
    t = [((2, 0, 0), (0, 0, 0))]
    t += [((1, s, 0), (0, 0, 0)) for s in range(18)]
    for m in range(9):
        t.append(((3, 0, m), (0, 0, 0)))
        t += [((3, s, m), (0, 0, 0)) for s in range(4, 19)]
    for m in range(6):
        for c in (4, 5, 6):
            for a in range(1, 5):
                t.append(((1, a, 0), (3, c, m)))
    for m in range(6, 9):
        for a in range(1, 5):
            t.append(((1, a, 0), (3, 4, m)))
    for m in range(9):
        t.append(((3, 4, m), (1, 1, 0)))
    assert len(t) == 256
    return t


_T = _table()


def vcd_int(r):
    v = 0
    while True:
        b = r.u8()
        v = (v << 7) | (b & 0x7f)
        if not b & 0x80:
            return v


def _secondary(raw, sec):
    if sec != 2:
        raise PatchError('Xdelta patch uses unsupported secondary compression (only LZMA is supported).')
    rr = R(raw)
    n = vcd_int(rr)
    return lzma.LZMADecompressor().decompress(raw[rr.p:])[:n]


def xdelta(p, rom):
    if p[3] != 0:
        raise PatchError('Unsupported VCDIFF version.')
    r = R(p, 4)
    hi, sec = r.u8(), None
    if hi & 1:
        sec = r.u8()
    if hi & 2:
        raise PatchError('Custom VCDIFF code tables are not supported.')
    if hi & 4:
        r.n(vcd_int(r))
    out, warn = bytearray(), []
    while not r.eof():
        wi = r.u8()
        src = b''
        if wi & 3:
            sz, pos = vcd_int(r), vcd_int(r)
            src = bytes((rom if wi & 1 else out)[pos:pos + sz])
        wend = vcd_int(r); wend += r.p
        tlen, di = vcd_int(r), r.u8()
        dl, il, al = vcd_int(r), vcd_int(r), vcd_int(r)
        ck = int.from_bytes(r.n(4), 'big') if wi & 4 else None
        secs = []
        for n, bit in ((dl, 1), (il, 2), (al, 4)):
            raw = r.n(n)
            secs.append(_secondary(raw, sec) if di & bit else raw)
        dr, ir, ar = R(secs[0]), R(secs[1]), R(secs[2])
        tgt, near, ns, same, sl = bytearray(), [0] * 4, 0, [0] * 768, len(src)
        while not ir.eof():
            for t, s, m in _T[ir.u8()]:
                if t == 0:
                    continue
                if s == 0:
                    s = vcd_int(ir)
                if t == 1:
                    tgt += dr.n(s)
                elif t == 2:
                    tgt += dr.n(1) * s
                else:
                    here = sl + len(tgt)
                    if m == 0:
                        a = vcd_int(ar)
                    elif m == 1:
                        a = here - vcd_int(ar)
                    elif m < 6:
                        a = near[m - 2] + vcd_int(ar)
                    else:
                        a = same[(m - 6) * 256 + ar.u8()]
                    near[ns] = a; ns = (ns + 1) % 4; same[a % 768] = a
                    if a + s <= sl:
                        tgt += src[a:a + s]
                    elif a >= sl and a - sl + s <= len(tgt):
                        tgt += tgt[a - sl:a - sl + s]
                    else:
                        for i in range(s):
                            x = a + i
                            tgt.append(src[x] if x < sl else tgt[x - sl])
        if len(tgt) != tlen:
            raise PatchError('Xdelta window size mismatch.')
        if ck is not None and zlib.adler32(tgt) != ck:
            warn.append('Checksum mismatch in Xdelta window (wrong ROM?).')
        out += tgt
        r.p = wend
    return out, warn


# ---------------------------------------------------------------- front door
def detect(p):
    if p[:5] == b'PATCH': return 'IPS'
    if p[:4] == b'BPS1': return 'BPS'
    if p[:4] == b'UPS1': return 'UPS'
    if p[:4] == b'APS1': return 'APS'
    if p[:3] == b'PPF': return 'PPF'
    if p[:6] == b'NINJA2': return 'RUP'
    if p[:3] == b'\xd6\xc3\xc4': return 'Xdelta'
    raise PatchError('Unrecognised patch format.')


_F = dict(IPS=ips, BPS=bps, UPS=ups, APS=aps, PPF=ppf, RUP=rup, Xdelta=xdelta)


def apply_patch(patch, rom):
    """Returns (format_name, patched_bytes, warnings)."""
    fmt = detect(patch)
    try:
        out, warn = _F[fmt](patch, rom)
    except (IndexError, struct.error, ValueError, lzma.LZMAError):
        raise PatchError('The patch file is truncated or corrupt.')
    return fmt, bytes(out), warn
