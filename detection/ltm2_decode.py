#!/usr/bin/env python3
"""LTM2 protocol dissector — Heyiwei/LTM C2. Structurally parses the handshake + AEAD frames for
triage/IDS validation. Does NOT (and cannot) decrypt: session keys are per-connection X25519 ephemerals.
Feed it the reassembled one-direction TCP payload bytes (client->server or server->client).

Wire format (from RE, x86_64 build; CHLO confirmed against a LIVE capture, real_chlo.bin):
  CHLO (client->server, 104B): "LTM2CHLO" | identity[32] | nonce[32] | X25519 pubkey[32]
      identity[32] = 30-byte ASCII bot-ID (getrandom hex token) null-padded to 32.
  SHLO (server->client,  72B): "LTM2SHLO" | nonce[32]    | X25519 pubkey[32]
  Record (both ways): len(u32) | seq(u64) | Poly1305 tag[16] | ChaCha20( type_byte || payload )
                      (len = payload+1, AAD = the 12B header, nonce = dir IV base + seq, max payload 4096)
"""
import struct, sys

def _u(fmt, buf, off):
    return struct.unpack_from(fmt, buf, off)[0]

def dissect(buf):
    out, off = [], 0
    if buf[:8] == b"LTM2CHLO" and len(buf) >= 104:
        out.append(("CHLO", 0, 104, {"identity": buf[8:40].rstrip(b"\x00").decode("latin1","replace"),
                                      "nonce": buf[40:72].hex(), "x25519_pub": buf[72:104].hex()}))
        off = 104
    elif buf[:8] == b"LTM2SHLO" and len(buf) >= 72:
        out.append(("SHLO", 0, 72, {"nonce": buf[8:40].hex(), "x25519_pub": buf[40:72].hex()}))
        off = 72
    # AEAD records: pick endianness that yields a sane (<=4097) length
    while off + 28 <= len(buf):
        cand = []
        for endi, f in (("LE","<"), ("BE",">")):
            ln = _u(f+"I", buf, off); sq = _u(f+"Q", buf, off+4)
            if 1 <= ln <= 4097 and off+28+ln <= len(buf): cand.append((endi, ln, sq))
        if not cand: break
        endi, ln, sq = cand[0]
        tag = buf[off+12:off+28]; ct = buf[off+28:off+28+ln]
        out.append(("RECORD", off, 28+ln, {"endian": endi, "seq": sq, "ct_len": ln,
                                            "tag": tag.hex(), "ct_head": ct[:8].hex()}))
        off += 28+ln
    return out

def looks_like_ltm2(buf):
    return buf[:8] in (b"LTM2CHLO", b"LTM2SHLO")

if __name__ == "__main__":
    data = open(sys.argv[1],"rb").read() if len(sys.argv) > 1 else sys.stdin.buffer.read()
    if not looks_like_ltm2(data):
        print("not an LTM2 stream (no CHLO/SHLO magic at offset 0)"); sys.exit(1)
    for kind, o, sz, f in dissect(data):
        print(f"[{o:5}] {kind:7} ({sz:4}B)  {f}")
