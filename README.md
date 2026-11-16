# Heyiwei / LTM2 — a bespoke encrypted-C2 Linux RAT

Heyiwei is a ground-up custom, multi-architecture Linux backdoor that spreads to IoT and Linux hosts
through an ADB/telnet stager. It is **not** Mirai or Gafgyt. It carries its own named, fully engineered
encrypted transport — **LTM2** — built from X25519 key exchange, a keyed-BLAKE2b key schedule, and
XChaCha20-Poly1305 authenticated records. It had run roughly a year with no public documentation and
near-zero antivirus coverage before it was caught by a honeypot's ADB decoy.

This repository documents the transport protocol, the key schedule, the capability set, and detection
material (Suricata rules + a passive dissector).

| | |
|---|---|
| **Family** | Heyiwei (instance/campaign); internal framework name "LTM"; transport "LTM2" |
| **Class** | Remote-access backdoor (RAT) — shell / exec / file push / file pull |
| **Platforms** | Linux, 11 arch builds (x86-64, i686, i586, aarch64, ARM v4l–v7l, MIPS, MIPSEL) |
| **Crypto** | X25519 · XChaCha20-Poly1305 · keyed BLAKE2b (Monocypher-shaped) |
| **AV coverage** | i686 build **0/75** on VirusTotal; others only the generic `trojan.mirai` bucket |
| **DDoS code** | **none** — not a booter, despite the `mc.` / port-25565 camouflage |

> **Scope.** Full analysis is of the x86-64 build (the only one not string-obfuscated). The other ten
> architectures share the LTM2 protocol and the same four-service dispatch but were not individually
> decompiled. Family labels from third-party AV engines were treated as leads and overridden only against
> primary analysis. The key schedule is documented here but **not** published as a runnable decryptor.

---

## Lineage — why it isn't Mirai

The generic `trojan.mirai` label is what lets a serious custom implant pass as commodity noise. The
distinction is structural: Heyiwei shares no strings, config format, or attack-table layout with either
common family.

| Trait | Mirai | Gafgyt / Bashlite | **Heyiwei / LTM2** |
|---|---|---|---|
| Config | single-byte XOR table | plaintext | X25519 + BLAKE2b schedule |
| C2 transport | near-plaintext TLV | plaintext ASCII (`PING`, `GETLOCALIP`) | XChaCha20-Poly1305 AEAD |
| Command set | DDoS attack table (`attack_*`) | flood methods (`attack_*.c`) | shell / exec / push / pull |
| Shared strings | yes, well-known | yes, well-known | none |

Automated triage first flagged "Speck / Salsa20 / RC4." Those were false positives — Salsa20's
quarter-round is structurally identical to ChaCha's, and the "RC4" 256-byte buffer is locale parsing, not a
cipher. The real stack, confirmed by the constants and the label strings left in the clear, is **X25519 +
XChaCha20-Poly1305 + keyed BLAKE2b** — the shape of [Monocypher](https://monocypher.org/).

---

## The LTM2 transport

LTM2 is a compact, Noise-flavored channel: ephemeral ECDH, a transcript-bound key schedule, then
per-direction authenticated records.

```
client ──  LTM2CHLO  (104 bytes)  ─▶  server      ephemeral X25519 pub + bot-ID + nonce
client ◀──  LTM2SHLO  ( 72 bytes)  ──  server      ephemeral X25519 pub + nonce
           │
           └─ both derive X25519 shared secret → keyed-BLAKE2b schedule → per-direction key+IV → AEAD
```

Everything after the server-hello is encrypted; the only fixed markers on the wire are the two 8-byte magics.

### Client-Hello (104 bytes)

Confirmed against a live 104-byte capture (a running sample resolved its C2 to a lab sink and sent this
before any reply):

| Offset | Len | Field |
|---:|---:|---|
| 0  | 8  | `"LTM2CHLO"` magic |
| 8  | 30 | bot-ID — ASCII hex token from `getrandom`, fresh per infection |
| 38 | 2  | `00 00` pad to 32 |
| 40 | 32 | nonce |
| 72 | 32 | X25519 ephemeral public key |

The identity field is the human-readable per-device bot-ID, null-padded — not an opaque blob. The
Server-Hello mirrors it at 72 bytes: `"LTM2SHLO" | nonce[32] | server_pub[32]`.

### Key schedule

Straight out of the decompiled x86-64 build (Ghidra decompiler names kept, primitives annotated). The
shared secret is the **key** of a keyed hash, and the **entire** client-hello and server-hello are absorbed
into the master, binding every session key to the exact handshake transcript:

```c
/* master = BLAKE2b( key = X25519 shared secret,
                     data = "LTM2 session master" || CHLO || SHLO ) */
FUN_00407587(ctx, 0x20, shared, 0x20);                 // keyed init, key = 32-byte shared secret
FUN_004076c7(ctx, "LTM2 session master", 0x13);        // absorb 19-byte label
FUN_004076c7(ctx, chlo, 0x68);                         // absorb the full 104-byte CHLO
FUN_004076c7(ctx, shlo, 0x48);                         // absorb the full  72-byte SHLO
FUN_004076d6(ctx, master);                             // finalize -> 32-byte session master

/* two 48-byte directional secrets, each keyed by the master */
FUN_0040775b(c2s, 0x30, master, 0x20, "LTM2 client to server", 0x15);  // -> key[32] | iv[16]
FUN_0040775b(s2c, 0x30, master, 0x20, "LTM2 server to client", 0x15);  // -> key[32] | iv[16]
```

A clean-room reimplementation reproduces it exactly:

```python
master = blake2b(b"LTM2 session master" + chlo + shlo, key=shared, digest_size=32)
c2s    = blake2b(b"LTM2 client to server",             key=master, digest_size=48)
s2c    = blake2b(b"LTM2 server to client",             key=master, digest_size=48)
# key, iv = dir[:32], dir[32:48]   (per direction)
```

This is competent, modern cryptographic engineering — the opposite of a reused XOR byte, and nothing any
IoT-bot family ships.

### AEAD record framing

Every post-handshake byte is one record. Header integers are **big-endian** — the one ordering that makes
the whole thing validate — and the 12-byte header is reused verbatim as AEAD associated data.

```
record = [ len:u32 BE ] [ seq:u64 BE ] [ tag:16B Poly1305 ] [ XChaCha20( type || payload ) ]
         └──────── 12-byte header = AEAD associated data ────────┘
         len   = len(payload) + 1               # +1 is the type byte
         nonce = dir_IV[0:16] || seq(BE, 8)      # HChaCha20 subkey from IV, 8-byte inner nonce
         seq   per-direction, from 0, strictly incrementing (anti-replay, enforced by the bot)
         max payload 4096
```

### Application layer

Inside the AEAD the application protocol is binary: one type byte, then a payload. The design is
SSH-connection-shaped (channels, windows, exit status), not a botnet's flat command list. Only one channel
is open at a time.

| Type | Dir | Meaning | Payload |
|---|---|---|---|
| `0x01` | c→s | beacon | `host=… arch=… kernel=<uname -r> uid=…\0` |
| `0x02` | s→c | ack (required right after beacon, or the bot aborts) | empty |
| `0x03` / `0x04` | s→c / c→s | ping / pong | empty |
| `0x0A` | s→c | **open shell** — PTY `/bin/sh -i` | 8-byte winsize |
| `0x0B` | s→c | **open exec** — `/bin/sh -c "<cmd>"` | command, NUL-term |
| `0x0C` | s→c | **open push** — write file to victim | `[hdr][dest\0]` |
| `0x0D` | s→c | **open pull** — read file from victim | `src path\0` |
| `0x14` | both | data | raw channel bytes |
| `0x15` | s→c | window | 8-byte winsize (`TIOCSWINSZ`) |
| `0x16` / `0x17` | s→c | file-commit / eof | size + BLAKE2b-256 |
| `0x18` / `0x19` / `0x1b` | c→s | open-ack / channel-exit / eof-ack | ack; 4-byte status; ack |

---

## Validation — the break

The key schedule was not guessed. A lab LTM2 *server* (pure reimplementation of X25519, keyed BLAKE2b, and
XChaCha20-Poly1305, self-tested against RFC 7748 / 8439 and the XChaCha vectors) was stood up to talk only
to a captured sample in an isolated victim VM. It completed the handshake, derived the session keys, and
**the Poly1305 tag verified on the very first record** — a wrong schedule fails the MAC, so a first-try
verify means every label, length, endianness, and nonce construction is exactly right.

Decrypted type-1 beacon:

```
seq=0  type=1 (beacon)  len=61
host=<hostname> arch=i686 kernel=5.4.0-216-generic uid=0\x00
```

All four services were then exercised end-to-end against the sample: interactive shell, one-shot exec, and
file push/pull — the last two each carrying an unkeyed BLAKE2b-256 integrity trailer, with push staged to a
temp name and atomically renamed only after the hash checks out.

---

## Capabilities — a four-service RAT, and no flood code

The decrypted channel offers exactly four services: interactive **shell**, one-shot **exec**, file
**push**, file **pull**. The "no DDoS" finding is confirmed, not assumed — a complete inventory of every
socket call site in the x86-64 build found only C2 TCP, the DNS resolver, and one local Unix socket:

```
no SOCK_RAW      no IP_HDRINCL     no bind / listen / accept
no flood loop    no attack dispatch no rival-bot kill-list
only: C2 TCP  ·  DNS resolver (UDP/TCP)  ·  one AF_UNIX
```

Port **25565** is simply the C2 port — it blends with Minecraft traffic and the `mc.` subdomain is
camouflage, not evidence of a booter. The net threat is heavier than a flood bot: a persistent, encrypted,
interactive foothold with arbitrary file read and write on every infected device.

---

## Build and persistence

Static, stripped ELF built with **GCC 15.2.0 on a current (2025) Ubuntu toolchain**, in 11 architectures.
The x86-64 build was not string-obfuscated the way the 32-bit builds are — which is how the config, the
persistence paths, and the LTM2 label strings were readable. The loader calls itself "Heyiwei stager v3";
its author's own English developer comments reference a prior run on a 54-device list and a MIPS-endianness
bug they fixed — a competent, iterating operator.

Persistence is comprehensive and multi-init: systemd, SysV + rcS, OpenRC, OpenWrt `rc.common`, and a custom
control script. It installs to `/usr/local/bin/Heyiwei`, single-instances on `/tmp/Heyiwei.lock`, and
masquerades in the process table as the kernel thread `khungtaskd`.

---

## Detection

The two 8-byte handshake magics are the one reliable fixed marker on an otherwise fully encrypted channel.
Rules are port-agnostic (the C2 can move off 25565); the CHLO rule was confirmed exact against a live
104-byte Client-Hello.

- [`detection/ltm2.rules`](detection/ltm2.rules) — Suricata signatures for the CHLO / SHLO magics.
- [`detection/ltm2_decode.py`](detection/ltm2_decode.py) — passive dissector; parses the handshake and walks
  the AEAD framing for triage. It cannot decrypt (session keys are per-connection ephemerals) but reliably
  identifies and structures an LTM2 stream from one direction of capture.

---

## Indicators of compromise

**C2**
```
mc.heyiwei.net   TCP 25565
apex heyiwei.net parked 185.53.179.146 / .128, 199.59.243.228   (NS *.dyna-ns.net)
```

**Protocol magics**
```
LTM2CHLO   (104 bytes, client -> server)
LTM2SHLO   ( 72 bytes, server -> client)
```

**Host artifacts**
```
/usr/local/bin/Heyiwei
/tmp/Heyiwei.lock
/etc/ltm/Heyiwei-control
/etc/systemd/system/Heyiwei.service      (Environment=HEYIWEI_SERVICE=1)
process masquerades as  khungtaskd
```

**Delivery**
```
loader on :8080 colocated with the C2
second loader   143.246.56.120:8080
delivered by    45.144.52.239            (H2NEXUS Cloud, UAE)
```

**Samples (SHA-256)**
```
x86-64   62e2b8a6c75cde2ec395c34ac5055be0d0c51d796e93d37b2f1681a833693896
i686     cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5
```

---

*TLP:CLEAR. Detection content and IOCs are free to use. No malware binaries are distributed in this
repository.*

## License

[MIT](LICENSE) — the writeup, Suricata rules, and dissector are free to use, modify, and redistribute.
