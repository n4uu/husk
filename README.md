# husk

[![ci](https://github.com/n4uu/husk/actions/workflows/ci.yml/badge.svg)](https://github.com/n4uu/husk/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/n4uu/husk.svg)](https://pkg.go.dev/github.com/n4uu/husk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A Cobalt Strike Beacon configuration extractor.** Point it at a PE, a
section dump, or a memory-carved blob, and it recovers the XOR key, decodes
the type-length-value configuration block, and prints the C2 servers, sleep
timers, process-injection technique, and Malleable C2 profile baked into the
implant. That's the same information an incident responder pulls out of a
sample recovered from a compromised host before it goes into a blocklist or
a report.

A from-scratch, clean-room implementation written directly against the wire
format, cross-checked line by line against the public reference
implementation for correctness (see [Format reference](#format-reference)).
No code from it, or any other parser, was copied.

## Demo, no real sample needed

```
$ husk fixture -out sample.bin
wrote synthetic fixture to sample.bin (4608 bytes, key 0x2e)
this is not malware: it's a hand-built config in husk's own test format, for trying `husk parse` end to end

$ husk parse sample.bin
found config in PE section .data at offset 0, key 0x2e (23 settings)

BeaconType                       - HTTPS
Port                              - 443
SleepTime                         - 60000
MaxGetSize                        - 1048576
Jitter                            - 20
MaxDNS                            - 255
C2Server                          - cdn.assets-delivery.invalid,/api/v1/metrics
UserAgent                         - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
HttpPostUri                       - /submit.php
Malleable_C2_Instructions         - Remove 4 bytes from the beginning
                                   base64 decode
PipeName                          - \\.\pipe\msagent_%x
Watermark                         - 305419896
bStageCleanup                     - True
bProcInject_StartRWX              - False
bProcInject_UseRWX                - False
bProcInject_MinAllocSize          - 4096
ProcInject_Execute                - CreateRemoteThread
ProcInject_AllocationMethod       - VirtualAllocEx
Retry_Max_Attempts                - 0
Retry_Increase_Attempts           - 0
Retry_Duration                    - 0
```

(The alignment above is reproduced as printed. `RenderText` left-pads names
to a fixed column width, so this is a byte-for-byte terminal capture, not a
mockup.)

`husk fixture` builds a config with husk's own encoder, the same TLV writer,
XOR routine, and minimal but spec-correct PE builder the test suite uses,
and wraps it in a real `.data` section that husk's PE reader then has to
actually find. There's no Cobalt Strike license involved, no real Beacon,
and nothing here that runs. It's a fixture for testing, not a payload. See
[`internal/beacon/fixture.go`](internal/beacon/fixture.go) and
[`pe_fixture.go`](internal/beacon/pe_fixture.go).

## Install & use

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are on the
[releases page](https://github.com/n4uu/husk/releases/latest). They're built
by GitHub Actions from the tagged commit, never on a workstation, and every
archive carries a signed build provenance attestation:

```sh
gh attestation verify husk_*_linux_amd64.tar.gz -R n4uu/husk
```

To build from source instead:

```sh
git clone https://github.com/n4uu/husk
cd husk
make build
./bin/husk parse suspicious.bin           # human-readable
./bin/husk parse -json suspicious.bin     # for piping into jq / a SIEM
./bin/husk parse -all suspicious.bin      # also show raw stub/shellcode blobs
```

## What the wire format actually is

A Beacon configuration is a run of records. Each one starts with a 6-byte
header, three big-endian `uint16` fields (**index**, **type** (1=short,
2=int, 3=str), and **length**), followed by `length` bytes of value, the
whole thing XORed with a single byte before being embedded in the binary.
Cobalt Strike has shipped exactly two such keys in the wild: `0x69` (Beacon
3) and `0x2e` (Beacon 4).

Three settings carry a further sub-format of their own, each read by its own
decoder in [`transform.go`](internal/beacon/transform.go):

| Setting | Sub-format |
| --- | --- |
| `ProcInject_PrependAppend_x86`/`x64` | Not an opcode stream at all: two length-prefixed byte strings glued around injected shellcode, usually to break naive signature scans of the injected region. |
| `Malleable_C2_Instructions` | An opcode stream describing how the beacon unwraps a server response before treating it as tasking (`remove N bytes`, `base64 decode`, `XOR mask w/ random key`, …). |
| `HttpGet_Metadata` / `HttpPost_Metadata` | A richer opcode stream, the compiled form of a Malleable C2 profile's `client { metadata / output }` blocks, describing how the beacon's session id and task output get smuggled into headers, a URI segment, or POST parameters. |

One field worth knowing about specifically for triage: **PublicKey** (index
7) is rendered with its MD5 alongside the raw bytes, because that hash is a
well-known threat-intel pivot. Cobalt Strike operators routinely reuse one
license's key pair across many otherwise-unrelated-looking C2 deployments,
so a shared PublicKey MD5 across two samples is a stronger infrastructure
link than a shared C2 domain.

## Design notes: where this departs from the reference implementation

The most-used public parser for this format ([Sentinel-One's
`CobaltStrikeParser`](https://github.com/Sentinel-One/CobaltStrikeParser))
works by taking each setting it already knows about, building that setting's
own 6-byte header, and searching the decoded blob for a byte-exact match.
Because a string setting's real length isn't otherwise available to it, it
then retries that search at doubling guessed lengths (16, 32, 64, ... 2048)
until one lands. husk instead walks the blob as a straightforward sequential
TLV stream, reading each entry's actual length directly from its own header.
Two things fall out of that:

- No guessing: a string field's length is data that's read, not a parameter
  that has to be rediscovered by trial and error.
- husk surfaces settings its catalog doesn't recognize yet (a newer Beacon
  version, a nonstandard build) as `unknown_N` instead of silently missing
  them, since it isn't limited to searching for headers it already expects.

The other departure is in locating the key and offset in the first place.
The reference implementation hardcodes the two known keys and locates the
config by searching for fixed byte-signature patterns (what those two known
keys turn a known-plaintext prefix into). husk instead brute-forces every
one of the 256 possible single-byte keys against every candidate offset and
keeps whichever produces the longest run of structurally valid,
catalog-matching entries (see [`recover.go`](internal/beacon/recover.go)).
It's slower, but it would still find a config keyed with a byte other than
the two observed so far, and it never needed those two signatures hardcoded
to work correctly against either of them. The same structural validator is
reused, rather than duplicated, for the second-stage repeating-4-byte-key
heuristic that unwraps a stageless beacon's outer encryption layer.

## Testing

Every decode path (every setting kind, both known XOR keys, the
repeating-key outer layer, PE section extraction, and the "this is not a
config" case) is exercised in `internal/beacon/*_test.go`, against blobs
husk's own encoder built. No external fixtures or real samples are checked
into the repo:

```sh
make test
```

## Limitations

- **Only the two publicly documented Beacon versions' wire layout is
  modeled** (the index/type/length TLV format used by Beacon 3 and 4).
  Newer Cobalt Strike releases have reportedly added further obfuscation on
  top of this base layout in some configurations; husk does not attempt to
  detect or reverse anything beyond the two known single-byte keys and the
  4-byte stageless-encryption layer.
- **Static extraction only.** husk reads a file; it does not attach to a
  running process, unpack a sleep-mask-obfuscated in-memory image, or
  follow a staged loader across a network fetch. A beacon that only
  materializes its config after in-memory decryption at runtime needs to be
  dumped from memory first.
- **The structural validator can, in principle, still be fooled.** Requiring
  five-plus chained, well-typed entries with at least three matching known
  catalog indices makes an accidental match astronomically unlikely on real
  data, but it isn't a cryptographic guarantee. A deliberately adversarial
  blob could, in theory, be crafted to pass it. Treat this as a niche-format
  parser for defensive triage, not a hardened parser for untrusted network
  input.
- **Index 54 is genuinely overloaded** in the format itself, shared between
  `HostHeader` and `SSH_Banner` (see the catalog's doc comment in
  [`settings.go`](internal/beacon/settings.go)). husk always labels it
  `HostHeader`, the far more common case.

## Format reference

The wire format itself was cross-checked against:

- [Sentinel-One/CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser): the reference implementation.
- [SentinelLabs: The Anatomy of an APT Attack and Cobalt Strike Beacon's Encoded Configuration](https://www.sentinelone.com/labs/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/)

## License

MIT, see [LICENSE](LICENSE).
