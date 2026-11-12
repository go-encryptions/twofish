<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/twofish" width="720"></p>

# go-encryptions/twofish

[![ci](https://github.com/go-encryptions/twofish/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/twofish/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-encryptions/twofish.svg)](https://pkg.go.dev/github.com/go-encryptions/twofish)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go **Twofish** block cipher (Schneier et al., 1998) as a standard `crypto/cipher.Block`: 16-byte blocks, 16-, 24- and 32-byte keys. Table-driven, no cgo, no dependency outside the standard library. It replaces the deprecated `golang.org/x/crypto/twofish` in [`go-fde/veracrypt`](https://github.com/go-fde/veracrypt) (tracked in go-fde/veracrypt#3).

## Install

```sh
go get github.com/go-encryptions/twofish
```

## Usage

```go
import "github.com/go-encryptions/twofish"

block, err := twofish.NewCipher(key) // 16, 24 or 32 bytes
if err != nil {
	// a twofish.KeySizeError for any other length
}
block.Encrypt(dst[:16], src[:16]) // dst and src may be the same slice
block.Decrypt(dst[:16], src[:16]) // a buffer under 16 bytes panics
```

The contract is that of `cipher.Block`. The value returned also has two methods, found with a type assertion:

```go
type blocks interface {
	EncryptBlocks(dst, src []byte) // ECB over len(src)/16 blocks
	DecryptBlocks(dst, src []byte)
}
```

They give the same bytes as calling `Encrypt` on each block, about 2.4 times faster, because four blocks go through the rounds side by side (see Performance). `len(src)` must be a multiple of 16 and `dst` at least as long; in-place use is allowed.

## Not constant-time

The key-dependent S-boxes and the MDS matrix are folded into four 256-entry tables of 32-bit words per key (4 KiB). Those look-ups use secret-dependent addresses, so **table lookups are not constant-time**: the cipher is exposed to cache-timing attacks by a local attacker. The key schedule is not constant-time either. Do not use it where that matters.

## Verification

- `testdata/kat/`: the designers' reference known-answer tests (`twofish-kat.zip`): `ecb_tbl` (tables and MDS, 147 vectors), `ecb_vk` (variable key, 576), `ecb_vt` (variable plaintext, 384), all three key sizes, encrypted and decrypted; and the ECB encrypt and decrypt Monte Carlo tests (400 outer iterations of 10000 chained operations per key size, 1200 records each), replayed in full.
- `testdata/botan-twofish.vec`: Botan's own `src/tests/data/block/twofish.vec`, 723 vectors.
- `testdata/botan-diff.vec`: a differential corpus of 600 random keys (16, 24 and 32 bytes in turn; the first six are all-zero and all-one) and blocks generated from the Botan 3.14.1 command line by `internal/genbotan` (`go run ./internal/genbotan`; it needs `botan` on the `PATH`).
- `EncryptBlocks` and `DecryptBlocks` are checked against block-by-block `Encrypt` and `Decrypt` for 0 to 11 blocks, all key sizes, in and out of place.
- `FuzzRoundTrip`: round trips and refusal of every key length but 16, 24 and 32; CI runs it for 60 seconds, its corpus is in `testdata/fuzz`.
- CI: race detector and a 100 % statement-coverage gate on amd64 and arm64; the same tests under QEMU on big-endian s390x and on riscv64; `govulncheck`. Under the race detector and QEMU the Monte Carlo tests run shortened (`-short`); a full run is a separate CI step.

## Implementation

A port of the paper's structure: the permutations `q0` and `q1` built from their 4-bit tables (section 4.3.5), the MDS matrix over GF(2^8)/0x169 (section 4.2), the Reed-Solomon matrix over GF(2^8)/0x14d for the S-box keys (section 4.3), the function `h` and the subkey schedule (section 4.3). Following Botan's structure, key setup expands the S-boxes and the MDS matrix into four tables, so `g` is four look-ups and a round is eight, with the 8-bit rotation of the second word folded into the choice of table. In `Encrypt` the round keys are added off the critical path (`X = u + K`, `Y = u + (g1 + K')` with `u = g0 + g1`).

Bibliography opened: Schneier et al., "Twofish: A 128-Bit Block Cipher" (1998); the designers' reference KAT and Monte Carlo files; Botan 3.14.1 `src/lib/block/twofish/twofish.cpp` and `twofish.h` (BSD-2) and `twofish.vec`. `golang.org/x/crypto/twofish` was not copied; it is benchmarked.

## Performance

Reference: Botan 3.14.1 (`botan speed --buf-size=1024 Twofish`, wrapped as Go benchmarks by `internal/botanbench` so that `abbench` can interleave it), 256-bit key, 1 KiB buffer of 64 blocks, Apple M4 Max (arm64), one core (`GOMAXPROCS=1`), 6 interleaved rounds by `abbench --max-load 8`, summarised with `benchstat`; every result file holds 12 `^Benchmark` lines. Botan's scalar code is used on this CPU (its AVX-512 path does not apply).

| 1 KiB, one core | encrypt | decrypt |
|---|---|---|
| this package, `EncryptBlocks` / `DecryptBlocks` | 1.305 µs ± 2 % (749 MiB/s) | 1.287 µs ± 2 % (759 MiB/s) |
| Botan 3.14.1 | 1.726 µs ± 2 % (566 MiB/s) | 1.733 µs ± 2 % (564 MiB/s) |
| this package, `Encrypt` / `Decrypt` one block at a time | 3.161 µs ± 5 % (309 MiB/s) | 3.147 µs ± 5 % (310 MiB/s) |
| `golang.org/x/crypto/twofish`, one block at a time | 6.888 µs ± 4 % (142 MiB/s) | 6.863 µs ± 1 % (142 MiB/s) |

The batch path is **1.32x faster than Botan**. The one-block path, which is what a caller going through `cipher.Block` gets (as `go-encryptions/xts` does), is **2.2x faster than x/crypto but 1.8x slower than Botan**: a single block is a chain of 16 dependent rounds, each waiting for its table loads, so it is bound by latency, not by the number of operations; Botan reaches its figure by running two blocks side by side, which `cipher.Block` cannot express. The bounds checks are gone from that path and the key additions are off the critical chain; the remaining gap is tracked as an issue. Callers able to hand over several blocks at once should use `EncryptBlocks`.

Reproduce: `go test -c -o twofish.test .`, `go test -c -o botan.test ./internal/botanbench`, then `abbench --base ./twofish.test --head ./botan.test --max-load 8 -n 6 --base-arg='-test.bench=^Benchmark(En|De)cryptBlocks$' --head-arg=-test.bench=. --rename-base EncryptBlocks=Encrypt --rename-base DecryptBlocks=Decrypt -- -test.run '^$'`; the x/crypto side is the separate module `internal/xcryptobench`.

## License

BSD-3-Clause © the go-encryptions/twofish authors.
