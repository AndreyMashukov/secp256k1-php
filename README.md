# amashukov/secp256k1-php

Pure-PHP secp256k1 elliptic-curve arithmetic and RFC 6979 deterministic ECDSA — sign, verify and recover for Ethereum and Bitcoin signatures.

[![CI](https://img.shields.io/github/actions/workflow/status/AndreyMashukov/secp256k1-php/ci.yml?branch=main&label=CI)](https://github.com/AndreyMashukov/secp256k1-php/actions)
[![PHPStan L9](https://img.shields.io/github/actions/workflow/status/AndreyMashukov/secp256k1-php/stan.yml?branch=main&label=PHPStan%20L9)](https://github.com/AndreyMashukov/secp256k1-php/actions)
[![Latest Version](https://img.shields.io/packagist/v/amashukov/secp256k1-php)](https://packagist.org/packages/amashukov/secp256k1-php)
[![Downloads](https://img.shields.io/packagist/dt/amashukov/secp256k1-php)](https://packagist.org/packages/amashukov/secp256k1-php)
[![PHP](https://img.shields.io/packagist/dependency-v/amashukov/secp256k1-php/php)](https://packagist.org/packages/amashukov/secp256k1-php)
[![License](https://img.shields.io/packagist/l/amashukov/secp256k1-php)](LICENSE)
[![Stars](https://img.shields.io/github/stars/AndreyMashukov/secp256k1-php?style=social)](https://github.com/AndreyMashukov/secp256k1-php)

`amashukov/secp256k1-php` implements the secp256k1 elliptic curve and ECDSA signature primitives in pure PHP on top of `ext-gmp`. It covers point arithmetic, RFC 6979 deterministic signing, signature verification and public-key recovery — the building blocks behind Ethereum and Bitcoin signatures, EIP-191 / EIP-712 signer derivation and EVM wallet tooling. Two static classes:

- **`Secp256k1`** — curve constants (`P`, `N`, `Gx`, `Gy`) and point arithmetic (`pointAdd`, `pointDouble`, `scalarMul`, `scalarMulG`).
- **`Ecdsa`** — RFC 6979 deterministic `sign`, `verify`, and `recover` (the latter is what EIP-191 / EIP-712 implementations call to derive a public key from a signature triple).

The package is a leaf primitive — it ships with zero composer dependencies (`ext-gmp` + `ext-hash` from PHP core), and the EIP-191 / EIP-712 message-prefix hashing belongs in a downstream package that owns the keccak / domain-separator step.

## Features

- **secp256k1 curve arithmetic** — `pointAdd`, `pointDouble`, `scalarMul`, `scalarMulG` over GMP big integers.
- **RFC 6979 deterministic ECDSA** — same input always yields the same signature; no entropy source required.
- **Canonical low-S signatures** — two clients signing the same payload produce byte-identical output.
- **Public-key recovery** — derive the `04 || x || y` uncompressed key from a `(v, r, s)` triple, the EIP-191 / EIP-712 signer step.
- **Validated public surface** — malformed lengths and out-of-range scalars are rejected.
- **Zero composer dependencies** — `ext-gmp` + `ext-hash` only.
- PHPStan level 9 clean, `@PER-CS` formatted, CI-tested.

## Why amashukov/secp256k1-php

`simplito/elliptic-php` is a fine general-purpose elliptic-curve library, but it is curve-agnostic and carries the machinery for many curves. `amashukov/secp256k1-php` is single-curve by design: it focuses exclusively on secp256k1 and the ECDSA operations EVM and Bitcoin tooling actually need — deterministic RFC 6979 signing, canonical low-S output and `(v, r, s)` recovery — with a smaller, audited surface and zero composer dependencies.

## Installation

```bash
composer require amashukov/secp256k1-php
```

## Usage

### Curve arithmetic

```php
use Amashukov\Secp256k1\Secp256k1;

$p  = Secp256k1::p();   // curve modulus
$n  = Secp256k1::n();   // curve order
$G  = Secp256k1::g();   // generator point ['x' => GMP, 'y' => GMP]

// Public key from a 32-byte private key.
$priv = hex2bin('c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4');
$d    = gmp_import($priv);
$pub  = Secp256k1::scalarMul($G, $d, $p); // ['x' => GMP, 'y' => GMP]
```

### Deterministic ECDSA sign (RFC 6979)

```php
use Amashukov\Secp256k1\Ecdsa;

$msgHash = hex2bin('5e89218a87e0bd6df9fdc62af4a8a87f48c44fcab6cdeefd6c6d3fcdcad1b48d'); // 32 bytes
$privKey = hex2bin('c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4'); // 32 bytes

$signature = Ecdsa::sign($msgHash, $privKey);
// → ['r' => 32 bytes, 's' => 32 bytes, 'v' => 0|1]
```

Signatures are deterministic per RFC 6979 (same input → same output) and returned in canonical low-S form, so two clients signing the same payload produce byte-identical signatures.

### Verify

```php
$pubKey = "\x04" . str_pad(gmp_export($pub['x']), 32, "\x00", STR_PAD_LEFT)
                 . str_pad(gmp_export($pub['y']), 32, "\x00", STR_PAD_LEFT);

$ok = Ecdsa::verify($msgHash, $pubKey, $signature['r'], $signature['s']);
```

### Recover (EIP-191 / EIP-712 step)

```php
// Given a (v, r, s) signature triple from an EVM wallet:
$pubKey = Ecdsa::recover($msgHash, $signature['v'], $signature['r'], $signature['s']);
// → 65 raw bytes uncompressed (`04 || x || y`), or null on failure
```

The recovered public key can then be hashed (keccak-256 of `x || y` → take last 20 bytes) to derive the signer's Ethereum address.

## Requirements

- PHP 8.3+
- `ext-gmp`
- `ext-hash` (bundled with PHP core; used for HMAC-SHA256 in RFC 6979 nonce derivation)

No composer dependencies.

## Security notes

- **Not constant-time.** `Secp256k1::scalarMul` walks the scalar bit-by-bit with conditional adds — it leaks timing information about secret scalars. Use this package for signing only when the resulting timing channel is acceptable for the deployment (server-side signing of own keys is generally fine; never use it to handle attacker-controlled scalars on shared hardware).
- **No side-channel hardening.** No blinding, no constant-time inversion.
- **Validated inputs.** `Ecdsa::recover` and `Ecdsa::sign` reject malformed lengths and out-of-range scalars at the public surface.

## Related packages

Part of a modular pure-PHP blockchain toolkit:

| Package | Purpose |
|---|---|
| [amashukov/keccak-php](https://github.com/AndreyMashukov/keccak-php) | Keccak-256 / SHA-3 / SHAKE hashing |
| [amashukov/secp256k1-php](https://github.com/AndreyMashukov/secp256k1-php) | secp256k1 ECDSA sign / verify / recover |
| [amashukov/rlp-php](https://github.com/AndreyMashukov/rlp-php) | Ethereum RLP encode / decode |
| [amashukov/ton-cell-php](https://github.com/AndreyMashukov/ton-cell-php) | TON TLB Cell / Builder / Slice / BOC |
| [amashukov/eip1559-tx-signer-php](https://github.com/AndreyMashukov/eip1559-tx-signer-php) | EIP-1559 transaction signer |
| [amashukov/abi-encoder-php](https://github.com/AndreyMashukov/abi-encoder-php) | Ethereum ABI encoder |
| [amashukov/eth-rpc-client-php](https://github.com/AndreyMashukov/eth-rpc-client-php) | Ethereum JSON-RPC client |
| [amashukov/eth-php](https://github.com/AndreyMashukov/eth-php) | EVM umbrella package |

## Quality

- PHPStan level 9.
- php-cs-fixer with the `@PER-CS` ruleset.
- GitHub Actions CI on every push.
- Test vectors validated against the SEC 2 / RFC 6979 reference outputs.

## References

- SEC 2: Recommended Elliptic Curve Domain Parameters — <https://www.secg.org/sec2-v2.pdf>
- RFC 6979 — Deterministic ECDSA — <https://www.rfc-editor.org/rfc/rfc6979>

## License

MIT License.
