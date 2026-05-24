# secp256k1-php

secp256k1 elliptic-curve arithmetic, ECDSA sign/verify, and EIP-191 (`personal_sign`) signature recovery in pure PHP on top of `ext-gmp`.

## Status

Pre-1.0. Public API may change before the 1.0 tag.

## Requirements

- PHP 8.3+
- `ext-gmp`

No composer dependencies.

## Credits

secp256k1 code path lifted from [`simplito/elliptic-php`](https://github.com/simplito/elliptic-php). Curve parameters from SEC 2 (<https://www.secg.org/sec2-v2.pdf>).

## License

MIT License.
