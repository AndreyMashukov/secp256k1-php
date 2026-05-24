<?php

declare(strict_types=1);

namespace Amashukov\Secp256k1;

use GMP;
use InvalidArgumentException;

final class Ecdsa
{
    private function __construct() {}

    /**
     * @param string $msgHash 32 raw bytes (the message hash actually signed; e.g. keccak256)
     * @param int    $v       recovery flag (0 or 1)
     * @param string $r       32 raw bytes
     * @param string $s       32 raw bytes
     *
     * @return null|string 65 raw bytes uncompressed public key, or null on failure
     */
    public static function recover(string $msgHash, int $v, string $r, string $s): ?string
    {
        if (32 !== strlen($msgHash) || 32 !== strlen($r) || 32 !== strlen($s)) {
            throw new InvalidArgumentException('msgHash, r, s must each be exactly 32 bytes.');
        }
        if (0 !== $v && 1 !== $v) {
            throw new InvalidArgumentException('v must be 0 or 1.');
        }

        $p  = Secp256k1::p();
        $n  = Secp256k1::n();
        $G  = Secp256k1::g();

        $rInt = gmp_import($r);
        $sInt = gmp_import($s);
        $z    = gmp_import($msgHash);

        if (gmp_cmp($rInt, 1) < 0 || gmp_cmp($rInt, gmp_sub($n, gmp_init(1))) > 0) {
            return null;
        }
        if (gmp_cmp($sInt, 1) < 0 || gmp_cmp($sInt, gmp_sub($n, gmp_init(1))) > 0) {
            return null;
        }
        if (gmp_cmp($rInt, $p) >= 0) {
            return null;
        }

        $x  = $rInt;
        $y2 = gmp_mod(gmp_add(gmp_powm($x, gmp_init(3), $p), gmp_init(7)), $p);
        $y  = gmp_powm($y2, gmp_div_q(gmp_add($p, gmp_init(1)), gmp_init(4)), $p);

        if (0 !== gmp_cmp(gmp_mod(gmp_mul($y, $y), $p), $y2)) {
            return null;
        }

        if (gmp_intval(gmp_mod($y, gmp_init(2))) !== $v) {
            $y = gmp_sub($p, $y);
        }

        $R = ['x' => $x, 'y' => $y];

        $rInv = gmp_invert($rInt, $n);
        if (false === $rInv) {
            return null;
        }

        $u1  = gmp_mod(gmp_mul(gmp_sub($n, gmp_mod($z, $n)), $rInv), $n);
        $u2  = gmp_mod(gmp_mul($sInt, $rInv), $n);
        $pub = Secp256k1::pointAdd(
            Secp256k1::scalarMul($G, $u1, $p),
            Secp256k1::scalarMul($R, $u2, $p),
            $p,
        );

        if (null === $pub['x'] || null === $pub['y']) {
            return null;
        }

        $xHex = str_pad(gmp_strval($pub['x'], 16), 64, '0', STR_PAD_LEFT);
        $yHex = str_pad(gmp_strval($pub['y'], 16), 64, '0', STR_PAD_LEFT);

        return hex2bin('04' . $xHex . $yHex) ?: null;
    }

    /**
     * @param string $msgHash 32 raw bytes
     * @param string $pubKey  65 raw bytes uncompressed (`04 || x || y`)
     * @param string $r       32 raw bytes
     * @param string $s       32 raw bytes
     */
    public static function verify(string $msgHash, string $pubKey, string $r, string $s): bool
    {
        if (32 !== strlen($msgHash) || 32 !== strlen($r) || 32 !== strlen($s)) {
            return false;
        }
        if (65 !== strlen($pubKey) || "\x04" !== $pubKey[0]) {
            return false;
        }

        $p = Secp256k1::p();
        $n = Secp256k1::n();
        $G = Secp256k1::g();

        $rInt = gmp_import($r);
        $sInt = gmp_import($s);
        $z    = gmp_import($msgHash);

        if (gmp_cmp($rInt, 1) < 0 || gmp_cmp($rInt, gmp_sub($n, gmp_init(1))) > 0) {
            return false;
        }
        if (gmp_cmp($sInt, 1) < 0 || gmp_cmp($sInt, gmp_sub($n, gmp_init(1))) > 0) {
            return false;
        }

        $px = gmp_import(substr($pubKey, 1, 32));
        $py = gmp_import(substr($pubKey, 33, 32));

        $sInv = gmp_invert($sInt, $n);
        if (false === $sInv) {
            return false;
        }

        $u1     = gmp_mod(gmp_mul($z, $sInv), $n);
        $u2     = gmp_mod(gmp_mul($rInt, $sInv), $n);
        $result = Secp256k1::pointAdd(
            Secp256k1::scalarMul($G, $u1, $p),
            Secp256k1::scalarMul(['x' => $px, 'y' => $py], $u2, $p),
            $p,
        );

        if (null === $result['x']) {
            return false;
        }

        return 0 === gmp_cmp(gmp_mod($result['x'], $n), $rInt);
    }

    /**
     * @param string $msgHash 32 raw bytes
     * @param string $privKey 32 raw bytes (must be in [1, n-1])
     *
     * @return array{r: string, s: string, v: int}
     */
    public static function sign(string $msgHash, string $privKey): array
    {
        if (32 !== strlen($msgHash)) {
            throw new InvalidArgumentException('msgHash must be exactly 32 bytes.');
        }
        if (32 !== strlen($privKey)) {
            throw new InvalidArgumentException('privKey must be exactly 32 bytes.');
        }

        $p = Secp256k1::p();
        $n = Secp256k1::n();
        $G = Secp256k1::g();

        $d = gmp_import($privKey);
        if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, gmp_sub($n, gmp_init(1))) > 0) {
            throw new InvalidArgumentException('privKey must be in [1, n-1].');
        }

        $z = gmp_import($msgHash);

        $hLen = 32;
        $V    = str_repeat("\x01", $hLen);
        $K    = str_repeat("\x00", $hLen);

        $intOctets = self::int2octets($d, $n, $hLen);
        $bitsOctets = self::bits2octets($z, $n, $hLen);

        $K = hash_hmac('sha256', $V . "\x00" . $intOctets . $bitsOctets, $K, true);
        $V = hash_hmac('sha256', $V, $K, true);
        $K = hash_hmac('sha256', $V . "\x01" . $intOctets . $bitsOctets, $K, true);
        $V = hash_hmac('sha256', $V, $K, true);

        while (true) {
            $T = '';
            while (strlen($T) < $hLen) {
                $V = hash_hmac('sha256', $V, $K, true);
                $T .= $V;
            }
            $k = self::bits2int(substr($T, 0, $hLen), $n);
            if (gmp_cmp($k, 1) >= 0 && gmp_cmp($k, gmp_sub($n, gmp_init(1))) <= 0) {
                $kG = Secp256k1::scalarMul($G, $k, $p);
                if (null !== $kG['x'] && null !== $kG['y']) {
                    $rInt = gmp_mod($kG['x'], $n);
                    if (gmp_cmp($rInt, 0) > 0) {
                        $kInv = gmp_invert($k, $n);
                        if (false !== $kInv) {
                            $sInt = gmp_mod(gmp_mul($kInv, gmp_add($z, gmp_mul($rInt, $d))), $n);
                            if (gmp_cmp($sInt, 0) > 0) {
                                $v = gmp_intval(gmp_mod($kG['y'], gmp_init(2)));
                                $halfN = gmp_div_q($n, gmp_init(2));
                                if (gmp_cmp($sInt, $halfN) > 0) {
                                    $sInt = gmp_sub($n, $sInt);
                                    $v ^= 1;
                                }

                                return [
                                    'r' => str_pad(gmp_export($rInt), 32, "\x00", STR_PAD_LEFT),
                                    's' => str_pad(gmp_export($sInt), 32, "\x00", STR_PAD_LEFT),
                                    'v' => $v,
                                ];
                            }
                        }
                    }
                }
            }
            $K = hash_hmac('sha256', $V . "\x00", $K, true);
            $V = hash_hmac('sha256', $V, $K, true);
        }
    }

    private static function int2octets(GMP $x, GMP $n, int $hLen): string
    {
        $bytes = gmp_export(gmp_mod($x, $n));

        return str_pad($bytes, $hLen, "\x00", STR_PAD_LEFT);
    }

    private static function bits2octets(GMP $z, GMP $n, int $hLen): string
    {
        $reduced = gmp_mod($z, $n);

        return self::int2octets($reduced, $n, $hLen);
    }

    private static function bits2int(string $bytes, GMP $n): GMP
    {
        $value = gmp_import($bytes);
        $blen  = strlen($bytes) * 8;
        $qlen  = strlen(gmp_strval($n, 2));
        if ($blen > $qlen) {
            $value = gmp_div_q($value, gmp_pow(gmp_init(2), $blen - $qlen));
        }

        return $value;
    }
}
