<?php

declare(strict_types=1);

namespace Amashukov\Secp256k1;

use GMP;

final class Secp256k1
{
    public const string P_HEX  = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';

    public const string N_HEX  = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';

    public const string GX_HEX = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';

    public const string GY_HEX = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';

    private function __construct() {}

    public static function p(): GMP
    {
        return gmp_init('0x' . self::P_HEX);
    }

    public static function n(): GMP
    {
        return gmp_init('0x' . self::N_HEX);
    }

    /**
     * @return array{x: GMP, y: GMP}
     */
    public static function g(): array
    {
        return [
            'x' => gmp_init('0x' . self::GX_HEX),
            'y' => gmp_init('0x' . self::GY_HEX),
        ];
    }

    /**
     * @param array{x: null|GMP, y: null|GMP} $P
     * @param array{x: null|GMP, y: null|GMP} $Q
     *
     * @return array{x: null|GMP, y: null|GMP}
     */
    public static function pointAdd(array $P, array $Q, GMP $p): array
    {
        if (null === $P['x'] || null === $P['y']) {
            return $Q;
        }
        if (null === $Q['x'] || null === $Q['y']) {
            return $P;
        }

        [$px, $py, $qx, $qy] = [$P['x'], $P['y'], $Q['x'], $Q['y']];

        if (0 === gmp_cmp($px, $qx)) {
            if (0 !== gmp_cmp($py, $qy)) {
                return ['x' => null, 'y' => null];
            }

            return self::pointDouble($P, $p);
        }

        $inv = gmp_invert(gmp_sub($qx, $px), $p);
        if (false === $inv) {
            return ['x' => null, 'y' => null];
        }
        $lam = gmp_mod(gmp_mul(gmp_sub($qy, $py), $inv), $p);
        $rx  = gmp_mod(gmp_sub(gmp_sub(gmp_mul($lam, $lam), $px), $qx), $p);
        $ry  = gmp_mod(gmp_sub(gmp_mul($lam, gmp_sub($px, $rx)), $py), $p);

        return ['x' => $rx, 'y' => $ry];
    }

    /**
     * @param array{x: null|GMP, y: null|GMP} $P
     *
     * @return array{x: null|GMP, y: null|GMP}
     */
    public static function pointDouble(array $P, GMP $p): array
    {
        if (null === $P['x'] || null === $P['y']) {
            return $P;
        }

        [$px, $py] = [$P['x'], $P['y']];

        $denom = gmp_invert(gmp_mul(gmp_init(2), $py), $p);
        if (false === $denom) {
            return ['x' => null, 'y' => null];
        }
        $lam = gmp_mod(
            gmp_mul(gmp_mul(gmp_init(3), gmp_mul($px, $px)), $denom),
            $p,
        );
        $rx = gmp_mod(gmp_sub(gmp_mul($lam, $lam), gmp_mul(gmp_init(2), $px)), $p);
        $ry = gmp_mod(gmp_sub(gmp_mul($lam, gmp_sub($px, $rx)), $py), $p);

        return ['x' => $rx, 'y' => $ry];
    }

    /**
     * @param array{x: null|GMP, y: null|GMP} $point
     *
     * @return array{x: null|GMP, y: null|GMP}
     */
    public static function scalarMul(array $point, GMP $scalar, GMP $p): array
    {
        $result = ['x' => null, 'y' => null];
        $addend = $point;

        while (gmp_cmp($scalar, 0) > 0) {
            if (1 === gmp_intval(gmp_mod($scalar, gmp_init(2)))) {
                $result = self::pointAdd($result, $addend, $p);
            }
            $addend = self::pointDouble($addend, $p);
            $scalar = gmp_div_q($scalar, gmp_init(2));
        }

        return $result;
    }

    /**
     * @return null|array{0: GMP, 1: GMP}
     */
    public static function scalarMulG(GMP $k, GMP $p, GMP $Gx, GMP $Gy): ?array
    {
        $result = self::scalarMul(['x' => $Gx, 'y' => $Gy], $k, $p);

        if (null === $result['x'] || null === $result['y']) {
            return null;
        }

        return [$result['x'], $result['y']];
    }
}
