<?php

declare(strict_types=1);

namespace Amashukov\Secp256k1\Tests;

use Amashukov\Secp256k1\Secp256k1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Secp256k1::class)]
final class Secp256k1Test extends TestCase
{
    public function testConstantsMatchSecp256k1Spec(): void
    {
        self::assertSame('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', Secp256k1::P_HEX);
        self::assertSame('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', Secp256k1::N_HEX);
        self::assertSame('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', Secp256k1::GX_HEX);
        self::assertSame('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', Secp256k1::GY_HEX);
    }

    public function testPHelperReturnsCurveModulus(): void
    {
        self::assertSame(strtolower(Secp256k1::P_HEX), gmp_strval(Secp256k1::p(), 16));
    }

    public function testNHelperReturnsCurveOrder(): void
    {
        self::assertSame(strtolower(Secp256k1::N_HEX), gmp_strval(Secp256k1::n(), 16));
    }

    public function testGHelperReturnsGeneratorPoint(): void
    {
        $g = Secp256k1::g();
        self::assertSame(strtolower(Secp256k1::GX_HEX), gmp_strval($g['x'], 16));
        self::assertSame(strtolower(Secp256k1::GY_HEX), gmp_strval($g['y'], 16));
    }

    public function testPointAtInfinityIsAdditiveIdentity(): void
    {
        $p        = Secp256k1::p();
        $G        = Secp256k1::g();
        $infinity = ['x' => null, 'y' => null];

        $sum = Secp256k1::pointAdd($infinity, $G, $p);
        if (null === $sum['x'] || null === $sum['y']) {
            self::fail('O + G must equal G, not infinity');
        }
        self::assertSame(gmp_strval($G['x'], 16), gmp_strval($sum['x'], 16));
        self::assertSame(gmp_strval($G['y'], 16), gmp_strval($sum['y'], 16));

        $sum2 = Secp256k1::pointAdd($G, $infinity, $p);
        if (null === $sum2['x'] || null === $sum2['y']) {
            self::fail('G + O must equal G, not infinity');
        }
        self::assertSame(gmp_strval($G['x'], 16), gmp_strval($sum2['x'], 16));
        self::assertSame(gmp_strval($G['y'], 16), gmp_strval($sum2['y'], 16));
    }

    public function testPointPlusNegativeIsPointAtInfinity(): void
    {
        $p    = Secp256k1::p();
        $G    = Secp256k1::g();
        $negG = ['x' => $G['x'], 'y' => gmp_sub($p, $G['y'])];

        $sum = Secp256k1::pointAdd($G, $negG, $p);
        self::assertNull($sum['x']);
        self::assertNull($sum['y']);
    }

    public function testPointDoubleGMatchesScalarMulByTwo(): void
    {
        $p     = Secp256k1::p();
        $G     = Secp256k1::g();
        $two   = gmp_init(2);

        $doubled = Secp256k1::pointDouble($G, $p);
        $scaled  = Secp256k1::scalarMul($G, $two, $p);

        if (null === $doubled['x'] || null === $doubled['y']) {
            self::fail('pointDouble(G) must return a finite point');
        }
        if (null === $scaled['x'] || null === $scaled['y']) {
            self::fail('scalarMul(G, 2) must return a finite point');
        }
        self::assertSame(gmp_strval($doubled['x'], 16), gmp_strval($scaled['x'], 16));
        self::assertSame(gmp_strval($doubled['y'], 16), gmp_strval($scaled['y'], 16));
    }

    public function testScalarMulByOneReturnsSamePoint(): void
    {
        $p   = Secp256k1::p();
        $G   = Secp256k1::g();
        $one = gmp_init(1);

        $result = Secp256k1::scalarMul($G, $one, $p);
        if (null === $result['x'] || null === $result['y']) {
            self::fail('scalarMul(G, 1) must return G, not infinity');
        }
        self::assertSame(gmp_strval($G['x'], 16), gmp_strval($result['x'], 16));
        self::assertSame(gmp_strval($G['y'], 16), gmp_strval($result['y'], 16));
    }

    public function testScalarMulByZeroReturnsPointAtInfinity(): void
    {
        $p      = Secp256k1::p();
        $G      = Secp256k1::g();
        $result = Secp256k1::scalarMul($G, gmp_init(0), $p);

        self::assertNull($result['x']);
        self::assertNull($result['y']);
    }

    public function testScalarMulByCurveOrderReturnsPointAtInfinity(): void
    {
        $p      = Secp256k1::p();
        $n      = Secp256k1::n();
        $G      = Secp256k1::g();
        $result = Secp256k1::scalarMul($G, $n, $p);

        self::assertNull($result['x']);
        self::assertNull($result['y']);
    }

    public function testScalarMulGKnownVectorForK2(): void
    {
        $p  = Secp256k1::p();
        $g  = Secp256k1::g();
        $r  = Secp256k1::scalarMulG(gmp_init(2), $p, $g['x'], $g['y']);

        if (null === $r) {
            self::fail('scalarMulG(2) should return a finite point');
        }
        self::assertSame(
            'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
            gmp_strval($r[0], 16),
        );
        self::assertSame(
            '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a',
            gmp_strval($r[1], 16),
        );
    }

    public function testScalarMulGOnZeroReturnsNull(): void
    {
        $p = Secp256k1::p();
        $g = Secp256k1::g();
        self::assertNull(Secp256k1::scalarMulG(gmp_init(0), $p, $g['x'], $g['y']));
    }

    public function testPointAddOfSamePointDelegatesToPointDouble(): void
    {
        $p = Secp256k1::p();
        $G = Secp256k1::g();

        $sum     = Secp256k1::pointAdd($G, $G, $p);
        $doubled = Secp256k1::pointDouble($G, $p);
        if (in_array(null, [$sum['x'], $sum['y'], $doubled['x'], $doubled['y']], true)) {
            self::fail('G + G must equal 2G, not infinity');
        }
        self::assertSame(gmp_strval($doubled['x'], 16), gmp_strval($sum['x'], 16));
        self::assertSame(gmp_strval($doubled['y'], 16), gmp_strval($sum['y'], 16));
    }

    public function testPointDoubleOfPointAtInfinityReturnsPointAtInfinity(): void
    {
        $p      = Secp256k1::p();
        $result = Secp256k1::pointDouble(['x' => null, 'y' => null], $p);
        self::assertNull($result['x']);
        self::assertNull($result['y']);
    }
}
