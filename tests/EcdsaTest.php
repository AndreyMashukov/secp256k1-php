<?php

declare(strict_types=1);

namespace Amashukov\Secp256k1\Tests;

use Amashukov\Secp256k1\Ecdsa;
use Amashukov\Secp256k1\Secp256k1;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Ecdsa::class)]
final class EcdsaTest extends TestCase
{
    private const string PRIV_HEX = 'c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4';

    private const string MSG_HASH_HEX = '5e89218a87e0bd6df9fdc62af4a8a87f48c44fcab6cdeefd6c6d3fcdcad1b48d';

    public function testSignRoundtripsThroughRecover(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);

        $sig = Ecdsa::sign($hash, $priv);
        self::assertSame(32, strlen($sig['r']));
        self::assertSame(32, strlen($sig['s']));
        self::assertTrue(0 === $sig['v'] || 1 === $sig['v']);

        $expected = $this->publicKeyFromPriv($priv);
        $recovered = Ecdsa::recover($hash, $sig['v'], $sig['r'], $sig['s']);
        self::assertSame(bin2hex($expected), bin2hex((string) $recovered));
    }

    public function testSignIsDeterministicForIdenticalInput(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);

        $sigA = Ecdsa::sign($hash, $priv);
        $sigB = Ecdsa::sign($hash, $priv);

        self::assertSame($sigA, $sigB);
    }

    public function testSignProducesLowS(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);
        $sig  = Ecdsa::sign($hash, $priv);

        $sInt  = gmp_import($sig['s']);
        $halfN = gmp_div_q(Secp256k1::n(), gmp_init(2));

        self::assertTrue(gmp_cmp($sInt, $halfN) <= 0, 's must be in the lower half of [1, n-1] (canonical low-S form)');
    }

    public function testVerifyAcceptsValidSignature(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);
        $sig  = Ecdsa::sign($hash, $priv);
        $pub  = $this->publicKeyFromPriv($priv);

        self::assertTrue(Ecdsa::verify($hash, $pub, $sig['r'], $sig['s']));
    }

    public function testVerifyRejectsMutatedMessageHash(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);
        $sig  = Ecdsa::sign($hash, $priv);
        $pub  = $this->publicKeyFromPriv($priv);

        $mutated     = $hash;
        $mutated[0]  = chr((ord($hash[0]) ^ 0x01) & 0xFF);
        self::assertFalse(Ecdsa::verify($mutated, $pub, $sig['r'], $sig['s']));
    }

    public function testVerifyRejectsMutatedSignature(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);
        $sig  = Ecdsa::sign($hash, $priv);
        $pub  = $this->publicKeyFromPriv($priv);

        $mutated    = $sig['r'];
        $mutated[0] = chr((ord($sig['r'][0]) ^ 0x01) & 0xFF);

        self::assertFalse(Ecdsa::verify($hash, $pub, $mutated, $sig['s']));
    }

    public function testVerifyRejectsWrongPublicKey(): void
    {
        $priv  = $this->bin(self::PRIV_HEX);
        $hash  = $this->bin(self::MSG_HASH_HEX);
        $sig   = Ecdsa::sign($hash, $priv);
        $other = $this->bin('a4e7c5dab1b2bc4d3c1a3e9c7c3c1a9c1e2c3a4b5c6d7e8f0a1b2c3d4e5f6708');
        $wrong = $this->publicKeyFromPriv($other);

        self::assertFalse(Ecdsa::verify($hash, $wrong, $sig['r'], $sig['s']));
    }

    public function testVerifyRejectsBadMsgHashLength(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);
        $sig  = Ecdsa::sign($hash, $priv);
        $pub  = $this->publicKeyFromPriv($priv);

        self::assertFalse(Ecdsa::verify(substr($hash, 0, 31), $pub, $sig['r'], $sig['s']));
    }

    public function testVerifyRejectsBadPublicKeyShape(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $hash = $this->bin(self::MSG_HASH_HEX);
        $sig  = Ecdsa::sign($hash, $priv);

        self::assertFalse(Ecdsa::verify($hash, str_repeat("\x00", 65), $sig['r'], $sig['s']));
        self::assertFalse(Ecdsa::verify($hash, str_repeat("\x04", 64), $sig['r'], $sig['s']));
    }

    public function testRecoverRejectsBadInputLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Ecdsa::recover(str_repeat("\x00", 31), 0, str_repeat("\x00", 32), str_repeat("\x00", 32));
    }

    public function testRecoverRejectsBadRecoveryFlag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Ecdsa::recover(str_repeat("\x00", 32), 2, str_repeat("\x01", 32), str_repeat("\x01", 32));
    }

    public function testRecoverReturnsNullOnROutOfRange(): void
    {
        $zero    = str_repeat("\x00", 32);
        $oneByte = str_repeat("\x00", 31) . "\x01";

        self::assertNull(Ecdsa::recover($zero, 0, $zero, $oneByte));
    }

    public function testRecoverReturnsNullOnSOutOfRange(): void
    {
        $zero    = str_repeat("\x00", 32);
        $oneByte = str_repeat("\x00", 31) . "\x01";

        self::assertNull(Ecdsa::recover($zero, 0, $oneByte, $zero));
    }

    public function testSignRejectsBadPrivateKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Ecdsa::sign(str_repeat("\x00", 32), str_repeat("\x01", 31));
    }

    public function testSignRejectsZeroPrivateKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Ecdsa::sign(str_repeat("\x00", 32), str_repeat("\x00", 32));
    }

    public function testSignAcceptsAMessageHashEqualToZero(): void
    {
        $priv = $this->bin(self::PRIV_HEX);
        $sig  = Ecdsa::sign(str_repeat("\x00", 32), $priv);
        $pub  = $this->publicKeyFromPriv($priv);

        self::assertTrue(Ecdsa::verify(str_repeat("\x00", 32), $pub, $sig['r'], $sig['s']));
    }

    private function bin(string $hex): string
    {
        $out = hex2bin($hex);
        if (false === $out) {
            self::fail('test fixture hex must be valid: ' . $hex);
        }

        return $out;
    }

    private function publicKeyFromPriv(string $priv): string
    {
        $p  = Secp256k1::p();
        $g  = Secp256k1::g();
        $d  = gmp_import($priv);

        $point = Secp256k1::scalarMul($g, $d, $p);
        if (null === $point['x'] || null === $point['y']) {
            self::fail('valid private key must derive a finite public-key point');
        }

        $xHex = str_pad(gmp_strval($point['x'], 16), 64, '0', STR_PAD_LEFT);
        $yHex = str_pad(gmp_strval($point['y'], 16), 64, '0', STR_PAD_LEFT);

        $out = hex2bin('04' . $xHex . $yHex);
        if (false === $out) {
            self::fail('synthesised uncompressed pubkey hex must decode');
        }

        return $out;
    }
}
