<?php declare(strict_types=1);

namespace Keccak256;


// PUBLIC INTERFACE

function keccak256(string $data, ?bool $raw_output = false): string {
    return Keccak256::hash($data, $raw_output);
}

class Keccak256 {
    // Some known input-output pairs.
    const testVectors = [
        '' =>
            'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
        'abc' =>
            '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' =>
            '45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371',
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' =>
            'f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67'
    ];

    // Wraps the implementation (which use arrays) in PHP's traditional string hashing interface.    
    static function hash(string $data, ?bool $raw_output = false): string {
        $dataBytes = hexToBytes($data);
        $resultBytes = Keccak256::keccak256($dataBytes);

        if ($raw_output) {
            $resultRawString = \pack('C*', $resultBytes->toArray());
            return $resultRawString;
        } else {
            $resultHex = bytesToHex($resultBytes);
            return $resultHex;
        }
    }
    
    // The meat of the thing.
    // http://keccak.noekeon.org/specs_summary.html
    // https://github.com/emn178/js-sha3/blob/master/src/sha3.js
    // http://www.movable-type.co.uk/scripts/sha3.html
    
    protected static function keccak256(\SplFixedArray $value): \SplFixedArray {
        $result = new \SplFixedArray(256 / 8);
        
        // 5 x 5 lanes of 64 bits
        $state = \SplFixedArray::fromArray([
            \SplFixedArray::fromArray([new Uint64, new Uint64, new Uint64, new Uint64, new Uint64]),
            \SplFixedArray::fromArray([new Uint64, new Uint64, new Uint64, new Uint64, new Uint64]),
            \SplFixedArray::fromArray([new Uint64, new Uint64, new Uint64, new Uint64, new Uint64]),
            \SplFixedArray::fromArray([new Uint64, new Uint64, new Uint64, new Uint64, new Uint64]),
            \SplFixedArray::fromArray([new Uint64, new Uint64, new Uint64, new Uint64, new Uint64])
        ]);

        $state[0][0]->rot(2)->xor($state[1][1]);

        throw new \Exception('not implemented');

        return $result;
    }

    protected static function keccak256_f(\SplFixedArray $state): void {
       throw new \Exception('not implemented');
    }
}


// INTERNAL UTILITIES

// A minimal byte-wise Uint64 implementing only the operators required for Keccak,
// because we can't assume we're running on 64-bit PHP.
class Uint64 {
    function __construct() {
        $this->bytes = new \SplFixedArray(8);
    }

    function toBytes(): \SplFixedArray {
        return \SplFixedArray::fromArray($this->bytes->toArray());
    }

    static function fromBytes(\SplFixedArray $bytes): Uint64 {
        if ($bytes->count() !== 8) {
            throw new \UnexpectedValueException('Uint64:fromBytes(...) argument must have length 8');
        }
        $result = new Uint64;
        for ($i = 0; $i < 8; $i++) {
            $result->bytes[$i] = $bytes[$i] & 0xFF;
        }
        return $result;
    }

    function xor(Uint64 $other): Uint64 {
        $result = new Uint64;
        for ($i = 0; $i < 8; $i++) {
            $result->bytes[$i] = $this->bytes[$i] ^ $other->bytes[$i];
        }
        return $result;
    }

    function rot(int $distance): Uint64 {
        if ($distance < 0) {
            throw new \UnexpectedValueException('Uint64:rot(...) argument must not be negative');
        }

        $bytes = $this->toBytes();
        $remaining = $distance;

        while ($remaining >= 8) {
            $tmp = $bytes[0];
            $bytes[0] = $bytes[7];
            $bytes[7] = $bytes[6];
            $bytes[6] = $bytes[5];
            $bytes[5] = $bytes[4];
            $bytes[4] = $bytes[3];
            $bytes[3] = $bytes[2];
            $bytes[2] = $bytes[1];
            $bytes[1] = $tmp;
            $remaining -= 8;
        }

        if ($remaining > 0) {
            $tmp = $bytes[0];
            $bytes[0] = 0xFF & (($bytes[0] >> $remaining) | ($bytes[7] << (8 - $remaining)));
            $bytes[7] = 0xFF & (($bytes[7] >> $remaining) | ($bytes[6] << (8 - $remaining)));
            $bytes[6] = 0xFF & (($bytes[6] >> $remaining) | ($bytes[5] << (8 - $remaining)));
            $bytes[5] = 0xFF & (($bytes[5] >> $remaining) | ($bytes[4] << (8 - $remaining)));
            $bytes[4] = 0xFF & (($bytes[4] >> $remaining) | ($bytes[3] << (8 - $remaining)));
            $bytes[3] = 0xFF & (($bytes[3] >> $remaining) | ($bytes[2] << (8 - $remaining)));
            $bytes[2] = 0xFF & (($bytes[2] >> $remaining) | ($bytes[1] << (8 - $remaining)));
            $bytes[1] = 0xFF & (($bytes[1] >> $remaining) | (     $tmp << (8 - $remaining)));
            $remaining = 0;
        }

        return Uint64::fromBytes($bytes);
    }
}

function bytesToHex(\SplFixedArray $array): string {
    $byteArray = implode(array_map('chr', $array->toArray()));
    $hex = \unpack('H*', $byteArray)[1];
    return $hex;
}

function hexToBytes(string $data): \SplFixedArray {
    $rawString = \pack('H*', $data);
    $byteArray = array_values(\unpack('C*', $rawString));
    return \SplFixedArray::fromArray($byteArray);
}


//// SANITY TESTS

function dump($x) { echo bytesToHex($x->toBytes()) . "\n"; }
$x = Uint64::fromBytes(hexToBytes('0123456789abcdef'));
dump($x);
dump($x->rot(1));
dump($x->rot(8));
dump($x->xor($x->rot(1)));

echo "\n\n\n";

// Assert that the test vectors produce the correct results.
foreach (Keccak256::testVectors as $input => $expected) {
    assert($expected === keccak256($input, false), new \Exception('Keccak256 test vector failed'));
}
