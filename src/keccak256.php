<?php declare(strict_types=1);

namespace Keccak256;


// PUBLIC INTERFACE

function keccak256(string $data, ?bool $raw_output = false): string {
    return Keccak256::hash($data, $raw_output);
}

class Keccak256 {
    // Keccak algorithim parameters
    const CAPACITY_BITS = 1088;
    const RATE_BITS = 512;
    const RATE_BYTES = Keccak256::RATE_BITS / 8;
    const LENGTH_BITS = 256;
    const LENGTH_BYTES = Keccak256::LENGTH_BITS / 8;
    const LANES = 5 * 5;

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
        // TODO: this needs string to byes, not hex!
        $dataBytes = hexToBytes($data);
        $resultBytes = Keccak256::keccak_sponge_c1088_r512_l256($dataBytes);

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
    // https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/CompactFIPS202-Python/CompactFIPS202.py
    // https://github.com/0xbb/php-sha3/blob/master/src/Sha3.php
    
    protected static function keccak_sponge_c1088_r512_l256(\SplFixedArray $value): \SplFixedArray {
        $result = new \SplFixedArray(Keccak256::LENGTH_BYTES);
        return $result;
        
        // State is 1600 bits group into 5x5 lanes of 64 bits each.
        $state = new \SplFixedArray(LANES);
        for ($i = 0; $i < LANES; $i++) {
            $state[$i] = new Lane;
        }

        // Break input into RATE (512 bit) size blocks.
        
        // Xor each block into the first RATE (512 bit) of $state (treating lanes as contiguous)

        // at the end of each full block, F-up the state.
        
        // xor the algorithm specifier suffix into the state at index input length % RATE + 1.


        throw new \Exception('not implemented');

        return $result;
    }

    protected static function keccak_f_b1600(\SplFixedArray $state): void {
       throw new \Exception('not implemented');
    }
}


// INTERNAL UTILITIES

// A 64-bit keccak "lane" supporting XOR and ROTL.
class Lane {
    function __construct() {
        $this->bytes = new \SplFixedArray(8);
    }

    function toBytes(): \SplFixedArray {
        return \SplFixedArray::fromArray($this->bytes->toArray());
    }

    static function fromBytes(\SplFixedArray $bytes): Lane {
        if ($bytes->count() !== 8) {
            throw new \UnexpectedValueException('Lane:fromBytes(...) argument must have length 8');
        }
        $result = new Lane;
        for ($i = 0; $i < 8; $i++) {
            $result->bytes[$i] = $bytes[$i] & 0xFF;
        }
        return $result;
    }

    // Returns a 2x2 2D array of 64-bit lanes from a flat array of byte values.
    static function lanesFromBytes(\SplFixedArray $bytes): \SplFixedArray {
        
    }
    
    // Converts a 2x2 2D array of 64-bit lanes into a flat array of byte values.
    static function bytesFromLanes(\SplFixedArray $lanes): \SplFixedArray {
           
    }

    function xor(Lane $other): Lane {
        $result = new Lane;
        for ($i = 0; $i < 8; $i++) {
            $result->bytes[$i] = $this->bytes[$i] ^ $other->bytes[$i];
        }
        return $result;
    }

    function rotl(int $distance): Lane {
        if ($distance < 0) {
            throw new \UnexpectedValueException('Lane:rotl(...) argument must not be negative');
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
            $bytes[0] = 0xFF & (($bytes[0] << $remaining) | ($bytes[7] >> (8 - $remaining)));
            $bytes[7] = 0xFF & (($bytes[7] << $remaining) | ($bytes[6] >> (8 - $remaining)));
            $bytes[6] = 0xFF & (($bytes[6] << $remaining) | ($bytes[5] >> (8 - $remaining)));
            $bytes[5] = 0xFF & (($bytes[5] << $remaining) | ($bytes[4] >> (8 - $remaining)));
            $bytes[4] = 0xFF & (($bytes[4] << $remaining) | ($bytes[3] >> (8 - $remaining)));
            $bytes[3] = 0xFF & (($bytes[3] << $remaining) | ($bytes[2] >> (8 - $remaining)));
            $bytes[2] = 0xFF & (($bytes[2] << $remaining) | ($bytes[1] >> (8 - $remaining)));
            $bytes[1] = 0xFF & (($bytes[1] << $remaining) | (     $tmp >> (8 - $remaining)));
            $remaining = 0;
        }

        return Lane::fromBytes($bytes);
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

function dump($x, $label = "") { echo bytesToHex($x->toBytes()) . " $label\n"; }
$x = Lane::fromBytes(hexToBytes('0123456789abcdef'));
dump($x, 'should be the hex alphabet');
dump($x->xor($x->rotl(1)->rotl(1)->rotl(12)->rotl(3)->rotl(21)->rotl(26)), 'should be zeroed out');

echo "\n\n\n";

// Assert that the test vectors produce the correct results.
foreach (Keccak256::testVectors as $input => $expected) {
    echo "testing Keccak256\keccak256(" . json_encode($input) . ")\n";
    $actual = keccak256($input, false);
    if ($expected !== $actual) {
        echo("ERROR: Got $actual expecting $expected.");
    }
}
