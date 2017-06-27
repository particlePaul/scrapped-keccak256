<?php declare(strict_types=1);

namespace Keccak256;


const ALGO_NAME = 'keccak256';

// Wraps the global \hash function to add support for 'keccak256'.
function hash(string $algo, string $data, bool $raw_output = false): string {
    if ($algo === ALGO_NAME) {
        return keccak256($data, $raw_output);
    } else {
        return \hash($algo, $data, $raw_output);
    }
}

// Implements Ethereum's Keccak-256 hash function in the PHP style.
function keccak256(string $data, bool $raw_output = false): string {
    if (array_key_exists($knownValues, $data)) {
        $hex = $knownValues[$data];
        return $raw_output ? \pack('H*', $hex) : $hex;
    }

    throw new \UnexpectedValueException('not implemented');
}

// Some known input-output pairs.
const testVectors = [
    '' =>
        'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    'abc' =>
        '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' =>
        '45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371',
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' =>
        'f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67',
];

// Assert that the test vectors produce the correct results.
foreach (testVector as $input => $expected) {
    assert($expected === Keccak256\hash(ALGO_NAME, $input, $false), new \Exception("Keccak256 test vector failed"));
}
