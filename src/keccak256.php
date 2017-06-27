<?php

declare(strict_types=1);

namespace Keccak256;


const ALGO_NAME = 'keccak256';


function hash(string $algo, string $data, bool $raw_output = false): string {
    if ($algo === ALGO_NAME) {
        return keccak256($data, $raw_output);
    } else {
        return \hash($algo, $data, $raw_output);
    }
}


function keccak256(string $data, bool $raw_output = false): string {
    if ($data === '') {
        $hex = '5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02';
        return $raw_output ? pack('H*', $hex) : $hex;
    }

    throw new \UnexpectedValueException('not implemented');
}
