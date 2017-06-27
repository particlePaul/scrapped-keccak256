<?php

namespace Keccak256;

const ALGO_NAME = 'keccak256';

function hash($algo, $data, $raw_output = false) {
    if ($algo === ALGO_NAME) {
        return keccak256($data, $raw_output);
    } else {
        return \hash($algo, $data, $raw_output);
    }
}

function keccak256($data, $raw_output = false) {
    die('not implemented');
}
