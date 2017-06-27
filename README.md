[hashing/keccak256](https://packagist.org/packages/hashing/keccak256) provides a PHP implementation of the SHA-3 candidate hash algorithm Ethereum calls "Keccak-256".

`Keccak256\keccak256($data [, $raw_output])` provides the hash function in the usual PHP style.  
`Keccak256\hash($algo , $data [, $raw_output])` wraps the global `\hash()` function to add our support for `'keccak256'`.
