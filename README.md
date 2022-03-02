# lamport_ots

[![Crate](https://img.shields.io/crates/v/lamport_ots.svg)](https://crates.io/crates/lamport_ots)
[![Documentation](https://docs.rs/lamport_ots/badge.svg)](https://docs.rs/lamport_ots)
[![License](https://img.shields.io/github/license/WillyWoosley/lamport_ots)](https://github.com/WillyWoosley/lamport_ots/blob/main/LICENSE)

A Rust implementation of Leslie Lamport's [eponymous signature scheme](https://en.wikipedia.org/wiki/Lamport_signature), providing a method of digitally signing data through the use of crypotgraphic hashes. Notably, this scheme is believed to be secure even in the face of attack by quantum computers.

## Documentation:
Full documentation for this crate can be found [here](https://docs.rs/lamport_ots).

## Usage:
### A Typical Example
```rust
use lamport_ots::KeyPair;
use sha2::Sha256;

// Generate a randomized Public/Private KeyPair
let keypair = KeyPair::<Sha256>::generate();

// Use that KeyPair to generate a signature for passed data
let signature = keypair.sign(b"Hello world!");

// That signature can now verify the signed data
assert!(signature.verify(b"Hello world!"));
assert!(!signature.verify(b"Hello moon!"));
```
### Signing a File
Since `lamport_ots` expects byte-data for signing and verifying, working with files (or any Read data) will require that data to first be read into a buffer.

```rust
use lamport_ots::KeyPair;
use sha2::Sha256;

use std::fs::File;
use std::io::Read;

// Generate a randomized Public/Private KeyPair
let keypair = KeyPair::<Sha256>::generate();

// Read the desired file into a buffer
let mut f = File::open("my_file.txt").unwrap();
let mut buffer = Vec::new();
f.read_to_end(&mut buffer);

// Sign the buffer
let signature = keypair.sign(&buffer);

// That signature can now verify the buffers contents
assert!(signature.verify(&buffer));
```

## Dependencies:
This crate makes use of the [`rand`](https://github.com/rust-random/rand) and RustCrypto [`digest`](https://github.com/RustCrypto/traits/tree/master/digest) crates. Further, it is intended for use with any of RustCrypto's numerous [hash functions](https://github.com/RustCrypto/hashes), or any other hashing algorithm which implements their `digest` trait.

## A Word of Caution:
This crate has been in no way vetted for security by any competent authority, and thus is not intended for any serious use without prior inspection. Use at your own risk.

## License:
This software distributed under the [MIT License](LICENSE).

