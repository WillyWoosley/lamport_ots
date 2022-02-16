# lamport_signatures
A Rust implementation of Leslie Lamport's [eponymous signature scheme](https://en.wikipedia.org/wiki/Lamport_signature), providing a method of digitally signing data through the use of crypotgraphic hashes. Notably, this scheme is believed to be secure even in the face of attack by quantum computers.

## Documentation:
TODO

## Usage:
TODO

## Dependencies:
This crate makes use of the [rand](https://github.com/rust-random/rand) and RustCrypto [digest](https://github.com/RustCrypto/traits/tree/master/digest) crates. Further, it is intended for use with any of RustCrypto's numerous [hash functions](https://github.com/RustCrypto/hashes), or any other hashing algorithm which implements their `digest` trait.

## A Word of Caution:
This crate has been in no way vetted for security by any competent authority, and thus is not intended for any serious use without prior inspection. Use at your own risk.

