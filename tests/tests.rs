extern crate lamport_ots;

use sha2::{Sha256, Sha512};

use lamport_ots::KeyPair;

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::io::Read;

#[test]
fn different_generates_different_keypairs() {
    let pair1 = KeyPair::<Sha256>::generate();
    let pair2 = KeyPair::<Sha256>::generate();

    assert_ne!(pair1.private(), pair2.private());
    assert_ne!(pair1.public(), pair2.public());
}

#[test]
fn signature_length_and_contents_sha256() {
    let keypair = KeyPair::<Sha256>::generate();
    let signature = keypair.sign(b"Hello world!");

    assert_eq!(signature.sig().len(), 256);
    
    for key in signature.sig() {
        assert_eq!(key.len(), 32);
    }
}

#[test]
fn signature_length_and_contents_sha512() {
    let keypair = KeyPair::<Sha512>::generate();
    let signature = keypair.sign(b"Hello world!");

    assert_eq!(signature.sig().len(), 512);
    
    for key in signature.sig() {
        assert_eq!(key.len(), 64);
    }
}

#[test]
fn correct_signature_verifies_correct_string() {
    let keypair = KeyPair::<Sha256>::generate();
    let signature = keypair.sign(b"Hello world!");

    assert!(signature.verify(b"Hello world!"));
}

#[test]
fn correct_signature_fails_incorrect_string() {
    let keypair = KeyPair::<Sha256>::generate();
    let signature = keypair.sign(b"Hello world!");

    assert!(!signature.verify(b"Hello moon!"));
}

#[test]
fn correct_signatre_verifies_correct_read() {
    let mut f = File::open("tests/data.txt").unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();

    let keypair = KeyPair::<Sha256>::generate();
    let signature = keypair.sign(&buffer);

    assert!(signature.verify(&buffer));
}

#[test]
fn correct_signatre_fails_incorrect_read() {
    let mut f = File::open("tests/data.txt").unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    
    let keypair = KeyPair::<Sha256>::generate();
    let signature = keypair.sign(&buffer);
    
    buffer.pop();
    assert!(!signature.verify(&buffer));
}


#[test]
fn test_privkey_traits() {
    let pair1 = KeyPair::<Sha256>::generate();
    let pair2 = KeyPair::<Sha256>::generate();
    
    assert_ne!(pair1.private(), pair2.private());
    assert!(pair1.private() > pair2.private() || pair2.private() > pair1.private());

    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    pair1.private().hash(&mut hasher1);
    pair2.private().hash(&mut hasher2);
    assert_ne!(hasher1.finish(), hasher2.finish());
    
    let _clone = pair1.private().clone();
}

#[test]
fn test_pubkey_traits() {
    let pair1 = KeyPair::<Sha256>::generate();
    let pair2 = KeyPair::<Sha256>::generate();
    
    assert_ne!(pair1.public(), pair2.public());
    assert!(pair1.public() > pair2.public() || pair2.public() > pair1.public());

    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    pair1.public().hash(&mut hasher1);
    pair2.public().hash(&mut hasher2);
    assert_ne!(hasher1.finish(), hasher2.finish());
    
    let _clone = pair1.public().clone();
}

#[test]
fn test_keypair_traits() {
    let pair1 = KeyPair::<Sha256>::generate();
    let pair2 = KeyPair::<Sha256>::generate();
    
    assert_ne!(pair1, pair2);
    assert!(pair1 > pair2 || pair2 > pair1);

    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    pair1.hash(&mut hasher1);
    pair2.hash(&mut hasher2);
    assert_ne!(hasher1.finish(), hasher2.finish());
    
    let _clone = pair1.clone();
}

#[test]
fn test_sig_traits() {
    let pair1 = KeyPair::<Sha256>::generate();
    let pair2 = KeyPair::<Sha256>::generate();
    let sig1 = pair1.sign(b"Hello world!");
    let sig2 = pair2.sign(b"Hello world!");

    assert_ne!(sig1, sig2);
    assert!(sig1 > sig2 || sig2 > sig1);

    let mut hasher1 = DefaultHasher::new();
    let mut hasher2 = DefaultHasher::new();
    sig1.hash(&mut hasher1);
    sig2.hash(&mut hasher2);
    assert_ne!(hasher1.finish(), hasher2.finish());
    
    let _clone = sig1.clone();
}
