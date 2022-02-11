use digest::DynDigest;
use rand::{thread_rng, Rng};
use num_bigint::BigUint;

use std::error::Error;
use std::io;
use std::cell::RefCell;

#[derive(Debug)]
pub struct PrivateKey {
    pub key_options: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PrivateKey {
    pub fn generate(digest_bytes: usize) -> Self {
        let mut rng = thread_rng();
        let mut key_options = Vec::with_capacity(digest_bytes * 8);
        
        for _ in 0..(digest_bytes * 8) {
            let key0 = (0..digest_bytes).map(|_| rng.gen()).collect();
            let key1 = (0..digest_bytes).map(|_| rng.gen()).collect();
            key_options.push((key0, key1));
        }

        PrivateKey {key_options}
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub key_options: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PublicKey {
    pub fn generate(private: &PrivateKey, hasher: &mut dyn DynDigest) -> Self {
        let mut key_options = Vec::with_capacity(hasher.output_size() * 8);

        for val in &private.key_options {
            hasher.update(&val.0);
            let hash0 = hasher.finalize_reset().into_vec();
            hasher.update(&val.1);
            let hash1 = hasher.finalize_reset().into_vec();
            key_options.push((hash0, hash1));
        }

        PublicKey {key_options}
    }
}

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
    pub hasher: RefCell<Box<dyn DynDigest>>, 
}

impl KeyPair {
    pub fn generate(mut hasher: Box<dyn DynDigest>) -> Self {
        let private = PrivateKey::generate(hasher.output_size());
        let public = PublicKey::generate(&private, &mut *hasher);
        
        KeyPair {public, private, hasher: RefCell::new(hasher)}
    }
    
    pub fn sign(self, msg: &mut dyn io::Read) -> Result<Signature, Box<dyn Error>> {
        let mut buffer = Vec::new();
        io::copy(msg, &mut buffer)?;
        
        let mut hasher = self.hasher.borrow_mut();
        hasher.update(&buffer);
        let msg_hash = BigUint::from_bytes_be(&hasher.finalize_reset());

        let mut sig = Vec::with_capacity(hasher.output_size() * 8); 
        for (i, (priv0, priv1)) in self.private.key_options.into_iter().enumerate() {
            if msg_hash.bit(i as u64) {
                sig.push(priv1);
            } else {
                sig.push(priv0);
            }
        }
        
        drop(hasher);

        Ok(Signature {
            pub_key: self.public,
            hasher: self.hasher,
            sig,
        })
    }

    pub fn sign_string(self, msg: &str) -> Signature {
        let mut hasher = self.hasher.borrow_mut();
        hasher.update(msg.as_bytes());
        let msg_hash = BigUint::from_bytes_be(&hasher.finalize_reset());
        
        let mut sig = Vec::with_capacity(hasher.output_size() * 8); 
        for (i, (priv0, priv1)) in self.private.key_options.into_iter().enumerate() {
            if msg_hash.bit(i as u64) {
                sig.push(priv1);
            } else {
                sig.push(priv0);
            }
        }
        
        drop(hasher);

        Signature {
            pub_key: self.public,
            hasher: self.hasher,
            sig,
        }
    }
}

pub struct Signature {
    pub pub_key: PublicKey,
    pub sig: Vec<Vec<u8>>,
    pub hasher: RefCell<Box<dyn DynDigest>>,
}

impl Signature {
    pub fn verify(&self, msg: &mut dyn io::Read) -> Result<bool, Box<dyn Error>> {
        let mut buffer = Vec::new();
        io::copy(msg, &mut buffer)?;
        
        let mut hasher = self.hasher.borrow_mut();
        hasher.update(&buffer);
        let msg_hash = BigUint::from_bytes_be(&hasher.finalize_reset());
        
        drop(hasher);
        
        Ok(self.check_against_hash(&msg_hash))
    }

    pub fn verify_string(&self, msg: &str) -> bool {
        let mut hasher = self.hasher.borrow_mut();
        hasher.update(msg.as_bytes());
        let msg_hash = BigUint::from_bytes_be(&hasher.finalize_reset());
        
        drop(hasher);
        
        self.check_against_hash(&msg_hash)
    }
    
    fn check_against_hash(&self, msg_hash: &BigUint) -> bool {
        let mut hasher = self.hasher.borrow_mut();

        for (i, (pub0, pub1)) in self.pub_key.key_options.iter().enumerate() {
            hasher.update(&self.sig[i]);
            let sig_hash = hasher.finalize_reset().into_vec();

            if msg_hash.bit(i as u64) {
                if &sig_hash != pub1 {
                    return false;
                }
            } else {
                if &sig_hash != pub0 {
                    return false;
                }
            }
        }

        true
    }
}
