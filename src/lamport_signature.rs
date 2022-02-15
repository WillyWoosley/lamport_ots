use digest::DynDigest;
use rand::{thread_rng, Rng};

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

        hasher.finalize_reset(); // in case hasher instance passed is not fresh

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
    
    pub fn sign(self, msg: &[u8]) -> Signature {
        let mut hasher = self.hasher.borrow_mut();
        hasher.update(msg);
        let msg_hash = hasher.finalize_reset().into_vec();

        let mut sig = Vec::with_capacity(hasher.output_size() * 8); 
        for (i, (priv0, priv1)) in self.private.key_options.into_iter().enumerate() {
            
            let msg_index = i / 8;
            let bit_index = 7 - (i % 8);
            
            if msg_hash[msg_index] & (1 << bit_index) != 0 {
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
    pub fn verify(&self, msg: &[u8]) -> bool {
        let mut hasher = self.hasher.borrow_mut();
        hasher.update(msg);
        let msg_hash = hasher.finalize_reset().into_vec();
    
        for (i, (pub0, pub1)) in self.pub_key.key_options.iter().enumerate() {
            hasher.update(&self.sig[i]);
            let sig_hash = hasher.finalize_reset().into_vec();
            
            let msg_index = i / 8;
            let bit_index = 7 - (i % 8);

            if msg_hash[msg_index] & (1 << bit_index) != 0 {
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

