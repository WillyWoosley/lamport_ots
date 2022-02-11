use digest::DynDigest;
use rand::{thread_rng, Rng};
use num_bigint::{BigUint, RandomBits};

use std::error::Error;
use std::io;
use std::cell::RefCell;

#[derive(Debug)]
pub struct PrivateKey {
    pub key_options: Vec<(BigUint, BigUint)>,
}

impl PrivateKey {
    pub fn generate(digest_size: usize) -> Self {
        let mut rng = thread_rng();
        
        PrivateKey {
            key_options: (0..digest_size)
                             .map(|_| (rng.sample(RandomBits::new(digest_size as u64)),
                                       rng.sample(RandomBits::new(digest_size as u64))))
                             .collect(),
        }
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub key_options: Vec<(BigUint, BigUint)>,
}

impl PublicKey {
    pub fn generate(private: &PrivateKey, hasher: &mut dyn DynDigest) -> Self {
        let mut key_options = Vec::with_capacity(hasher.output_size() * 8);

        for val in &private.key_options {
            hasher.update(&val.0.to_bytes_be());
            let hash0 = BigUint::from_bytes_be(&hasher.finalize_reset());
            hasher.update(&val.1.to_bytes_be());
            let hash1 = BigUint::from_bytes_be(&hasher.finalize_reset());
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
        let private = PrivateKey::generate(hasher.output_size() * 8);
        let public = PublicKey::generate(&private, &mut *hasher);
        
        KeyPair {public, private, hasher: RefCell::new(hasher)}
    }
    
    pub fn sign(self, msg: &mut dyn io::Read) -> Result<Signature, Box<dyn Error>> {
        let mut buffer = Vec::new();
        let mut hasher = self.hasher.borrow_mut();
        io::copy(msg, &mut buffer)?;
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
    pub sig: Vec<BigUint>,
    pub hasher: RefCell<Box<dyn DynDigest>>,
}

impl Signature {
    pub fn verify(&self, msg: &mut dyn io::Read) -> Result<bool, Box<dyn Error>> {
        let mut buffer = Vec::new();
        let mut hasher = self.hasher.borrow_mut();
        io::copy(msg, &mut buffer)?;
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
            hasher.update(&self.sig[i].to_bytes_be());
            let sig_hash = BigUint::from_bytes_be(&hasher.finalize_reset());

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
