use digest::DynDigest;
use rand::{thread_rng, Rng};
use num_bigint::{BigUint, RandomBits};

use std::error::Error;
use std::io;

#[derive(Debug)]
pub struct PrivateKey {
    pub key_options: Vec<(BigUint, BigUint)>,
}

impl PrivateKey {
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        
        PrivateKey {
            key_options: (0..256).map(|_| (rng.sample(RandomBits::new(256)),
                                           rng.sample(RandomBits::new(256)))).collect(),
        }
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub key_options: Vec<(BigUint, BigUint)>,
}

impl PublicKey {
    pub fn generate(private: &PrivateKey, hasher: &'static dyn DynDigest) -> Self {
        let mut key_options = Vec::with_capacity(256);

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
    pub hasher: &'static dyn DynDigest, 
}

impl KeyPair {
    pub fn generate(hasher: &'static dyn DynDigest) -> Self {
        let private = PrivateKey::generate();
        let public = PublicKey::generate(&private, hasher);

        KeyPair {public, private, hasher}
    }
    
    pub fn sign(self, msg: &mut dyn io::Read) -> Result<Signature, Box<dyn Error>> {
        let mut buffer = Vec::new();
        io::copy(msg, &mut buffer)?;
        self.hasher.update(&buffer);
        let msg_hash = BigUint::from_bytes_be(&self.hasher.finalize_reset());

        let mut sig = Vec::with_capacity(256); 
        for (i, (priv0, priv1)) in self.private.key_options.into_iter().enumerate() {
            if msg_hash.bit(i as u64) {
                sig.push(priv1);
            } else {
                sig.push(priv0);
            }
        }

        Ok(Signature {
            pub_key: self.public,
            hasher: self.hasher,
            sig,
        })
    }

    pub fn sign_string(self, msg: &str) -> Signature {
        self.hasher.update(msg.as_bytes());
        let msg_hash = BigUint::from_bytes_be(&self.hasher.finalize_reset());
        
        let mut sig = Vec::with_capacity(256); 
        for (i, (priv0, priv1)) in self.private.key_options.into_iter().enumerate() {
            if msg_hash.bit(i as u64) {
                sig.push(priv1);
            } else {
                sig.push(priv0);
            }
        }

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
    pub hasher: &'static dyn DynDigest,
}

impl Signature {
    pub fn verify(&self, msg: &mut dyn io::Read) -> Result<bool, Box<dyn Error>> {
        let mut buffer = Vec::new();
        io::copy(msg, &mut buffer)?;
        self.hasher.update(&buffer);
        let msg_hash = BigUint::from_bytes_be(&self.hasher.finalize_reset());
    
        Ok(self.check_against_hash(&msg_hash))
    }

    pub fn verify_string(&self, msg: &str) -> bool {
        self.hasher.update(msg.as_bytes());
        let msg_hash = BigUint::from_bytes_be(&self.hasher.finalize_reset());
        
        self.check_against_hash(&msg_hash)
    }
    
    fn check_against_hash(&self, msg_hash: &BigUint) -> bool {
        for (i, (pub0, pub1)) in self.pub_key.key_options.iter().enumerate() {
            self.hasher.update(&self.sig[i].to_bytes_be());
            let sig_hash = BigUint::from_bytes_be(&self.hasher.finalize_reset());

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
