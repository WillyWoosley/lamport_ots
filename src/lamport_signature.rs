use sha2::{Sha256, Digest};
use rand::{thread_rng, Rng};
use num_bigint::{BigUint, RandomBits};

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

pub struct PublicKey {
    pub key_options: Vec<(BigUint, BigUint)>,
}

impl PublicKey {
    pub fn generate(private: &PrivateKey) -> Self {
        let mut key_options = Vec::with_capacity(256);

        for val in &private.key_options {
            let mut hash0 = Sha256::new();
            let mut hash1 = Sha256::new();
            hash0.update(val.0.to_bytes_be());
            hash1.update(val.1.to_bytes_be());
            key_options.push((BigUint::from_bytes_be(&hash0.finalize()), 
                      BigUint::from_bytes_be(&hash1.finalize())));
        }

        PublicKey {key_options}
    }
}

pub struct Signature {
    pub msg_hash: BigUint,
    pub sig: Vec<BigUint>,
}

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        let public = PublicKey::generate(&private);

        KeyPair {public, private}
    }

    pub fn sign(&self, msg: &str) -> Signature {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let msg_hash = BigUint::from_bytes_be(&hasher.finalize());
        
        let mut sig = Vec::with_capacity(256); 
        for i in 0..256 {
            if msg_hash.bit(i as u64) {
                sig.push(self.private.key_options[i].1.clone());
            } else {
                sig.push(self.private.key_options[i].0.clone());
            }
        }

        Signature {msg_hash, sig}
    }
}
