use sha2::{Sha256, Digest};
use rand::{thread_rng, Rng};
use num_bigint::{BigUint, RandomBits};

#[derive(Debug)]
pub struct PrivateKey {
    key_options: Vec<(BigUint, BigUint)>,
}

impl PrivateKey {
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        
        PrivateKey {
            key_options: vec![(rng.sample(RandomBits::new(256)), 
                               rng.sample(RandomBits::new(256))); 256],
        }
    }
}

pub struct PublicKey {
    key_options: Vec<(BigUint, BigUint)>,
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

pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        let public = PublicKey::generate(&private);

        KeyPair {public, private}
    }
}
