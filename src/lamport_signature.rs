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

#[derive(Debug)]
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

#[derive(Debug)]
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

    pub fn sign(self, msg: &str) -> Signature {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let msg_hash = BigUint::from_bytes_be(&hasher.finalize());
        
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
            sig,
        }
    }
}

#[derive(Debug)]
pub struct Signature {
    pub pub_key: PublicKey,
    pub sig: Vec<BigUint>,
}

impl Signature {
    pub fn verify(&self, msg: &str) -> bool {
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(msg);
        let msg_hash = BigUint::from_bytes_be(&msg_hasher.finalize());

        for (i, (pub0, pub1)) in self.pub_key.key_options.iter().enumerate() {
            let mut sig_hasher = Sha256::new();
            sig_hasher.update(self.sig[i].to_bytes_be());
            let sig_hash = BigUint::from_bytes_be(&sig_hasher.finalize());

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
