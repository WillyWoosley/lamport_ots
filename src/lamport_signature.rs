use digest::Digest;
use rand::{thread_rng, Rng};

use std::marker::PhantomData;

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
    pub fn generate<T: Digest>(private: &PrivateKey) -> Self {
        let mut key_options = Vec::with_capacity(T::output_size() * 8);

        for val in &private.key_options {
            let hash0 = T::digest(&val.0).to_vec();
            let hash1 = T::digest(&val.1).to_vec();
            key_options.push((hash0, hash1));
       }

        PublicKey {key_options}
    }
}

pub struct KeyPair<T: Digest> {
    pub private: PrivateKey,
    pub public: PublicKey,
    hasher: PhantomData<T>, 
}

impl<T: Digest> KeyPair<T> {
    pub fn generate() -> Self {
        let private = PrivateKey::generate(T::output_size());
        let public = PublicKey::generate::<T>(&private);

        KeyPair {
            hasher: PhantomData,
            private,
            public,
        }
    }
    
    pub fn sign(self, msg: &[u8]) -> Signature<T> {
        let msg_hash = T::digest(msg).to_vec();

        let mut sig = Vec::with_capacity(T::output_size() * 8); 
        for (i, (priv0, priv1)) in self.private.key_options.into_iter().enumerate() {
            
            let msg_index = i / 8;
            let bit_index = 7 - (i % 8);
            
            if msg_hash[msg_index] & (1 << bit_index) != 0 {
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

pub struct Signature<T: Digest> {
    pub pub_key: PublicKey,
    pub sig: Vec<Vec<u8>>,
    hasher: PhantomData<T>,
}

impl<T:Digest> Signature<T> {
    pub fn verify(&self, msg: &[u8]) -> bool {
        let msg_hash = T::digest(msg).to_vec();

        for (i, (pub0, pub1)) in self.pub_key.key_options.iter().enumerate() {
            let sig_hash = T::digest(&self.sig[i]).to_vec();

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

