use ring::aead::{self, Aad, BoundKey, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

fn generate_key_iv() -> [u8; 32] {
    let mut key = [0u8; 32];
    let rng = SystemRandom::new();
    rng.fill(&mut key).expect("Failed to generate key");
    key
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let rng = SystemRandom::new();
    rng.fill(&mut nonce).expect("Failed to generate nonce");
    nonce
}

fn encrypt_data(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).expect("Invalid key");
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(nonce).expect("Invalid nonce");
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .expect("Encryption failed");
    in_out
}

fn decrypt_data(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key).expect("Invalid key");
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::try_assume_unique_for_key(nonce).expect("Invalid nonce");
    let mut in_out = ciphertext.to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .expect("Decryption failed")
        .to_vec()
}

fn main() {
    let plaintext = b"Hello, this is a secret message!";
    let key = generate_key_iv();
    let nonce = generate_nonce();
    let ciphertext = encrypt_data(plaintext, &key, &nonce);
    println!("Ciphertext: {:?}", ciphertext);
    
    let decrypted_data = decrypt_data(&ciphertext, &key, &nonce);
    println!("Decrypted text: {}", String::from_utf8(decrypted_data).unwrap());
}
