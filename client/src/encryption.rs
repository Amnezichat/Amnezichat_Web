use rand::RngCore;
use sha3::{Sha3_512, Digest};
use zeroize::Zeroize;
use hex;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use base64::engine::general_purpose;
use base64::Engine;
use argon2::{Argon2, Params, password_hash::SaltString};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

pub fn derive_salt_from_password(password: &str) -> [u8; 16] {
    let mut hasher = Sha3_512::new();
    hasher.update(password.as_bytes());
    let hash_result = hasher.finalize();

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash_result[..16]);
    salt
}

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    use argon2::{ParamsBuilder};

    let params = ParamsBuilder::new()
        .m_cost(19456)
        .t_cost(2)
        .p_cost(1)
        .output_len(32)
        .build()
        .expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 hashing failed");

    key
}


pub fn combine_shared_secrets(
    kyber_secret: &str,
    ecdh_secret: &str,
) -> Result<String, AnyError> {
    let combined = [kyber_secret.as_bytes(), ecdh_secret.as_bytes()].concat();

    let mut hasher = Sha3_512::new();
    hasher.update(combined);

    Ok(hex::encode(hasher.finalize()))
}

pub fn encrypt_data(plain_text: &str, password: &str) -> Result<String, AnyError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_data = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|_| "Encryption error")?;

    key.zeroize();

    Ok(format!(
        "{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce_bytes),
        hex::encode(encrypted_data)
    ))
}

pub fn decrypt_data(encrypted_text: &str, password: &str) -> Result<String, AnyError> {
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted data format".into());
    }

    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error: Invalid salt format")?;
    let nonce_bytes = hex::decode(parts[1]).map_err(|_| "Decryption error: Invalid nonce format")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error: Invalid encrypted data format")?;

    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| "Decryption error: Failed to decrypt")?;

    key.zeroize();

    Ok(String::from_utf8(decrypted_data).map_err(|_| "Decryption error: Invalid UTF-8 data")?)
}
