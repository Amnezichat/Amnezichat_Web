use rand::RngCore;
use sha3::{Sha3_512, Digest};
use zeroize::Zeroize;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};

// Derive a salt from the password itself
pub fn derive_salt_from_password(password: &str) -> [u8; 16] {
    let mut hasher = Sha3_512::new();
    hasher.update(password.as_bytes());
    let hash_result = hasher.finalize();

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash_result[..16]); // Use the first 16 bytes of the hash as the salt
    salt
}

// Derive encryption key using Argon2
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(salt).expect("Failed to generate salt string");
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");
    let hash_bytes = hash.hash.expect("Hash missing in PasswordHash structure");

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    key
}

pub fn combine_shared_secrets(
    kyber_secret: &str,
    ecdh_secret: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use sha3::{Digest, Sha3_512};
    use hex; // For hexadecimal encoding

    // Concatenate the secrets
    let combined = [kyber_secret.as_bytes(), ecdh_secret.as_bytes()].concat();

    // Hash the combined secrets to produce a fixed-length shared secret
    let mut hasher = Sha3_512::new();
    hasher.update(combined);

    // Convert the hash result to a hexadecimal string
    Ok(hex::encode(hasher.finalize()))
}

// Encrypt the data using ChaCha20Poly1305
pub fn encrypt_data(plain_text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Generate random salt for key derivation
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive encryption key using Argon2
    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    // Generate random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let encrypted_data = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|_| "Encryption error")?;

    // Clear the key from memory after usage
    key.zeroize();

    // Return the formatted encrypted message with salt, nonce, and encrypted data
    Ok(format!(
        "{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce_bytes),
        hex::encode(encrypted_data)
    ))
}

// Decrypt the data using ChaCha20Poly1305
pub fn decrypt_data(encrypted_text: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Split the encrypted data into salt, nonce, and encrypted part
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted data format".into());
    }

    // Decode hex-encoded salt, nonce, and encrypted data
    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error: Invalid salt format")?;
    let nonce_bytes = hex::decode(parts[1]).map_err(|_| "Decryption error: Invalid nonce format")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error: Invalid encrypted data format")?;

    // Derive the decryption key using the password and salt
    let mut key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(&key));

    // Ensure nonce is of the correct length (12 bytes for ChaCha20Poly1305)
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt the data
    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|_| "Decryption error: Failed to decrypt")?;

    // Clear the key from memory after usage
    key.zeroize();

    // Convert decrypted bytes into a string
    Ok(String::from_utf8(decrypted_data).map_err(|_| "Decryption error: Invalid UTF-8 data")?)
}