use oqs::*;
use oqs::sig::{Sig, PublicKey, SecretKey};
use std::fs::{self, File};
use std::io::{self, Write, Read};
use std::result::Result;
use base64::{Engine, engine::general_purpose};
use rand::RngCore;
use chacha20poly1305::aead::OsRng;
use ed25519_dalek::{SigningKey as Ed25519PrivateKey, VerifyingKey as Ed25519PublicKey};

use crate::{decrypt_data, encrypt_data, get_raw_bytes_public_key, get_raw_bytes_secret_key};

pub fn save_dilithium_keys_to_file(public_key: &PublicKey, secret_key: &SecretKey, user: &str, password: &str) -> io::Result<()> {
    let pub_bytes = get_raw_bytes_public_key(public_key);
    let sec_bytes = get_raw_bytes_secret_key(secret_key);

    let pub_base64 = general_purpose::STANDARD.encode(&pub_bytes);
    let sec_base64 = general_purpose::STANDARD.encode(&sec_bytes);

    let encrypted_pub = encrypt_data(&pub_base64, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {}", e)))?;
    let encrypted_sec = encrypt_data(&sec_base64, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {}", e)))?;

    fs::create_dir_all("keys")?;
    let pub_file_path = format!("keys/{}_dilithium_public_key.enc", user);
    let sec_file_path = format!("keys/{}_dilithium_secret_key.enc", user);

    File::create(&pub_file_path)?.write_all(encrypted_pub.as_bytes())?;
    File::create(&sec_file_path)?.write_all(encrypted_sec.as_bytes())?;

    Ok(())
}

pub fn load_dilithium_keys_from_file(sigalg: &Sig, user: &str, password: &str) -> io::Result<(PublicKey, SecretKey)> {
    let pub_file_path = format!("keys/{}_dilithium_public_key.enc", user);
    let sec_file_path = format!("keys/{}_dilithium_secret_key.enc", user);

    let mut pub_file = File::open(&pub_file_path)?;
    let mut pub_encrypted = String::new();
    pub_file.read_to_string(&mut pub_encrypted)?;

    let mut sec_file = File::open(&sec_file_path)?;
    let mut sec_encrypted = String::new();
    sec_file.read_to_string(&mut sec_encrypted)?;

    let decrypted_pub = decrypt_data(&pub_encrypted, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {}", e)))?;
    let decrypted_sec = decrypt_data(&sec_encrypted, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {}", e)))?;

    let pub_bytes = general_purpose::STANDARD.decode(&decrypted_pub)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to decode public key"))?;
    let sec_bytes = general_purpose::STANDARD.decode(&decrypted_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to decode secret key"))?;

    let public_key_ref = sigalg
        .public_key_from_bytes(&pub_bytes)
        .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid public key data"))?;
    let secret_key_ref = sigalg
        .secret_key_from_bytes(&sec_bytes)
        .ok_or(io::Error::new(io::ErrorKind::InvalidData, "Invalid secret key data"))?;

    Ok((public_key_ref.to_owned(), secret_key_ref.to_owned()))
}

pub fn save_eddsa_keys(
    username: &str, 
    signing_key: &Ed25519PrivateKey, 
    verifying_key: &Ed25519PublicKey,
    password: &str,
) -> io::Result<()> {
    let private_key_base64 = general_purpose::STANDARD.encode(signing_key.as_bytes());
    let public_key_base64 = general_purpose::STANDARD.encode(verifying_key.as_bytes());

    let encrypted_private_key = encrypt_data(&private_key_base64, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
    let encrypted_public_key = encrypt_data(&public_key_base64, password)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;

    fs::create_dir_all("keys")?;
    let priv_file_name = format!("keys/{}_eddsa_private_key.enc", username);
    let pub_file_name = format!("keys/{}_eddsa_public_key.enc", username);

    File::create(&priv_file_name)?.write_all(encrypted_private_key.as_bytes())?;
    File::create(&pub_file_name)?.write_all(encrypted_public_key.as_bytes())?;

    Ok(())
}

pub fn load_eddsa_keys(username: &str, password: &str) -> Result<(Ed25519PrivateKey, Ed25519PublicKey), Box<dyn std::error::Error>> {
    let priv_file_name = format!("keys/{}_eddsa_private_key.enc", username);
    let pub_file_name = format!("keys/{}_eddsa_public_key.enc", username);

    let mut priv_file = File::open(&priv_file_name)?;
    let mut priv_key_encrypted = String::new();
    priv_file.read_to_string(&mut priv_key_encrypted)?;
    let priv_key_decrypted = decrypt_data(&priv_key_encrypted, password)?;

    let priv_key_bytes = general_purpose::STANDARD.decode(priv_key_decrypted.trim())?;
    let priv_key_array: [u8; 32] = priv_key_bytes.as_slice().try_into()?;
    let signing_key = Ed25519PrivateKey::from_bytes(&priv_key_array);

    let mut pub_file = File::open(&pub_file_name)?;
    let mut pub_key_encrypted = String::new();
    pub_file.read_to_string(&mut pub_key_encrypted)?;
    let pub_key_decrypted = decrypt_data(&pub_key_encrypted, password)?;

    let pub_key_bytes = general_purpose::STANDARD.decode(pub_key_decrypted.trim())?;
    let pub_key_array: [u8; 32] = pub_key_bytes.as_slice().try_into()?;
    let verifying_key = Ed25519PublicKey::from_bytes(&pub_key_array)?;

    Ok((signing_key, verifying_key))
}

pub fn generate_dilithium_keys(sigalg: &Sig) -> Result<(sig::PublicKey, sig::SecretKey), Box<dyn std::error::Error>> {
    let (sig_pk, sig_sk) = sigalg.keypair()?;
    Ok((sig_pk, sig_sk))
}

/// Returns a tuple containing serialized signing key and verifying key.
pub fn generate_eddsa_keys() -> (Ed25519PrivateKey, Ed25519PublicKey) {
    // Create a cryptographically secure pseudorandom number generator.
    let mut csprng = OsRng;

    // Generate 32 random bytes for the private key.
    let mut secret_key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_key_bytes);

    // Create the signing key from the random bytes.
    let signing_key = Ed25519PrivateKey::from_bytes(&secret_key_bytes);

    // Serialize the signing key and verifying key to byte arrays.
    let signing_key_bytes = signing_key.clone().to_bytes(); // 32 bytes (private key)
    let verifying_key_bytes = signing_key.verifying_key(); // 32 bytes (public key)

    (signing_key_bytes.into(), verifying_key_bytes)
}

pub fn key_operations_dilithium(
    sigalg: &Sig,
    username: &str,
    password: &str,
) -> Result<(PublicKey, SecretKey), Box<dyn std::error::Error>> {
    // Check if we have already saved keys for the given username; if not, generate and save them
    match load_dilithium_keys_from_file(sigalg, username, password) {
        Ok((pk, sk)) => {
            println!("Loaded {}'s Dilithium5 keys from file.", username);
            Ok((pk, sk))
        },
        Err(_) => {
            let (pk, sk) = generate_dilithium_keys(sigalg)?;

            // Handle save result
            if let Err(e) = save_dilithium_keys_to_file(&pk, &sk, username, password) {
                // Log or handle the error appropriately
                println!("Error saving Dilithium5 keys for {}: {}", username, e);
                // Depending on your requirement, you may want to propagate this error or return a success anyway
                return Err(Box::new(e));
            }

            Ok((pk, sk))
        }
    }
}


pub fn key_operations_eddsa(
    username: &str,
    password: &str,
) -> Result<(Ed25519PrivateKey, [u8; 32]), Box<dyn std::error::Error>> {
    // Try to load the keys, expecting Result type from load_eddsa_keys
    let result = load_eddsa_keys(username, password);

    // If loading fails, generate and save new keys, otherwise return the loaded keys
    match result {
        Ok((sk, pk)) => {
            // Successfully loaded keys
            println!("Loaded {}'s EdDSA keys from file.", username);
            Ok((sk, pk.to_bytes()))  // Return public key and private key bytes
        },
        Err(_) => {
            // If loading failed, generate new keys and save them
            let (sk, pk) = generate_eddsa_keys();

            // Handle save result
            if let Err(e) = save_eddsa_keys(username, &sk, &pk, password) {
                // Log or handle the error appropriately
                println!("Error saving EdDSA keys for {}: {}", username, e);
                // Depending on your requirement, you may want to propagate this error or return a success anyway
                return Err(Box::new(e));
            }

            // Return the newly generated keys
            Ok((sk, pk.to_bytes()))
        }
    }
}
