use base64::{engine::general_purpose, Engine};
use oqs::kem::{Kem, Algorithm};
use ed25519_dalek::{VerifyingKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Sha3_512, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use std::{error::Error, time::Duration};

use crate::{create_client_with_proxy, fetch_ciphertext, fetch_kyber_pubkey, send_ciphertext, send_kyber_pubkey, sign_data_with_dilithium, sign_data_with_eddsa, verify_signature_with_dilithium, verify_signature_with_eddsa};

pub fn kyber_key_exchange(
    room_id: &str,
    dilithium_pks: &[oqs::sig::PublicKey],
    dilithium_sk: &oqs::sig::SecretKey,
    server_url: &str, 
) -> Result<String, Box<dyn Error>> {

    let kemalg = Kem::new(Algorithm::Kyber1024)?;

    let (kem_pk, kem_sk) = kemalg.keypair()?;
    let kem_pk_hex = hex::encode(kem_pk.as_ref());

    let public_key = fetch_kyber_pubkey(room_id, server_url); 
    let is_alice = match public_key {
        Some(ref key) if !key.is_empty() => {
            println!("Fetched public key: {}", key);
            false
        }
        _ => {
            println!("No valid public key found. Sending own Kyber public key.");
            send_kyber_pubkey(room_id, &kem_pk_hex, server_url); 
            true
        }
    };

    let shared_secret_result = if is_alice {
        let ciphertext = fetch_ciphertext(room_id, server_url); 

        let start_pos = ciphertext.find("-----BEGIN SIGNATURE-----").ok_or("Signature start not found")?;

        let ciphertext_before_signature = &ciphertext[..start_pos].trim();

        let decoded_ct = hex::decode(ciphertext_before_signature)?;

        let mut signature_verified = false;
        for dilithium_pk in dilithium_pks {
            if verify_signature_with_dilithium(ciphertext.as_bytes(), dilithium_pk).is_ok() {
                println!("Signature verified with Dilithium public key.");
                signature_verified = true;
                break;
            }
        }

        if !signature_verified {
            return Err("Failed to verify signature with any Dilithium public key.".into());
        }

        let ciphertext_obj = kemalg
            .ciphertext_from_bytes(&decoded_ct)
            .ok_or("Invalid ciphertext bytes")?;

        let shared_secret = kemalg.decapsulate(&kem_sk, &ciphertext_obj)?;
        let mut hasher = Sha3_512::new();
        hasher.update(shared_secret.as_ref());
        let result = hasher.finalize();
        let shared_secret_result = hex::encode(result);

        shared_secret_result
    } else {
        let alice_pk_bytes = hex::decode(public_key.unwrap())?;
        let alice_pk_ref = kemalg
            .public_key_from_bytes(&alice_pk_bytes)
            .ok_or("Failed to convert Alice's public key")?;

        let (kem_ct, shared_secret) = kemalg.encapsulate(&alice_pk_ref)?;

        let ciphertext_signature = sign_data_with_dilithium(kem_ct.as_ref(), dilithium_sk)?;
        println!("Bob signed the ciphertext: {}", ciphertext_signature);

        send_ciphertext(room_id, &ciphertext_signature, server_url); 

        let mut hasher = Sha3_512::new();
        hasher.update(shared_secret.as_ref());
        let result = hasher.finalize();
        let shared_secret_result = hex::encode(result);

        shared_secret_result
    };

    Ok(shared_secret_result)
}

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    room_id: String,
}

pub fn perform_ecdh_key_exchange(
    room_id: &str,
    eddsa_sk: &Ed25519SecretKey,
    eddsa_pk: &Ed25519PublicKey,
    server_url: &str, 
) -> Result<String, Box<dyn std::error::Error>> {

    let secret_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = X25519PublicKey::from(&secret_key);

    let public_key_bytes = public_key.as_bytes();

    let signed_public_key = sign_data_with_eddsa(public_key_bytes, eddsa_sk)?;

    let formatted_signed_public_key = format!("ECDH_PUBLIC_KEY:{}[END DATA]", signed_public_key);

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    loop {

        let message = Message {
            message: formatted_signed_public_key.clone(),
            room_id: room_id.to_string(),
        };

        let send_url = format!("{}/send", server_url); 
        if let Err(err) = client.post(&send_url).json(&message).timeout(Duration::from_secs(60)).send() {
            eprintln!("Failed to send signed public key to the server: {}", err);
            continue; 
        } else {
            println!("Successfully sent signed public key to the server.");
        }

        let fetch_url = format!("{}/messages?room_id={}", server_url, room_id); 
        let res = match client.get(&fetch_url).timeout(Duration::from_secs(60)).send() {
            Ok(response) => response,
            Err(err) => {
                eprintln!("Failed to fetch the other party's public key: {}", err);
                continue; 
            }
        };

        if !res.status().is_success() {
            eprintln!("Non-success status code while fetching messages: {}", res.status());
            continue; 
        }

        let html_response = match res.text() {
            Ok(text) => text,
            Err(err) => {
                eprintln!("Failed to read response text: {}", err);
                continue; 
            }
        };

        let start_tag = "ECDH_PUBLIC_KEY:";
        let end_tag = "[END DATA]";
        let mut keys_processed = false;

        let mut start = 0;
        while let Some(start_pos) = html_response[start..].find(start_tag) {
            start += start_pos + start_tag.len();
            if let Some(end_pos) = html_response[start..].find(end_tag) {
                let extracted_signed_key = &html_response[start..start + end_pos].trim();

                if let Err(err) = verify_signature_with_eddsa(extracted_signed_key, eddsa_pk) {
                    eprintln!("Failed to verify the signature: {}", err);
                    continue; 
                }

                let extracted_key = extracted_signed_key.split("-----BEGIN SIGNATURE-----").next().unwrap().trim();

                if extracted_key == formatted_signed_public_key {
                    println!("Ignoring our own public key.");
                    start += end_pos + end_tag.len(); 
                    keys_processed = true;
                    continue; 
                }

                match hex::decode(extracted_key) {
                    Ok(other_public_key_bytes) => {
                        if other_public_key_bytes.len() != 32 {
                            eprintln!("Invalid public key length: {}", other_public_key_bytes.len());
                            continue;
                        }

                        let other_public_key_bytes =
                            match <[u8; 32]>::try_from(other_public_key_bytes.as_slice()) {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    eprintln!("Failed to convert other public key bytes: {}", err);
                                    continue;
                                }
                            };

                        let other_public_key = X25519PublicKey::from(other_public_key_bytes);
                        let shared_secret = secret_key.diffie_hellman(&other_public_key);
                        let shared_secret_base64 = general_purpose::STANDARD.encode(shared_secret.as_bytes());
                        return Ok(shared_secret_base64);
                    }
                    Err(err) => {
                        eprintln!("Failed to decode other public key: {}", err);
                    }
                }

                start += end_pos + end_tag.len();
                keys_processed = true;
            } else {
                eprintln!("End tag not found after start tag. Skipping.");
                break;
            }
        }

        if !keys_processed {
            eprintln!("No valid other signed public keys found. Retrying...");
        }
    }
}