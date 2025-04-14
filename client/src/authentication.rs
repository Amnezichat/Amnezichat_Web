use ed25519_dalek::{SigningKey as Ed25519PrivateKey, VerifyingKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier as Ed25519Verifier};
use oqs::sig::Sig;
use std::error::Error;

pub fn sign_data_with_dilithium(data: &[u8], dilithium_sk: &oqs::sig::SecretKey) -> Result<String, Box<dyn Error>> {

    let sigalg = Sig::new(oqs::sig::Algorithm::Dilithium5)?;

    let signature = sigalg.sign(data, dilithium_sk)?;

    let combined = format!(
        "{}-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----",
        hex::encode(data), 
        hex::encode(signature) 
    );

    Ok(combined)
}

pub fn verify_signature_with_dilithium(data: &[u8], dilithium_pk: &oqs::sig::PublicKey) -> Result<bool, Box<dyn Error>> {

    let data_str = String::from_utf8_lossy(data);

    let start_pos = data_str.find("-----BEGIN SIGNATURE-----").ok_or("Signature start not found")?;

    let data_before_signature = &data_str[..start_pos].trim();

    let data_bytes = hex::decode(data_before_signature)?;

    let end_pos = data_str.find("-----END SIGNATURE-----").ok_or("Signature end not found")?;

    let signature_hex = &data_str[start_pos + "-----BEGIN SIGNATURE-----".len()..end_pos].trim();
    let signature_bytes = hex::decode(signature_hex)?;

    let sigalg = Sig::new(oqs::sig::Algorithm::Dilithium5)?;

    let signature_ref = match (&sigalg).signature_from_bytes(&signature_bytes) {
        Some(sig) => sig,
        None => return Err("Invalid signature".into()),
    };

    sigalg.verify(&data_bytes, &signature_ref, dilithium_pk)?;

    Ok(true)
}

pub fn sign_data_with_eddsa(data: &[u8], eddsa_sk: &Ed25519SecretKey) -> Result<String, Box<dyn Error>> {

    let signing_key = Ed25519PrivateKey::from(*eddsa_sk); 

    let signature: Ed25519Signature = signing_key.sign(data);

    let combined = format!(
        "{}-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----",
        hex::encode(data), 
        hex::encode(signature.to_bytes()) 
    );

    Ok(combined)
}

pub fn verify_signature_with_eddsa(signature_with_data: &str, eddsa_pk: &Ed25519PublicKey) -> Result<bool, Box<dyn Error>> {
    let start_pos = signature_with_data
        .find("-----BEGIN SIGNATURE-----")
        .ok_or("Signature start marker not found")?;
    let end_pos = signature_with_data
        .find("-----END SIGNATURE-----")
        .ok_or("Signature end marker not found")?;

    let signature_hex = &signature_with_data[start_pos + "-----BEGIN SIGNATURE-----".len()..end_pos].trim();
    let signature_bytes = hex::decode(signature_hex).map_err(|e| format!("Failed to decode signature: {}", e))?;

    let signature_array: &[u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Signature byte slice is not 64 bytes long")?;

    let signature = Ed25519Signature::from_bytes(signature_array);

    let data_before_signature = &signature_with_data[..start_pos].trim();

    let data_bytes = hex::decode(data_before_signature).map_err(|e| format!("Failed to decode data: {}", e))?;

    let verification_result = eddsa_pk
        .verify(&data_bytes, &signature)
        .map_err(|_| "Signature verification failed");

    match verification_result {
        Ok(_) => println!("Signature verification successful."),
        Err(_) => println!("Signature verification failed."),
    }

    verification_result?;

    Ok(true)
}