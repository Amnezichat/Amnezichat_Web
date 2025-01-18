use ed25519_dalek::{SigningKey as Ed25519PrivateKey, VerifyingKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey, Signature as Ed25519Signature, Signer as Ed25519Signer, Verifier as Ed25519Verifier};
use oqs::sig::Sig;
use std::error::Error;


pub fn sign_data_with_dilithium(data: &[u8], dilithium_sk: &oqs::sig::SecretKey) -> Result<String, Box<dyn Error>> {
    // Create the signature algorithm instance for Dilithium5
    let sigalg = Sig::new(oqs::sig::Algorithm::Dilithium5)?;

    // Sign the data using the secret key
    let signature = sigalg.sign(data, dilithium_sk)?;

    // Format the data and signature into a single combined string
    let combined = format!(
        "{}-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----",
        hex::encode(data), // Data encoded as hex
        hex::encode(signature) // Signature encoded as hex
    );

    Ok(combined)
}

pub fn verify_signature_with_dilithium(data: &[u8], dilithium_pk: &oqs::sig::PublicKey) -> Result<bool, Box<dyn Error>> {
    // Convert the data to a string for easier processing
    let data_str = String::from_utf8_lossy(data);

    // Find the "-----BEGIN SIGNATURE-----" delimiter
    let start_pos = data_str.find("-----BEGIN SIGNATURE-----").ok_or("Signature start not found")?;

    // Extract the data before the signature part (i.e., before the "-----BEGIN SIGNATURE-----")
    let data_before_signature = &data_str[..start_pos].trim();
    
    // If the extracted data before the signature is hex-encoded, decode it
    let data_bytes = hex::decode(data_before_signature)?;

    // Find the "-----END SIGNATURE-----" delimiter
    let end_pos = data_str.find("-----END SIGNATURE-----").ok_or("Signature end not found")?;

    // Extract the signature hex value and decode it
    let signature_hex = &data_str[start_pos + "-----BEGIN SIGNATURE-----".len()..end_pos].trim();
    let signature_bytes = hex::decode(signature_hex)?;

    // Initialize the Dilithium algorithm for signature verification
    let sigalg = Sig::new(oqs::sig::Algorithm::Dilithium5)?;
    
    // Attempt to convert the signature bytes to a valid signature
    let signature_ref = match (&sigalg).signature_from_bytes(&signature_bytes) {
        Some(sig) => sig,
        None => return Err("Invalid signature".into()),
    };

    // Verify the signature using the provided public key
    sigalg.verify(&data_bytes, &signature_ref, dilithium_pk)?;

    Ok(true)
}

pub fn sign_data_with_eddsa(data: &[u8], eddsa_sk: &Ed25519SecretKey) -> Result<String, Box<dyn Error>> {
    // Create a SigningKey using the SecretKey
    let signing_key = Ed25519PrivateKey::from(*eddsa_sk); // Create SigningKey from SecretKey

    // Sign the raw data using the EdDSA secret key
    let signature: Ed25519Signature = signing_key.sign(data);

    // Format the data and signature into a single combined string
    let combined = format!(
        "{}-----BEGIN SIGNATURE-----\n{}\n-----END SIGNATURE-----",
        hex::encode(data), // Hex-encoded data
        hex::encode(signature.to_bytes()) // Signature encoded as hex
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

    // Verify the signature with the original data
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