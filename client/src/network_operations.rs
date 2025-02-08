use regex::Regex;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use std::{thread, time::Duration};

use crate::{clear_screen, encryption::decrypt_data, MessageData};

// Structures for public keys and ciphertext
#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    room_id: String,
}

// Function to create the reqwest blocking client with proxy
pub fn create_client_with_proxy(proxy: &str) -> Client {
    // Create the reqwest client with custom transport handling the proxy
    let transport = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false) // Reject invalid certificates
        .proxy(reqwest::Proxy::all(proxy).expect("Invalid proxy address")) // Set proxy
        // Route through Tor/I2P proxy
        .build()
        .unwrap();

    transport
}

pub fn fetch_kyber_pubkey(password: &str, server_url: &str) -> Option<String> {
    // Check if the server URL contains `.i2p`
    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);
    
    let url = format!("{}/messages?room_id={}", server_url, password);
    let mut retries = 0;
    let max_retries = 3;

    loop {
        let res: Response = match client.get(&url).timeout(Duration::from_secs(60)).send() {
            Ok(response) => response,
            Err(_) => {
                retries += 1;
                if retries > max_retries {
                    return None; // Return None after 3 failed attempts
                }
                println!("Error while fetching public key. Retrying...");
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(_) => {
                    retries += 1;
                    if retries > max_retries {
                        return None;
                    }
                    println!("Error while reading response body. Retrying...");
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            if let Some(public_key_start) = body.find("KYBER_PUBLIC_KEY:") {
                let public_key = &body[public_key_start + "KYBER_PUBLIC_KEY:".len()..]; // Remove marker
                if let Some(end_data) = public_key.find("[END DATA]") {
                    return Some(public_key[0..end_data].to_string()); // Remove [END DATA] marker
                }
            }
        }

        retries += 1;
        if retries > max_retries {
            return None; // Return None after 3 failed attempts
        }

        println!("Public key not found. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

pub fn fetch_dilithium_pubkeys(password: &str, server_url: &str) -> Vec<String> {
    // Check if the server URL contains `.i2p`
    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);
    let mut retries = 0;
    let max_retries = 3;

    loop {
        let res: Response = match client.get(&url).timeout(Duration::from_secs(60)).send() {
            Ok(response) => response,
            Err(_) => {
                retries += 1;
                if retries > max_retries {
                    eprintln!("Failed to fetch public keys after {} retries.", max_retries);
                    return Vec::new(); // Return an empty vector on failure
                }
                println!("Error while fetching public keys. Retrying...");
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(_) => {
                    retries += 1;
                    if retries > max_retries {
                        eprintln!("Failed to read response body after {} retries.", max_retries);
                        return Vec::new();
                    }
                    println!("Error while reading response body. Retrying...");
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            let mut public_keys = Vec::new();
            for key_data in body.split("DILITHIUM_PUBLIC_KEY:") {
                if let Some(end_data) = key_data.find("[END DATA]") {
                    let key = key_data[0..end_data].trim().to_string();
                    public_keys.push(key);
                }
            }

            if !public_keys.is_empty() {
                return public_keys; // Return all valid public keys
            }
        }

        retries += 1;
        if retries > max_retries {
            eprintln!("Public keys not found after {} retries.", max_retries);
            return Vec::new(); // Return an empty vector on failure
        }

        println!("No valid public keys found in response. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

pub fn fetch_eddsa_pubkeys(password: &str, server_url: &str) -> Vec<String> {
    // Check if the server URL contains `.i2p`
    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);
    let mut retries = 0;
    let max_retries = 3;

    loop {
        let res: Response = match client.get(&url).timeout(Duration::from_secs(60)).send() {
            Ok(response) => response,
            Err(_) => {
                retries += 1;
                if retries > max_retries {
                    eprintln!("Failed to fetch public keys after {} retries.", max_retries);
                    return Vec::new(); // Return an empty vector on failure
                }
                println!("Error while fetching public keys. Retrying...");
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(_) => {
                    retries += 1;
                    if retries > max_retries {
                        eprintln!("Failed to read response body after {} retries.", max_retries);
                        return Vec::new();
                    }
                    println!("Error while reading response body. Retrying...");
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            let mut public_keys = Vec::new();
            for key_data in body.split("EDDSA_PUBLIC_KEY:") {
                if let Some(end_data) = key_data.find("[END DATA]") {
                    let key = key_data[0..end_data].trim().to_string();
                    public_keys.push(key);
                }
            }

            if !public_keys.is_empty() {
                return public_keys; // Return all valid public keys
            }
        }

        retries += 1;
        if retries > max_retries {
            eprintln!("Public keys not found after {} retries.", max_retries);
            return Vec::new(); // Return an empty vector on failure
        }

        println!("No valid public keys found in response. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

pub fn fetch_ciphertext(password: &str, server_url: &str) -> String {
    // Check if the server URL contains `.i2p`
    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);

    loop {
        let res: Response = match client.get(&url).timeout(Duration::from_secs(60)).send() {
            Ok(response) => response,
            Err(err) => {
                println!("Error while fetching ciphertext: {}. Retrying...", err);
                thread::sleep(Duration::from_secs(2)); // Wait before retrying
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(err) => {
                    println!("Error while reading response body: {}. Retrying...", err);
                    thread::sleep(Duration::from_secs(2)); // Wait before retrying
                    continue;
                }
            };

            if let Some(ciphertext_start) = body.find("KYBER_PUBLIC_KEY:CIPHERTEXT:") {
                let ciphertext = &body[ciphertext_start + "KYBER_PUBLIC_KEY:CIPHERTEXT:".len()..]; // Remove marker
                if let Some(end_data) = ciphertext.find("[END DATA]") {
                    return ciphertext[0..end_data].to_string(); // Remove [END DATA] marker
                }
            }
        }

        // Wait for 2 seconds before retrying
        println!("Ciphertext not found. Retrying...");
        thread::sleep(Duration::from_secs(2)); // Sleep for 2 seconds before retrying
    }
}

pub fn send_kyber_pubkey(room_id: &str, public_key: &str, url: &str) {
    // Check if the server URL contains `.i2p`
    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("KYBER_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res = client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send(); // Use the full URL

    match res {
        Ok(response) if response.status().is_success() => {
            println!("Kyber1024 public key sent successfully!");
        }
        Ok(response) => {
            println!("Failed to send public key. Status: {}", response.status());
        }
        Err(e) => {
            println!("Failed to send public key. Error: {}", e);
        }
    }
}

pub fn send_dilithium_pubkey(room_id: &str, public_key: &str, url: &str) {
    // Check if the server URL contains `.i2p`
    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("DILITHIUM_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res = client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send(); // Use the full URL

    match res {
        Ok(response) if response.status().is_success() => {
            println!("Dilithium5 public key sent successfully!");
        }
        Ok(response) => {
            println!("Failed to send public key. Status: {}", response.status());
        }
        Err(e) => {
            println!("Failed to send public key. Error: {}", e);
        }
    }
}

pub fn send_eddsa_pubkey(room_id: &str, public_key: &str, url: &str) {
    // Check if the server URL contains `.i2p`
    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("EDDSA_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res: Response = match client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send() {
        Ok(response) => response,
        Err(_) => {
            println!("Failed to send the public key.");
            return;
        }
    };

    if res.status().is_success() {
        println!("EdDSA public key sent successfully!");
    } else {
        println!("Failed to send public key.");
    }
}

pub fn send_ciphertext(room_id: &str, ciphertext: &str, url: &str) {
    // Check if the server URL contains `.i2p`
    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); // Append /send to the URL
    let message = Message {
        message: format!("KYBER_PUBLIC_KEY:CIPHERTEXT:{}[END DATA]", ciphertext),
        room_id: room_id.to_string(),
    };

    let res: Response = client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send().unwrap(); // Use the full URL

    if res.status().is_success() {
        println!("Ciphertext sent successfully!");
    } else {
        println!("Failed to send ciphertext");
    }
}

pub fn send_encrypted_message(
    encrypted_message: &str,
    room_id: &str,
    server_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if the server URL contains `.i2p`
    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    // Format the encrypted message with the BEGIN and END markers
    let formatted_encrypted_message = format!(
        "-----BEGIN ENCRYPTED MESSAGE-----{}-----END ENCRYPTED MESSAGE-----",
        encrypted_message
    );

    // Create the message data to send
    let message_data = MessageData {
        message: formatted_encrypted_message,
        room_id: room_id.to_string(),
    };

    // Construct the full URL for sending the message
    let send_url = format!("{}/send", server_url);

    // Send the message via HTTP POST request
    let res = client
        .post(&send_url)
        .json(&message_data)
        .timeout(Duration::from_secs(60)) // Set a timeout for the request
        .send()?;

    // Check if the request was successful and print the result
    if res.status().is_success() {
        println!("Message sent successfully.");
    } else {
        eprintln!("Failed to send message: {}", res.status());
    }

    Ok(())
}

pub fn receive_and_fetch_messages(
    room_id: &str,
    shared_secret: &str,
    server_url: &str,
    gui: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // SOCKS5 Proxy setup
    // Check if the server URL contains `.i2p`
    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" // I2P Proxy address
    } else {
        "socks5h://127.0.0.1:9050" // SOCKS5 Proxy address (Tor)
    };
    let client = create_client_with_proxy(proxy);

    // Build the URL with the provided room password and server URL
    let url = format!("{}/messages?room_id={}", server_url, room_id);

    // Send a synchronous GET request to fetch messages
    let res = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(30)) // Set a timeout for the request
        .send()?;

    // Declare the vector to store messages outside the response block
    let mut messages = Vec::new();

    // Check if the request was successful
    if res.status().is_success() {
        clear_screen();
        // Get the body of the HTML response
        let body = res.text()?;

        // Define a regular expression to capture messages between the markers
        let re = Regex::new(r"-----BEGIN ENCRYPTED MESSAGE-----\s*(.*?)\s*-----END ENCRYPTED MESSAGE-----")
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        // Iterate over all matches in the HTML body
        for cap in re.captures_iter(&body) {
            if let Some(encrypted_message) = cap.get(1) {
                // Step 1: Get the encrypted message without the markers
                let cleaned_message = encrypted_message.as_str().trim();

                // Step 2: Decrypt the message (ignore the markers, only pass the actual content)
                match decrypt_data(cleaned_message, shared_secret) {
                    Ok(decrypted_message) => {
                        fn unpad_message(message: &str) -> String {
                            // Remove everything inside the <padding>...</padding> part and trim any extra spaces from the message
                            if let Some(start) = message.find("<padding>") {
                                if let Some(end) = message.find("</padding>") {
                                    let (message_before_padding, _) = message.split_at(start); // Part before <padding>
                                    let (_, message_after_padding) = message.split_at(end + 10); // Skip past </padding> (length 10 including '>')
                                    return format!("{}{}", message_before_padding, message_after_padding);
                                }
                            }
                            message.to_string()  // In case there are no <padding>...</padding> markers
                        }                                  
                        
                        let unpadded_message = unpad_message(&decrypted_message);
                        
                        // Ignore messages containing `[DUMMY_DATA]:`
                        if unpadded_message.contains("[DUMMY_DATA]:") {
                            continue;
                        }

                        // If gui is false, skip messages containing `<media>`
                        if !gui && unpadded_message.contains("<media>") {
                            continue;
                        }

                        // If gui is false, skip messages containing `<pfp>`
                        if !gui && unpadded_message.contains("<pfp>") {
                            continue;
                        }

                        // If gui is true, do not replace <strong> tags
                        let final_message = if gui {
                            unpadded_message.to_string()
                        } else {
                            // Step 3: Replace <strong> tags with ANSI escape codes for bold text
                            let strong_re = Regex::new(r"<strong>(.*?)</strong>").unwrap();
                            strong_re.replace_all(&unpadded_message, |caps: &regex::Captures| {
                                // Replace <strong>...</strong> with ANSI escape codes for bold text
                                format!("\x1b[1m{}\x1b[0m", &caps[1])
                            }).to_string()
                        };

                        // Add the messages to the list
                        messages.push(final_message);
                    }
                    Err(_e) => {
                        // Ignore decryption failure
                    }
                }
            }
        }
    } else {
        // Provide more detailed error info for failed requests
        eprintln!("Failed to fetch messages: {} - {}", res.status(), res.text()?);
    }

    // Return the collected messages
    Ok(messages)
}
