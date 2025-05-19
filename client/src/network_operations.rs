use rand::Rng;
use regex::Regex;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use std::{thread, time::Duration};

use crate::{clear_screen, encryption::decrypt_data, MessageData};

#[derive(Serialize, Deserialize)]
struct Message {
    message: String,
    room_id: String,
}

pub fn create_client_with_proxy(proxy: &str) -> Client {
    if proxy == "" {
        let transport = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false)

        .build()
        .unwrap();

    transport
    } else {
        let transport = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(false)
        .proxy(reqwest::Proxy::all(proxy).expect("Invalid proxy address"))

        .build()
        .unwrap();

    transport
    }
}

pub fn fetch_kyber_pubkey(password: &str, server_url: &str) -> Option<String> {

    let mut rng = rand::thread_rng();
    let delay_secs = rng.gen_range(10..=60);
    println!("Waiting for {} seconds to prevent race condition...", delay_secs);
    thread::sleep(Duration::from_secs(delay_secs));

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
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
                    return None; 
                }
                println!("Error while fetching public key. Retrying...");
                thread::sleep(Duration::from_secs(2)); 
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
                    thread::sleep(Duration::from_secs(2)); 
                    continue;
                }
            };

            if let Some(public_key_start) = body.find("KYBER_PUBLIC_KEY:") {
                let public_key = &body[public_key_start + "KYBER_PUBLIC_KEY:".len()..]; 
                if let Some(end_data) = public_key.find("[END DATA]") {
                    return Some(public_key[0..end_data].to_string()); 
                }
            }
        }

        retries += 1;
        if retries > max_retries {
            return None; 
        }

        println!("Public key not found. Retrying...");
        thread::sleep(Duration::from_secs(2)); 
    }
}

pub fn fetch_dilithium_pubkeys(password: &str, server_url: &str) -> Vec<String> {

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
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
                    return Vec::new(); 
                }
                println!("Error while fetching public keys. Retrying...");
                thread::sleep(Duration::from_secs(2)); 
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
                    thread::sleep(Duration::from_secs(2)); 
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
                return public_keys; 
            }
        }

        retries += 1;
        if retries > max_retries {
            eprintln!("Public keys not found after {} retries.", max_retries);
            return Vec::new(); 
        }

        println!("No valid public keys found in response. Retrying...");
        thread::sleep(Duration::from_secs(2)); 
    }
}

pub fn fetch_eddsa_pubkeys(password: &str, server_url: &str) -> Vec<String> {

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
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
                    return Vec::new(); 
                }
                println!("Error while fetching public keys. Retrying...");
                thread::sleep(Duration::from_secs(2)); 
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
                    thread::sleep(Duration::from_secs(2)); 
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
                return public_keys; 
            }
        }

        retries += 1;
        if retries > max_retries {
            eprintln!("Public keys not found after {} retries.", max_retries);
            return Vec::new(); 
        }

        println!("No valid public keys found in response. Retrying...");
        thread::sleep(Duration::from_secs(2)); 
    }
}

pub fn fetch_ciphertext(password: &str, server_url: &str) -> String {

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, password);

    loop {
        let res: Response = match client.get(&url).timeout(Duration::from_secs(60)).send() {
            Ok(response) => response,
            Err(err) => {
                println!("Error while fetching ciphertext: {}. Retrying...", err);
                thread::sleep(Duration::from_secs(2)); 
                continue;
            }
        };

        if res.status().is_success() {
            let body = match res.text() {
                Ok(text) => text,
                Err(err) => {
                    println!("Error while reading response body: {}. Retrying...", err);
                    thread::sleep(Duration::from_secs(2)); 
                    continue;
                }
            };

            if let Some(ciphertext_start) = body.find("KYBER_PUBLIC_KEY:CIPHERTEXT:") {
                let ciphertext = &body[ciphertext_start + "KYBER_PUBLIC_KEY:CIPHERTEXT:".len()..]; 
                if let Some(end_data) = ciphertext.find("[END DATA]") {
                    return ciphertext[0..end_data].to_string(); 
                }
            }
        }

        println!("Ciphertext not found. Retrying...");
        thread::sleep(Duration::from_secs(2)); 
    }
}

pub fn send_kyber_pubkey(room_id: &str, public_key: &str, url: &str) {

    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); 
    let message = Message {
        message: format!("KYBER_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res = client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send(); 

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

    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); 
    let message = Message {
        message: format!("DILITHIUM_PUBLIC_KEY:{}[END DATA]", public_key),
        room_id: room_id.to_string(),
    };

    let res = client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send(); 

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

    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); 
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

    let proxy = if url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let full_url = format!("{}/send", url); 
    let message = Message {
        message: format!("KYBER_PUBLIC_KEY:CIPHERTEXT:{}[END DATA]", ciphertext),
        room_id: room_id.to_string(),
    };

    let res: Response = client.post(&full_url).json(&message).timeout(Duration::from_secs(60)).send().unwrap(); 

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

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let formatted_encrypted_message = format!(
        "-----BEGIN ENCRYPTED MESSAGE-----{}-----END ENCRYPTED MESSAGE-----",
        encrypted_message
    );

    let message_data = MessageData {
        message: formatted_encrypted_message,
        room_id: room_id.to_string(),
    };

    let send_url = format!("{}/send", server_url);

    let res = client
        .post(&send_url)
        .json(&message_data)
        .timeout(Duration::from_secs(60)) 
        .send()?;

    if res.status().is_success() {
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

    let proxy = if server_url.contains(".i2p") {
        "http://127.0.0.1:4444" 
    } else if server_url.contains(".onion") {
        "socks5h://127.0.0.1:9050"
    } else {
        ""
    };
    let client = create_client_with_proxy(proxy);

    let url = format!("{}/messages?room_id={}", server_url, room_id);

    let res = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(30)) 
        .send()?;

    let mut messages = Vec::new();

    if res.status().is_success() {
        clear_screen();

        let body = res.text()?;

        let re = Regex::new(r"-----BEGIN ENCRYPTED MESSAGE-----\s*(.*?)\s*-----END ENCRYPTED MESSAGE-----")
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        for cap in re.captures_iter(&body) {
            if let Some(encrypted_message) = cap.get(1) {

                let cleaned_message = encrypted_message.as_str().trim();

                match decrypt_data(cleaned_message, shared_secret) {
                    Ok(decrypted_message) => {
                        fn unpad_message(message: &str) -> String {

                            if let Some(start) = message.find("<padding>") {
                                if let Some(end) = message.find("</padding>") {
                                    let (message_before_padding, _) = message.split_at(start); 
                                    let (_, message_after_padding) = message.split_at(end + 10); 
                                    return format!("{}{}", message_before_padding, message_after_padding);
                                }
                            }
                            message.to_string()  
                        }                                  

                        let unpadded_message = unpad_message(&decrypted_message);

                        if unpadded_message.contains("[DUMMY_DATA]:") {
                            continue;
                        }

                        if !gui && unpadded_message.contains("<media>") {
                            continue;
                        }

                        if !gui && unpadded_message.contains("<pfp>") {
                            continue;
                        }

                        let final_message = if gui {
                            unpadded_message.to_string()
                        } else {

                            let strong_re = Regex::new(r"<strong>(.*?)</strong>").unwrap();
                            strong_re.replace_all(&unpadded_message, |caps: &regex::Captures| {

                                format!("\x1b[1m{}\x1b[0m", &caps[1])
                            }).to_string()
                        };

                        messages.push(final_message);
                    }
                    Err(_e) => {

                    }
                }
            }
        }
    } else {

        eprintln!("Failed to fetch messages: {} - {}", res.status(), res.text()?);
    }

    Ok(messages)
}