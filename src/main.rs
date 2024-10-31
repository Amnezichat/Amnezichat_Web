#[macro_use]
extern crate rocket;

use rocket::response::Redirect;
use rocket::serde::{Serialize, Deserialize};
use rocket::State;
use rocket::response::content::RawHtml;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use std::time::{SystemTime, UNIX_EPOCH};
use html_escape::encode_text;
use tokio::time::sleep;
use zeroize::Zeroize;
use base64::{engine::general_purpose, Engine};

// Import encryption dependencies
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::Rng;
use argon2::{Argon2, password_hash::SaltString, PasswordHasher};

// Type alias for AES-256-CBC
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Constants for the encryption
const ENCRYPTION_IV_SIZE: usize = 16;

// Constants
const TIME_WINDOW: u64 = 60;
const REQUEST_LIMIT: u64 = 5;
const MAX_USERNAME_LENGTH: usize = 30;
const MAX_MESSAGE_LENGTH: usize = 300;
const RECENT_MESSAGE_LIMIT: usize = 1000; // Maximum number of messages
const MESSAGE_EXPIRY_DURATION: u64 = 86400; // 1 day

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    username: String,
    content: String,
    timestamp: u64,
}

#[derive(Debug)]
struct ChatState {
    messages: Arc<Mutex<Vec<Message>>>,
    user_request_timestamps: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    recent_messages: Arc<Mutex<HashSet<String>>>,
}

// Manually implement Clone for ChatState with Arc
impl Clone for ChatState {
    fn clone(&self) -> Self {
        ChatState {
            messages: Arc::clone(&self.messages),
            user_request_timestamps: Arc::clone(&self.user_request_timestamps),
            recent_messages: Arc::clone(&self.recent_messages),
        }
    }
}

// Encryption key derivation function with salt
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::b64_encode(salt).expect("Failed to generate salt string");
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password");
    let hash_bytes = hash.hash.expect("Hash missing in PasswordHash structure");

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    key
}

// Encryption function
fn encrypt_message(plain_text: &str, password: &str) -> Result<String, &'static str> {
    let mut rng = rand::thread_rng();
    let iv: [u8; ENCRYPTION_IV_SIZE] = rng.gen();
    let salt: [u8; 16] = rng.gen();

    let mut key = derive_key(password, &salt);

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|_| "Encryption error")?;
    let encrypted_data = cipher.encrypt_vec(plain_text.as_bytes());

    // Zeroize key after use
    key.zeroize();

    Ok(format!("{}:{}:{}", hex::encode(salt), hex::encode(iv), hex::encode(encrypted_data)))
}

// Decryption function
fn decrypt_message(encrypted_text: &str, password: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = encrypted_text.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted message format");
    }

    let salt = hex::decode(parts[0]).map_err(|_| "Decryption error")?;
    let iv = hex::decode(parts[1]).map_err(|_| "Decryption error")?;
    let encrypted_data = hex::decode(parts[2]).map_err(|_| "Decryption error")?;

    let mut key = derive_key(password, &salt);
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).map_err(|_| "Decryption error")?;
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).map_err(|_| "Decryption error")?;

    // Zeroize key after use
    key.zeroize();

    String::from_utf8(decrypted_data).map_err(|_| "Decryption error")
}

// Helper function to format the timestamp into HH:MM:SS
fn format_timestamp(timestamp: u64) -> String {
    let seconds = timestamp % 60;
    let minutes = (timestamp / 60) % 60;
    let hours = (timestamp / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

// Check if a user is allowed to send a message based on rate-limiting
async fn is_request_allowed(username: &str, state: &ChatState) -> bool {
    let mut timestamps = state.user_request_timestamps.lock().await;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Check if the user has made requests before
    if let Some((last_request_time, request_count)) = timestamps.get_mut(username) {
        if current_time - *last_request_time > TIME_WINDOW {
            // Reset count if the time window has passed
            *last_request_time = current_time;
            *request_count = 1; // Reset count for the new time window
            true
        } else if *request_count < REQUEST_LIMIT {
            // Increment count if within limits
            *request_count += 1;
            true
        } else {
            // Rate limit exceeded
            false
        }
    } else {
        // New user, initialize their count
        timestamps.insert(username.to_string(), (current_time, 1));
        true
    }
}

// Function to check if the message is valid (length and total message count)
async fn is_message_valid(message: &str, state: &ChatState) -> bool {
    // Check if the message length exceeds the maximum limit
    if message.len() > MAX_MESSAGE_LENGTH {
        return false;
    }

    // Lock the messages state to access the total message count
    let mut messages = state.messages.lock().await;

    // Check if the total number of messages exceeds the limit
    if messages.len() >= RECENT_MESSAGE_LIMIT {
        // Wipe the content of the oldest message before removing it
        wipe_message_content(&mut messages[0]);
        messages.remove(0); // Remove the first message in the vector (oldest)
    }

    true
}

// Index route to render chat interface with decrypted messages
#[get("/?<username>&<password>")]
async fn index(username: Option<String>, password: Option<String>, state: &State<Arc<ChatState>>) -> RawHtml<String> {
    let messages = state.messages.lock().await;

    let mut html = String::from(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
            <meta http-equiv="refresh" content="60">
            <title>Amnesichat</title>
            <style>
                * {
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }
                body {
                    background-color: #000000;
                    color: #e0e0e0;
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    flex-direction: column;
                    min-height: 100vh;
                }
                h1 {
                    font-size: 1.5em;
                    text-align: center;
                    color: #ffffff;
                    margin-bottom: 10px;
                }
                #disclaimer {
                    font-size: 0.9em;
                    text-align: center;
                    margin-bottom: 15px;
                    font-style: italic;
                }
                #chat-container {
                    flex: 1;
                    background-color: #1e1e1e;
                    padding: 10px;
                    margin: 10px;
                    border-radius: 8px;
                    overflow-y: auto;
                    display: flex;
                    flex-direction: column;
                    max-height: 70vh;
                }
                #messages {
                    flex: 1;
                    overflow-y: auto;
                }
                #messages p {
                    background-color: #2e2e2e;
                    border-left: 4px solid #00c853;
                    padding: 10px;
                    margin-bottom: 10px;
                    border-radius: 6px;
                    line-height: 1.5;
                }
                #chat-form {
                    background-color: #1c1c1c;
                    padding: 10px;
                    border-radius: 8px;
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    box-shadow: 0 -4px 10px rgba(0, 0, 0, 0.5);
                }
                input[type="text"], input[type="password"], input[type="submit"] {
                    border-radius: 6px;
                    padding: 10px;
                    margin-top: 5px;
                    width: 100%;
                    max-width: 100%;
                    background-color: #2e2e2e;
                    color: #e0e0e0;
                    border: 1px solid #444;
                }
                input[type="submit"] {
                    background-color: #007bff;
                    color: white;
                    border: none;
                    cursor: pointer;
                    transition: background-color 0.3s ease;
                }
                input[type="submit"]:hover {
                    background-color: #0056b3;
                }
                @media (max-width: 768px) {
                    h1 {
                        font-size: 1.2em;
                    }
                    #chat-container {
                        max-height: 60vh;
                        margin: 5px;
                    }
                    #chat-form {
                        padding: 10px;
                    }
                    input[type="text"], input[type="submit"], input[type="password"] {
                        font-size: 1em;
                        padding: 8px;
                    }
                }
                #footer {
                    text-align: center;
                    margin-top: 15px;
                }
                #footer a {
                    color: #007bff;
                    text-decoration: none;
                }
                #footer a:hover {
                    text-decoration: underline;
                }
                /* Styles for the no-script warning message */
                .noscript-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.9); /* Dark overlay */
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: 9999; /* Ensure it is on top of other content */
                }
                .noscript-message {
                    text-align: center;
                    padding: 20px;
                    background-color: rgba(30, 30, 30, 0.9); /* Slightly lighter background for the message */
                    border-radius: 10px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
                }
                details {
                    background-color: #1c1c1c;
                    border-radius: 8px;
                    margin: 10px 0;
                    padding: 10px;
                }
                summary {
                    cursor: pointer;
                    outline: none;
                    font-weight: bold;
                }
            </style>
            <script src="/static/crypto-js.min.js"></script>
            <script>
                window.onload = function() {
                    // Retrieve and set the client-side password from localStorage
                    const savedPassword = localStorage.getItem('client-password');
                    if (savedPassword) {
                        document.getElementById('client-password').value = savedPassword;
                    }
                    decryptMessages(); // Decrypt messages upon loading
                };

                function deriveKeyAndIV(password, salt) {
                    // Using PBKDF2 to derive a key and IV from the password
                    const iterations = 100000;
                    const key = CryptoJS.PBKDF2(password, salt, {
                        keySize: 256 / 32,
                        iterations: iterations
                    });

                    // Deriving IV from the same password and salt, ensuring consistency
                    const iv = CryptoJS.PBKDF2(password, salt, {
                        keySize: 128 / 32, // IV size is 128 bits (16 bytes)
                        iterations: iterations
                    });

                    return { key, iv };
                }

                function encryptMessage() {
                    const clientPassword = document.getElementById('client-password').value;
                    const message = document.getElementById('message').value;
                    if (clientPassword && message) {
                        const salt = CryptoJS.lib.WordArray.random(128 / 8); // Generate a random salt
                        const { key, iv } = deriveKeyAndIV(clientPassword, salt);
                        
                        const encrypted = CryptoJS.AES.encrypt(message, key, { iv: iv }).toString();

                        // Save the encrypted message along with the salt and IV in the format "encrypted[salt][iv]"
                        document.getElementById('message').value = `${encrypted} [${salt.toString()}] [${iv.toString()}]`;

                        // Save the client-side password in localStorage
                        localStorage.setItem('client-password', clientPassword);
                    }
                    // Clear the client password field
                    document.getElementById('client-password').value = ''; 
                }

                function decryptMessages() {
                    // Retrieve the client-side password from localStorage
                    const clientPassword = localStorage.getItem('client-password');
                    if (!clientPassword) {
                        console.warn("Client-side password not set. Unable to decrypt messages.");
                        return;
                    }

                    const messageElements = document.querySelectorAll('#messages p');

                    messageElements.forEach((element) => {
                        const messageText = element.innerHTML;
                        const regex = /(.*?) \[(.*?)\]: (.+)/; // Regex to match "username [timestamp]: encryptedMessage"
                        const matches = messageText.match(regex);

                        if (matches && matches.length === 4) {
                            const username = matches[1].trim();
                            const timestamp = matches[2].trim();
                            const encryptedMessageWithSaltAndIV = matches[3].trim();

                            console.log("Decrypting message:", { username, timestamp, encryptedMessageWithSaltAndIV });

                            if (encryptedMessageWithSaltAndIV) {
                                try {
                                    const [encryptedMessage, saltString, ivString] = encryptedMessageWithSaltAndIV.split(' [');
                                    const salt = CryptoJS.enc.Hex.parse(saltString.replace(']', '')); // Parse the salt
                                    const iv = CryptoJS.enc.Hex.parse(ivString.replace(']', '')); // Parse the IV
                                    const { key } = deriveKeyAndIV(clientPassword, salt); // Derive the key using the same salt

                                    // Decrypt using the derived key and IV
                                    const decryptedBytes = CryptoJS.AES.decrypt(encryptedMessage, key, { iv: iv });
                                    const decrypted = decryptedBytes.toString(CryptoJS.enc.Utf8);

                                    if (decrypted) {
                                        element.innerHTML = `<strong>${username}</strong> [${timestamp}]: ${decrypted}`;
                                        console.log("Decrypted message:", decrypted);
                                    } else {
                                        console.error("Decryption failed for message:", encryptedMessage);
                                    }
                                } catch (error) {
                                    console.error("Error during decryption:", error);
                                }
                            } else {
                                console.warn("Encrypted message or client password missing for element:", element);
                            }
                        } else {
                            console.warn("Message format is incorrect:", messageText);
                        }
                    });
                }
            </script>
        </head>
        <body>
            <h1>Amnesichat</h1>
            <div id="disclaimer">Warning: By using this service, you agree to the terms of service and acknowledge that you will not use it for illegal activities. The developer is not responsible for any misuse of the tool.</div>
            <noscript>
                <div class="noscript-overlay">
                    <div class="noscript-message">
                        <h2>JavaScript is Disabled</h2>
                        <p>This chat application requires JavaScript to function properly. Please enable JavaScript in your browser settings.</p>
                    </div>
                </div>
            </noscript>
            <div id="chat-container">
                <h2>Messages:</h2>
                <div id="messages">
        "#,
    );

    for msg in messages.iter() {
        let timestamp = format_timestamp(msg.timestamp);
        
        // Decrypt the message content using the provided password
        let decrypted_content = match &password {
            Some(ref pw) => decrypt_message(&msg.content, pw), // Directly using the password
            None => Err("Password not provided"), // Handle missing password case
        };

        // Only push to HTML if decryption is successful
        if let Ok(content) = decrypted_content {
            html.push_str(&format!(
                "<p><strong>{}</strong> [{}]: {}</p>",
                encode_text(&msg.username), // Escape username
                timestamp,
                encode_text(&content) // Escape decrypted message content
            ));
        } // Ignore messages with decryption failure
    }

    html.push_str(
        r#"
                </div>
            </div>
            <div id="chat-form">
                <form action="/send" method="get" onsubmit="encryptMessage()">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required value="USERNAME_PLACEHOLDER"><br>
                    <label for="message">Message:</label>
                    <input type="text" id="message" name="message" required><br>
                    <label for="client-password" required>E2E Encryption Password:</label>
                    <input type="text" id="client-password" name="client-password"><br> <!-- Client-side password -->
                    <label for="password">Room Password (Optional):</label>
                    <input type="text" id="password" name="password" value="PASSWORD_PLACEHOLDER"><br> <!-- Server-side password -->
                    <input type="submit" value="Send">
                </form>
            </div>
            <div id="footer">
                <p>
                    <a href="https://github.com/umutcamliyurt/Amnesichat" target="_blank">Source Code</a> |
                    <a href="monero:8495bkvsReJAvxm8YP5KUQ9BWxh6Ta63eZGjF4HqU4JcUXdQtXBeBGyWte8L95sSJUMUvh5GHD1RcTNebfTNmFgmRX4XJja">Donate Monero</a>
                </p>
                <details>
                    <summary>Privacy Policy</summary>
                    <p>Your privacy is of utmost importance to us. This Privacy Policy outlines how we handle your information when you use our services.</p>
                    <p>We do not collect, store, or share any personal information or chat logs from users. All messages are temporary and are deleted once the chat session ends.</p>
                    <p>All communication on Amnesichat is encrypted using industry-standard encryption protocols to ensure your conversations remain private and secure.</p>
                    <p>Our service does not use cookies or any tracking technologies to collect data about your usage. We do not monitor your activities on our platform.</p>
                    <p>We may update this Privacy Policy from time to time to reflect changes in our practices. We encourage you to periodically review this page for the latest information on our privacy practices.</p>
                    <p>If you have any questions about this Privacy Policy or our data practices, please contact us at nemesisuks@protonmail.com.</p>
                </details>

                <details>
                    <summary>Terms of Service</summary>
                    <p>By accessing or using Amnesichat, you agree to be bound by the following terms and conditions:</p>
                    <p>These Terms of Service govern your use of the Amnesichat service. If you do not agree to these terms, you should not use the service.</p>
                    <p>You agree to use Amnesichat solely for lawful purposes. Prohibited activities include, but are not limited to:</p>
                    <ul>
                        Engaging in any form of harassment, abuse, or harmful behavior towards others.
                        Sharing illegal content or engaging in illegal activities.
                        Attempting to access, interfere with, or disrupt the service or servers.
                        Impersonating any person or entity or misrepresenting your affiliation with a person or entity.
                    </ul>
                    <p>Amnesichat is not responsible for any loss, damage, or harm resulting from your use of the service or any third-party interactions. Use of the service is at your own risk.</p>
                    <p>We reserve the right to modify or discontinue the service at any time without notice. We will not be liable for any modification, suspension, or discontinuance of the service.</p>
                    <p>These Terms of Service shall be governed by and construed in accordance with the laws of Türkiye.</p>
                    <p>We may update these Terms of Service from time to time. We will notify users of any significant changes by posting a notice on our website. Continued use of the service after changes signifies your acceptance of the new terms.</p>
                    <p>If you have any questions regarding these Terms of Service, please contact us at nemesisuks@protonmail.com.</p>
                </details>

            </div>
        </body>
        </html>
        "#
    );

    let username_value = username.unwrap_or_else(|| "".to_string());
    let password_value = password.unwrap_or_else(|| "".to_string());
    let final_html = html
        .replace("USERNAME_PLACEHOLDER", &username_value)
        .replace("PASSWORD_PLACEHOLDER", &password_value);
    RawHtml(final_html)
}

// Route for sending a message with encryption
#[get("/send?<username>&<message>&<password>")]
async fn send(username: String, message: String, password: String, state: &State<Arc<ChatState>>) -> Result<Redirect, RawHtml<String>> {
    let username = username.trim();
    let message = message.trim();
    let password = password.trim();

    // Delay message processing by 2 seconds
    sleep(Duration::from_secs(2)).await;

    // Check if the username length exceeds the maximum limit
    if username.len() > MAX_USERNAME_LENGTH {
        return Err(RawHtml("Username is too long. Please use a shorter username.".to_string()));
    }

    // Validate the request frequency limit
    if !is_request_allowed(username, state).await {
        return Err(RawHtml("You are sending messages too quickly. Please wait a moment.".to_string()));
    }

    // Check if the message is valid (length and total message count)
    if !is_message_valid(message, state).await {
        return Err(RawHtml("Invalid message. Make sure it's less than 300 characters.".to_string()));
    }

    // Check if the message is encrypted
    if !is_message_encrypted(message) {
        return Err(RawHtml("Message is not encrypted. Please provide an encrypted message.".to_string()));
    }

    // Lock the messages state
    let mut messages = state.messages.lock().await;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Encrypt the message using the provided password
    let encrypted_content = encrypt_message(message, password).map_err(|_| RawHtml("Encryption failed.".to_string()))?;

    // Store the encrypted message
    messages.push(Message {
        username: username.to_string(),
        content: encrypted_content,
        timestamp,
    });

    // Redirect to the main page, including the username and password in the URL
    Ok(Redirect::to(format!("/?username={}&password={}", username, password)))
}

fn is_message_encrypted(message: &str) -> bool {
    // Split the message by spaces to extract potential parts
    let parts: Vec<&str> = message.split_whitespace().collect();
    
    // Check if we have at least three parts (the encrypted message, salt, and IV)
    if parts.len() < 3 {
        return false; // Not enough parts to be valid
    }

    // The first part should be the base64 encoded encrypted message
    let encrypted_message = parts[0];

    // The last two parts should be the salt and IV, enclosed in brackets
    let salt_part = parts[1];
    let iv_part = parts[2];

    // Check if the salt and IV parts are in the correct format
    if !salt_part.starts_with('[') || !salt_part.ends_with(']') || 
       !iv_part.starts_with('[') || !iv_part.ends_with(']') {
        return false; // Salt or IV is not in the correct format
    }

    // Extract salt and IV by removing the brackets
    let salt = &salt_part[1..salt_part.len()-1]; // Remove the '[' and ']'
    let iv = &iv_part[1..iv_part.len()-1];     // Remove the '[' and ']'

    // Validate the encrypted message is a valid base64 string using the general purpose engine
    general_purpose::STANDARD.decode(encrypted_message).is_ok() &&
    // Validate the salt and IV are valid hex strings
    is_valid_hex(salt) &&
    is_valid_hex(iv)
}

// Function to check if a string is a valid hex string
fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

// Function to wipe message content securely
fn wipe_message_content(message: &mut Message) {
    // Overwrite the message content with zeros
    let empty_content = vec![0u8; message.content.len()];
    message.content = String::from_utf8(empty_content).unwrap_or_default();
}

// Cleanup task to remove expired messages and securely wipe their contents
async fn message_cleanup_task(state: Arc<ChatState>) {
    let mut interval = interval(Duration::from_secs(1)); // Check every second

    loop {
        interval.tick().await; // Wait for the next tick of the interval

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Acquire the lock on messages
        let mut messages = state.messages.lock().await;

        // Check if there are messages that should be wiped
        if let Some(oldest_message_index) = messages.iter().position(|message| {
            current_time - message.timestamp >= MESSAGE_EXPIRY_DURATION
        }) {
            // Securely wipe the content of the oldest message
            wipe_message_content(&mut messages[oldest_message_index]);

            // Remove the oldest message
            messages.remove(oldest_message_index);
        }
    }
}

#[launch]
async fn rocket() -> _ {
    let chat_state = Arc::new(ChatState {
        messages: Arc::new(Mutex::new(vec![])),
        user_request_timestamps: Arc::new(Mutex::new(HashMap::new())),
        recent_messages: Arc::new(Mutex::new(HashSet::new())),
    });

    // Spawn the message cleanup task
    let cleanup_task_state = Arc::clone(&chat_state);
    tokio::spawn(message_cleanup_task(cleanup_task_state));

    rocket::build()
        .manage(chat_state)
        .mount("/", routes![index, send])
        .mount("/static", rocket::fs::FileServer::from("static"))
}
