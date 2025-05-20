#[macro_use]
extern crate rocket;

use rocket::response::{Redirect, content::RawHtml};
use rocket::serde::{Serialize, Deserialize};
use rocket::State;
use rocket::http::Status;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{interval, Duration};
use std::time::{SystemTime, UNIX_EPOCH};
use html_escape::encode_text;
use zeroize::Zeroize;
use rocket::serde::json::Json;

mod encryption;
use crate::encryption::{encrypt_message, decrypt_message, is_message_encrypted};

const TIME_WINDOW: u64 = 60;
const MESSAGE_LIMIT: usize = 200;
const MAX_MESSAGE_LENGTH: usize = 5 * 1024 * 1024;
const RECENT_MESSAGE_LIMIT: usize = 200;
const MESSAGE_EXPIRY_DURATION: u64 = 600;
const MAX_ACTIVE_REQUESTS: usize = 100;
const ROOM_TIME_WINDOW: u64 = 60; 
const ROOM_MESSAGE_LIMIT: usize = 60; 

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    content: String,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct MessageData {
    message: String,
    room_id: String,
}

#[derive(Debug)]
struct ChatState {
    messages: Arc<Mutex<Vec<Message>>>,
    user_request_timestamps: Arc<Mutex<HashMap<String, (u64, u64)>>>,
    recent_messages: Arc<Mutex<HashSet<String>>>,
    global_message_timestamps: Arc<Mutex<Vec<u64>>>,
    room_limits: Arc<Mutex<HashMap<String, usize>>>,
    recent_fingerprints: Arc<Mutex<HashSet<String>>>,
    active_requests: Arc<Semaphore>,

    room_message_timestamps: Arc<Mutex<HashMap<String, Vec<u64>>>>,
}

impl Clone for ChatState {
    fn clone(&self) -> Self {
        ChatState {
            messages: Arc::clone(&self.messages),
            user_request_timestamps: Arc::clone(&self.user_request_timestamps),
            recent_messages: Arc::clone(&self.recent_messages),
            global_message_timestamps: Arc::clone(&self.global_message_timestamps),
            room_limits: Arc::clone(&self.room_limits),
            recent_fingerprints: Arc::clone(&self.recent_fingerprints),
            active_requests: Arc::clone(&self.active_requests),
            room_message_timestamps: Arc::clone(&self.room_message_timestamps),
        }
    }
}

fn format_timestamp(timestamp: u64) -> String {
    let seconds = timestamp % 60;
    let minutes = (timestamp / 60) % 60;
    let hours = (timestamp / 3600) % 24;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

async fn check_message_limit(state: &ChatState) -> bool {
    let mut global_timestamps = state.global_message_timestamps.lock().await;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    global_timestamps.retain(|&timestamp| current_time - timestamp <= TIME_WINDOW);

    if global_timestamps.len() >= MESSAGE_LIMIT {
        return false;
    }

    global_timestamps.push(current_time);
    true
}

async fn check_room_rate_limit(state: &ChatState, room_id: &str) -> bool {
    let mut room_timestamps = state.room_message_timestamps.lock().await;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let timestamps = room_timestamps.entry(room_id.to_string()).or_default();

    timestamps.retain(|&t| current_time - t <= ROOM_TIME_WINDOW);

    if timestamps.len() >= ROOM_MESSAGE_LIMIT {
        return false; 
    }

    timestamps.push(current_time);
    true
}

async fn is_message_valid(message: &str, state: &ChatState) -> bool {
    if message.len() > MAX_MESSAGE_LENGTH {
        return false;
    }

    let mut messages = state.messages.lock().await;

    if messages.len() >= RECENT_MESSAGE_LIMIT {
        wipe_message_content(&mut messages[0]);
        messages.remove(0);
    }

    true
}

#[get("/messages?<room_id>")]
async fn messages(room_id: Option<String>, state: &State<Arc<ChatState>>) -> String {
    let chat_state = state.inner();
    let messages = chat_state.messages.lock().await;

    let mut html = String::new();
    for message in messages.iter() {
        let timestamp = format_timestamp(message.timestamp);

        let decrypted_content = match &room_id {
            Some(ref pw) => decrypt_message(&message.content, pw).unwrap_or_else(|_| {
                return String::new();
            }),
            None => String::new(),
        };

        if decrypted_content.is_empty() {
            continue;
        }

        html.push_str(&format!(
            r#"<p>[{}]: {}</p>"#,
            timestamp,
            encode_text(&decrypted_content)
        ));
    }

    html
}

#[get("/?<room_id>")]
async fn index(room_id: Option<String>, state: &State<Arc<ChatState>>) -> Result<RawHtml<String>, Status> {
    let mut html = tokio::fs::read_to_string("static/index.html")
        .await
        .map_err(|_error| Status::InternalServerError)?;

    let room_id_value = room_id.clone().unwrap_or_else(|| "".to_string());

    let encoded_room_id = encode_text(&room_id_value);

    html = html.replace("room_id_PLACEHOLDER", &encoded_room_id);

    let messages = state.messages.lock().await;
    let mut messages_html = String::new();

    for msg in messages.iter() {
        let timestamp = format_timestamp(msg.timestamp);

        let decrypted_content = if let Some(ref pw) = room_id {
            decrypt_message(&msg.content, pw).unwrap_or_else(|_| "Decryption failed".to_string())
        } else {
            "room_id not provided".to_string()
        };

        messages_html.push_str(&format!(
            "<p>[{}]: {}</p>",
            timestamp,
            encode_text(&decrypted_content)
        ));
    }

    html = html.replace("<!-- Messages will be dynamically inserted here -->", &messages_html);

    Ok(RawHtml(html))
}

#[post("/send", data = "<message_data>")]
async fn send(message_data: Json<MessageData>, state: &State<Arc<ChatState>>) -> Result<Redirect, RawHtml<String>> {
    let message = message_data.message.trim();
    let room_id = message_data.room_id.trim();

    if !check_message_limit(&state.inner()).await {
        return Err(RawHtml("Too many messages sent globally in a short period. Please wait for 2 minutes.".to_string()));
    }

    if !check_room_rate_limit(&state.inner(), room_id).await {
        return Err(RawHtml(format!("Too many messages sent to room {} in a short period. Please wait a while.", encode_text(room_id))));
    }

    if room_id.is_empty() {
        return Err(RawHtml("Room room_id cannot be empty. Please provide a room_id.".to_string()));
    }

    if room_id.len() < 8 {
        return Err(RawHtml("Room room_id must be at least 8 characters long.".to_string()));
    }

    if !is_message_valid(message, state).await {
        return Err(RawHtml("Invalid message. Make sure it's less than 5MB.".to_string()));
    }

    if !is_message_encrypted(message) {
        return Err(RawHtml("Message is not encrypted. Please provide an encrypted message.".to_string()));
    }

    let mut messages = state.messages.lock().await;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let encrypted_content = encrypt_message(message, room_id).map_err(|_| RawHtml("Encryption failed.".to_string()))?;

    messages.push(Message {
        content: encrypted_content,
        timestamp,
    });

    Ok(Redirect::to(format!("/")))
}

fn wipe_message_content(message: &mut Message) {
    message.content.zeroize();
}

async fn message_cleanup_task(state: Arc<ChatState>) {
    let mut interval = interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut messages = state.messages.lock().await;

        if let Some(oldest_message_index) = messages.iter().position(|message| {
            current_time - message.timestamp >= MESSAGE_EXPIRY_DURATION
        }) {
            wipe_message_content(&mut messages[oldest_message_index]);
            messages.remove(oldest_message_index);
        }
    }
}

#[tokio::main]
async fn main() {
    let state = Arc::new(ChatState {
        messages: Arc::new(Mutex::new(vec![])),
        user_request_timestamps: Arc::new(Mutex::new(HashMap::new())),
        recent_messages: Arc::new(Mutex::new(HashSet::new())),
        global_message_timestamps: Arc::new(Mutex::new(vec![])),
        room_limits: Arc::new(Mutex::new(HashMap::new())),
        recent_fingerprints: Arc::new(Mutex::new(HashSet::new())),
        active_requests: Arc::new(Semaphore::new(MAX_ACTIVE_REQUESTS)),

        room_message_timestamps: Arc::new(Mutex::new(HashMap::new())),
    });

    tokio::spawn(message_cleanup_task(state.clone()));

    rocket::build()
        .manage(state)
        .mount("/", routes![index, send, messages])
        .mount("/static", rocket::fs::FileServer::from("static"))
        .launch()
        .await
        .unwrap();
}
