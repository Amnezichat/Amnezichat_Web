use crate::encrypt_data;
use crate::receive_and_fetch_messages;
use crate::send_encrypted_message;
use crate::pad_message;
use rocket::{get, post, routes, serde::json::Json};
use rocket::fs::NamedFile;
use rocket::tokio;
use rocket::fs::FileServer;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::path::PathBuf;

#[derive(Clone)]
pub struct MessagingApp {
    username: String,
    messages: Arc<Mutex<Vec<String>>>,
    shared_hybrid_secret: Arc<String>,
    shared_room_id: Arc<String>,
    shared_url: Arc<String>,
}

#[derive(Serialize, Deserialize)]
struct MessageInput {
    message: String,
}

impl MessagingApp {
    pub fn new(
        username: String,
        shared_hybrid_secret: Arc<String>,
        shared_room_id: Arc<Mutex<String>>,
        shared_url: Arc<Mutex<String>>,
    ) -> Self {
        let messages = Arc::new(Mutex::new(vec![]));
        let messages_clone = Arc::clone(&messages);
        let shared_hybrid_secret_clone = Arc::clone(&shared_hybrid_secret);
        let shared_room_id_clone = Arc::clone(&shared_room_id);
        let shared_url_clone = Arc::clone(&shared_url);

        let room_id = Arc::new(shared_room_id_clone.lock().unwrap_or_else(|_| panic!("Failed to lock room_id")).clone());
        let url = Arc::new(shared_url_clone.lock().unwrap_or_else(|_| panic!("Failed to lock url")).clone());

        tokio::spawn(async move {
            loop {
                let room_id_str = shared_room_id_clone.lock().unwrap_or_else(|_| panic!("Failed to lock room_id")).clone();
                let url_str = shared_url_clone.lock().unwrap_or_else(|_| panic!("Failed to lock url")).clone();

                match receive_and_fetch_messages(
                    &room_id_str,
                    &shared_hybrid_secret_clone,
                    &url_str,
                    true,
                ) {
                    Ok(new_messages) => {
                        let mut msgs = messages_clone.lock().unwrap_or_else(|_| panic!("Failed to lock messages"));
                        msgs.clear();
                        msgs.extend(new_messages);
                    }
                    Err(e) => {
                        eprintln!("Error fetching messages: {}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        MessagingApp {
            username,
            messages,
            shared_hybrid_secret,
            shared_room_id: room_id,
            shared_url: url,
        }
    }
}

#[get("/messages")]
async fn get_messages(app: &rocket::State<MessagingApp>) -> Json<Vec<String>> {
    let result = fetch_and_update_messages(&app).await;
    
    match result {
        Ok(msgs) => Json(msgs),
        Err(e) => {
            eprintln!("Error fetching messages: {}", e);
            
            // Return current messages if fetching fails
            let msgs = app.messages.lock().unwrap_or_else(|_| panic!("Failed to lock messages"));
            Json(msgs.clone())
        }
    }
}

async fn fetch_and_update_messages(app: &rocket::State<MessagingApp>) -> Result<Vec<String>, String> {
    let room_id_str = app.shared_room_id.clone();
    let url_str = app.shared_url.clone();
    
    let new_messages = tokio::task::block_in_place(move || {
        receive_and_fetch_messages(
            &room_id_str,
            &app.shared_hybrid_secret,
            &url_str,
            true,
        )
    }).map_err(|e| format!("Error fetching messages: {}", e))?;

    // Update the in-memory message storage
    let mut msgs = app.messages.lock().unwrap_or_else(|_| panic!("Failed to lock messages"));
    msgs.clear();
    msgs.extend(new_messages.clone());

    Ok(new_messages)
}

#[post("/send", data = "<input>")]
async fn post_message(
    input: Json<MessageInput>,
    app: &rocket::State<MessagingApp>
) -> Result<&'static str, rocket::http::Status> {
    // Create the formatted message once
    let formatted_message = format!("<strong>{}</strong>: {}", app.username, input.message);
    let padded_message = pad_message(&formatted_message, 2048);

    let result = tokio::task::block_in_place(|| {
        // Encrypt the message
        let encrypted = encrypt_data(&padded_message, &app.shared_hybrid_secret)
            .map_err(|e| {
                eprintln!("Encryption error: {}", e);
                rocket::http::Status::InternalServerError
            })?;
        
        // Send the encrypted message
        send_encrypted_message(&encrypted, &app.shared_room_id, &app.shared_url)
            .map_err(|e| {
                eprintln!("Error sending message: {}", e);
                rocket::http::Status::InternalServerError
            })
    });

    match result {
        Ok(_) => {
            {
                let mut msgs = app.messages.lock().unwrap_or_else(|_| panic!("Failed to lock messages"));
                msgs.push(formatted_message);
            }
            Ok("Message sent")
        }
        Err(e) => Err(e),
    }
}

#[get("/")]
async fn serve_webpage() -> Option<NamedFile> {
    NamedFile::open(PathBuf::from("static/index.html")).await.ok()
}

pub fn create_rocket(app: MessagingApp) -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .manage(app)
        .mount("/", routes![get_messages, post_message, serve_webpage])
        .mount("/static", FileServer::from("static"))
}