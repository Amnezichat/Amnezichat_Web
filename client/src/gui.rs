use crate::{encrypt_data, pad_message, receive_and_fetch_messages, send_encrypted_message};
use rocket::{get, post, routes, serde::json::Json, State};
use rocket::fs::{NamedFile, FileServer};
use rocket::tokio;
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
        shared_room_id_mutex: Arc<Mutex<String>>,
        shared_url_mutex: Arc<Mutex<String>>,
    ) -> Self {
        let room_id_str = shared_room_id_mutex.lock().unwrap().clone();
        let url_str = shared_url_mutex.lock().unwrap().clone();

        let room_id = Arc::new(room_id_str);
        let url = Arc::new(url_str);

        let messages = Arc::new(Mutex::new(vec![]));
        let messages_clone = Arc::clone(&messages);

        let shared_room_id_mutex_clone = Arc::clone(&shared_room_id_mutex);
        let shared_url_mutex_clone = Arc::clone(&shared_url_mutex);
        let shared_hybrid_secret_clone = Arc::clone(&shared_hybrid_secret);

        tokio::spawn(async move {
            loop {
                let room_id_str = shared_room_id_mutex_clone.lock().unwrap().clone();
                let url_str = shared_url_mutex_clone.lock().unwrap().clone();
                let secret_clone = Arc::clone(&shared_hybrid_secret_clone);

                let result = tokio::task::spawn_blocking(move || {
                    receive_and_fetch_messages(&room_id_str, &secret_clone, &url_str, true)
                        .map_err(|e| {
                            Box::<dyn std::error::Error + Send + Sync>::from(format!("{}", e))
                        })
                }).await;

                match result {
                    Ok(Ok(new_messages)) => {
                        let mut msgs = messages_clone.lock().unwrap();
                        msgs.clear();
                        msgs.extend(new_messages);
                    }
                    Ok(Err(e)) => eprintln!("Error fetching messages: {}", e),
                    Err(e) => eprintln!("Join error: {}", e),
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
async fn get_messages(app: &State<MessagingApp>) -> Json<Vec<String>> {
    let result = fetch_and_update_messages(app).await;

    match result {
        Ok(msgs) => Json(msgs),
        Err(e) => {
            eprintln!("Error fetching messages: {}", e);
            let msgs = app.messages.lock().unwrap();
            Json(msgs.clone())
        }
    }
}

async fn fetch_and_update_messages(app: &State<MessagingApp>) -> Result<Vec<String>, String> {
    let room_id_str = app.shared_room_id.clone();
    let url_str = app.shared_url.clone();
    let secret_clone = app.shared_hybrid_secret.clone();

    let new_messages = tokio::task::spawn_blocking(move || {
        receive_and_fetch_messages(&room_id_str, &secret_clone, &url_str, true)
            .map_err(|e| format!("Error fetching messages: {}", e))
    })
    .await
    .map_err(|e| format!("Spawn blocking join error: {}", e))??;

    let mut msgs = app.messages.lock().unwrap();
    msgs.clear();
    msgs.extend(new_messages.clone());

    Ok(new_messages)
}

#[post("/send", data = "<input>")]
async fn post_message(
    input: Json<MessageInput>,
    app: &State<MessagingApp>,
) -> Result<&'static str, rocket::http::Status> {
    let formatted_message = format!("<strong>{}</strong>: {}", app.username, input.message);
    let padded_message = pad_message(&formatted_message, 2048);

    let secret_clone = Arc::clone(&app.shared_hybrid_secret);
    let room_id_clone = Arc::clone(&app.shared_room_id);
    let url_clone = Arc::clone(&app.shared_url);

    let _result = tokio::task::spawn_blocking(move || {
        let encrypted = encrypt_data(&padded_message, &secret_clone)
            .map_err(|e| {
                eprintln!("Encryption error: {}", e);
                rocket::http::Status::InternalServerError
            })?;

        send_encrypted_message(&encrypted, &room_id_clone, &url_clone)
            .map_err(|e| {
                eprintln!("Send message error: {}", e);
                rocket::http::Status::InternalServerError
            })
    })
    .await
    .map_err(|_| rocket::http::Status::InternalServerError)??;

    {
        let mut msgs = app.messages.lock().unwrap();
        msgs.push(formatted_message);
    }

    Ok("Message sent")
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