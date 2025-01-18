use crate::encrypt_data;
use crate::receive_and_fetch_messages;
use crate::send_encrypted_message;
use crate::pad_message;
use eframe::egui;
use image::GenericImageView;
use rfd::FileDialog;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use regex::Regex;
use base64;

pub struct MessagingApp {
    username: String,
    message_input: String,
    messages: Arc<Mutex<Vec<String>>>,
    shared_hybrid_secret: Arc<std::string::String>,
    shared_room_id: Arc<String>,
    shared_url: Arc<String>,
    image_data: Option<String>,
}

impl MessagingApp {
    pub fn new(
        username: String,
        shared_hybrid_secret: Arc<std::string::String>,
        shared_room_id: Arc<String>,
        shared_url: Arc<String>,
    ) -> Self {
        let messages = Arc::new(Mutex::new(vec![]));
        let messages_clone = Arc::clone(&messages);
        let shared_hybrid_secret_clone = Arc::clone(&shared_hybrid_secret);
        let shared_room_id_clone = Arc::clone(&shared_room_id);
        let shared_url_clone = Arc::clone(&shared_url);

        thread::spawn(move || loop {
            match receive_and_fetch_messages(
                &shared_room_id_clone,
                &shared_hybrid_secret_clone,
                &shared_url_clone,
                true,
            ) {
                Ok(new_messages) => {
                    let mut msgs = messages_clone.lock().unwrap();
                    msgs.clear();
                    msgs.extend(new_messages);
                }
                Err(e) => {
                    eprintln!("Error fetching messages: {}", e);
                }
            }
            thread::sleep(Duration::from_secs(10));
        });

        MessagingApp {
            username,
            message_input: String::new(),
            messages,
            shared_hybrid_secret,
            shared_room_id,
            shared_url,
            image_data: None,
        }
    }

    fn handle_image_upload(&mut self) {
        if let Some(file_path) = FileDialog::new().add_filter("Image files", &["png", "jpg", "jpeg", "bmp", "gif"]).pick_file() {
            match fs::read(&file_path) {
                Ok(data) => {
                    let encoded = base64::encode(data);
                    self.image_data = Some(format!("[IMAGE_DATA]:{}[END DATA]", encoded));
                }
                Err(e) => eprintln!("Error reading image file: {}", e),
            }
        }
    }
}

impl eframe::App for MessagingApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                let chat_area_height = ui.available_height() - 80.0;

                egui::Frame::none()
                    .fill(egui::Color32::from_black_alpha(50))
                    .rounding(10.0)
                    .inner_margin(egui::style::Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.set_height(chat_area_height);
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                let messages = self.messages.lock().unwrap();
                                let re = Regex::new(r"</?strong>").unwrap();

                                for message in messages.iter() {
                                    if message.contains("[IMAGE_DATA]:") {
                                        if let Some(encoded) = message.split("[IMAGE_DATA]:").nth(1) {
                                            if let Some(end_idx) = encoded.find("[END DATA]") {
                                                let image_data = &encoded[..end_idx];
                                                match base64::decode(image_data) {
                                                    Ok(decoded) => {
                                                        if let Ok(image) = image::load_from_memory(&decoded) {
                                                            let size = image.dimensions();
                                                            let color_image = egui::ColorImage::from_rgba_unmultiplied(
                                                                [size.0 as usize, size.1 as usize],
                                                                &image.to_rgba8(),
                                                            );
                                                            let texture = ctx.load_texture(
                                                                "received_image",
                                                                color_image,
                                                                egui::TextureOptions::LINEAR,
                                                            );
                                                            ui.image(&texture);
                                                        } else {
                                                            eprintln!("Failed to decode image format");
                                                        }
                                                    }
                                                    Err(e) => eprintln!("Error decoding base64 image: {}", e),
                                                }
                                            }
                                        }
                                    } else {
                                        let cleaned_message = re.replace_all(message, "");
                                        ui.label(
                                            egui::RichText::new(cleaned_message.as_ref())
                                                .size(16.0)
                                                .color(egui::Color32::WHITE),
                                        );
                                    }
                                }
                            });
                    });

                ui.horizontal(|ui| {
                    let input_box_width = ui.available_width() * 0.65;
                    let button_width = ui.available_width() * 0.15;

                    let text_edit = egui::TextEdit::singleline(&mut self.message_input)
                        .hint_text("Type a message...")
                        .text_color(egui::Color32::WHITE)
                        .frame(true);
                    ui.add_sized([input_box_width, 40.0], text_edit);

                    if ui.add_sized([button_width, 40.0], egui::Button::new("Send")).clicked() {
                        let mut message = format!("<strong>{}</strong>: {}", self.username, self.message_input);
                        if let Some(image) = &self.image_data {
                            message.push_str(image);
                            self.image_data = None;
                        }

                        // Pad the message to a fixed length (e.g., 2048 bytes)
                        let padded_message = pad_message(&message, 2048);

                        if let Err(e) = send_encrypted_message(
                            &encrypt_data(&padded_message, &self.shared_hybrid_secret).unwrap(),
                            &self.shared_room_id,
                            &self.shared_url,
                        ) {
                            eprintln!("Error sending message: {}", e);
                        } else {
                            self.message_input.clear();
                        }
                    }

                    if ui.add_sized([button_width, 40.0], egui::Button::new("Upload Image")).clicked() {
                        self.handle_image_upload();
                    }
                });
            });
        });
    }
}

pub fn run_gui(
    username: String,
    shared_hybrid_secret: Arc<std::string::String>,
    shared_room_id: Arc<String>,
    shared_url: Arc<String>,
) -> Result<(), eframe::Error> {
    let app = MessagingApp::new(
        username,
        shared_hybrid_secret,
        shared_room_id,
        shared_url,
    );
    let native_options = eframe::NativeOptions {
        ..Default::default()
    };
    eframe::run_native("Amnezichat", native_options, Box::new(|_| Box::new(app)))
}
