use eframe::egui;
use reqwest;
use serde::{Deserialize, Serialize}; // Import Serialize as welluse serde_bencode::from_bytes;
use serde_bencode::{from_bytes, value::Value};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use std::fs; // Add this to handle binary data
use url::form_urlencoded;

#[derive(Debug, Serialize, Deserialize)]
struct Torrent {
    announce: String,
    info: Info,
}

#[derive(Debug, Serialize, Deserialize)]
struct Info {
    name: String,
    length: Option<u64>,
    #[serde(default)]
    piece_length: u64,
    pieces: ByteBuf, // Fix: Use ByteBuf instead of Vec<u8>
}

fn contact_tracker(
    announce_url: &str,
    info_hash: &[u8; 20],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_id = "-RT0001-123456789012"; // Random peer ID
    let params = form_urlencoded::Serializer::new(String::new())
        .append_pair("info_hash", &String::from_utf8_lossy(info_hash))
        .append_pair("peer_id", peer_id)
        .append_pair("port", "36363")
        .append_pair("uploaded", "0")
        .append_pair("downloaded", "0")
        .append_pair("left", &file_size.to_string())
        .append_pair("compact", "1")
        .finish();

    let url = format!("{}?{}", announce_url, params);
    let response = reqwest::blocking::get(&url)?.bytes()?;

    println!("Tracker Response: {:?}", response);
    Ok(())
}

fn compute_info_hash(info: &Info) -> [u8; 20] {
    let encoded_info = serde_bencode::to_bytes(info).expect("Failed to encode info dict");
    let mut hasher = Sha1::new();
    hasher.update(encoded_info);
    let result = hasher.finalize();
    result.into()
}

fn parse_torrent_file(path: &str) -> Result<Torrent, Box<dyn std::error::Error>> {
    let path = path.trim_matches('"');
    println!("Trying to load file: {}", path);

    if !std::path::Path::new(path).exists() {
        eprintln!("Error: File '{}' does not exist!", path);
        return Err("File not found".into());
    }

    let data = fs::read(path)?;
    println!("Raw data (hex): {:?}", hex::encode(&data)); // Debug print raw data

    // Try parsing as generic bencode structure first
    match serde_bencode::from_bytes::<Value>(&data) {
        Ok(decoded) => println!("Decoded Bencode: {:?}", decoded),
        Err(e) => eprintln!("Failed to decode raw bencode: {}", e),
    }

    // Now attempt to parse into the Torrent struct
    let torrent: Torrent = from_bytes(&data)?;

    let info_hash = compute_info_hash(&torrent.info);

    println!("Info Hash: {:?}", hex::encode(info_hash));
    contact_tracker(
        &torrent.announce,
        &info_hash,
        torrent.info.length.unwrap_or(0),
    )?;
    Ok(torrent)
}

struct TorrentApp {
    torrent: Option<Torrent>,
    file_path: String,
}

impl Default for TorrentApp {
    fn default() -> Self {
        Self {
            torrent: None,
            file_path: "example.torrent".to_string(),
        }
    }
}

impl eframe::App for TorrentApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Torrent Parser");
            ui.label("Enter .torrent file path:");
            ui.text_edit_singleline(&mut self.file_path);

            if ui.button("Load Torrent").clicked() {
                match parse_torrent_file(&self.file_path) {
                    Ok(torrent) => self.torrent = Some(torrent),
                    Err(e) => eprintln!("Failed to parse: {}", e),
                }
            }

            if let Some(ref torrent) = self.torrent {
                ui.label(format!("Announce URL: {}", torrent.announce));
                ui.label(format!("Name: {}", torrent.info.name));
                if let Some(length) = torrent.info.length {
                    ui.label(format!("Length: {} bytes", length));
                }
                ui.label(format!("Piece Length: {} bytes", torrent.info.piece_length));
            }
        });
    }
}

fn main() {
    let options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "Torrent Parser",
        options,
        Box::new(|_cc| Ok(Box::new(TorrentApp::default()))),
    );
}
