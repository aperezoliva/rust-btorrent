use eframe::egui;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_bencode::{from_bytes, value::Value};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use std::fs;

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
    pieces: ByteBuf,
}

fn percent_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("%{:02X}", b)).collect()
}

fn contact_tracker(
    announce_url: &str,
    info_hash: &[u8; 20],
    file_size: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_id = "-RT0001-123456789012";
    let info_hash_encoded = percent_encode(info_hash);
    let peer_id_encoded = percent_encode(peer_id.as_bytes());

    if !announce_url.starts_with("http") {
        println!("Skipping non-HTTP tracker: {}", announce_url);
        return Ok(());
    }

    let url = format!(
        "{}?info_hash={}&peer_id={}&port=36363&uploaded=0&downloaded=0&left={}&compact=1",
        announce_url, info_hash_encoded, peer_id_encoded, file_size
    );

    let response = reqwest::blocking::get(&url)?.bytes()?;
    println!("Raw tracker response (hex): {:?}", hex::encode(&response));

    // Parse tracker response as bencoded dictionary
    let tracker_response: Value = from_bytes(&response)?;
    if let Value::Dict(dict) = tracker_response {
    if let Some(peers_value) = dict.get(&b"peers"[..]) {
        if let Value::Bytes(peers) = peers_value {
            println!("Peers:");
            for chunk in peers.chunks(6) {
                if chunk.len() < 6 {
                    continue;
                }
                let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                println!("  {}:{}", ip, port);
            }
        } else {
            println!("`peers` field is not a byte string.");
        }
    } else {
        println!("No `peers` key found in tracker response.");
    }
} else {
    println!("Tracker response is not a dict.");
}

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
    println!("Raw data (hex): {:?}", hex::encode(&data));

    match serde_bencode::from_bytes::<Value>(&data) {
        Ok(decoded) => println!("Decoded Bencode: {:?}", decoded),
        Err(e) => eprintln!("Failed to decode raw bencode: {}", e),
    }

    let torrent: Torrent = from_bytes(&data)?;
    let info_hash = compute_info_hash(&torrent.info);

    println!("Info Hash: {:?}", hex::encode(info_hash));

    contact_tracker(
        &torrent.announce,
        &info_hash,
        torrent.info.length.unwrap_or(0),
    )?;

    if let Ok(decoded) = serde_bencode::from_bytes::<Value>(&data) {
    println!("Decoded Bencode Tree:");
    print_bencode_tree(&decoded, 0);
}

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

fn print_bencode_tree(value: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    match value {
        Value::Int(i) => println!("{}Int: {}", pad, i),
        Value::Bytes(bytes) => {
            if let Ok(s) = std::str::from_utf8(bytes) {
                println!("{}Bytes: {:?}", pad, s);
            } else {
                println!("{}Bytes: ({} bytes)", pad, bytes.len());
            }
        }
        Value::List(list) => {
            println!("{}List [", pad);
            for item in list {
                print_bencode_tree(item, indent + 2);
            }
            println!("{}]", pad);
        }
        Value::Dict(dict) => {
            println!("{}Dict {{", pad);
            for (key, val) in dict {
                let key_display = match std::str::from_utf8(key) {
                    Ok(s) => format!("{:?}", s),
                    Err(_) => format!("(binary key: {} bytes)", key.len()),
                };
                println!("{}  Key: {}", pad, key_display);
                print_bencode_tree(val, indent + 4);
            }
            println!("{}}}", pad);
        }
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
