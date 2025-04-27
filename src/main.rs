use eframe::egui;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_bencode::{from_bytes, value::Value};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use torrent_parser::{parse_torrent_file, Torrent};
use std::fs;

mod torrent_parser;


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
