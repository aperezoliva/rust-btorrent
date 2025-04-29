// Libraries for decoding, file I/O, hashing, and communicating with a tracker
// Also draws in from other files' functions
use crate::tracker::PeerInfo;
use serde::{Deserialize, Serialize};
use serde_bencode::{from_bytes, value::Value};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use std::fs;

// Struct representing the 'info' dictionary usually supplied by a torrent file
#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    pub name: String,
    pub length: Option<u64>,
    #[serde(default)]
    pub piece_length: u64,
    pub pieces: ByteBuf,
}

// Main structure of a torrent file
#[derive(Debug, Serialize, Deserialize)]
pub struct Torrent {
    #[serde(default)]
    pub announce: Option<String>, // Now optional, because modern torrents might not have it WTF
    #[serde(rename = "announce-list", default)]
    pub announce_list: Option<Vec<Vec<String>>>, // Nested list of tracker URLs
    pub info: Info,
}

// Gui state for the app
pub struct TorrentApp {
    torrent: Option<Torrent>,
    file_path: String,
    peers: Vec<PeerInfo>,
}

// Default initialization for the app (empty torrent, default file path, no peers)
impl Default for TorrentApp {
    fn default() -> Self {
        Self {
            torrent: None,
            file_path: "example.torrent".to_string(),
            peers: Vec::new(),
        }
    }
}

// Main gui rendering and event handling function for the gui window
impl eframe::App for TorrentApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Torrent Parser");
            ui.label("Enter .torrent file path:");
            ui.text_edit_singleline(&mut self.file_path);

            if ui.button("Load Torrent").clicked() {
                match parse_torrent_file(&self.file_path) {
                    Ok(torrent) => {
                        self.torrent = Some(torrent);
                        self.peers.clear(); // clears old peers just incase
                    }
                    Err(e) => {
                        eprintln!("Failed to parse: {}", e);
                        self.torrent = None;
                        self.peers.clear();
                    }
                }
            }

            // buttont to find peers, worked with .unwrap but appearently that's not really recommended in rust
            if ui.button("Find Peers").clicked() {
                if let Some(ref torrent) = self.torrent {
                    if let Some(ref announce_url) = torrent.announce {
                        let info_hash = compute_info_hash(&torrent.info);
                        match crate::tracker::contact_tracker(
                            announce_url,
                            &info_hash,
                            torrent.info.length.unwrap_or(0),
                        ) {
                            Ok(peers) => {
                                self.peers = peers;
                            }
                            Err(e) => {
                                eprintln!("Failed to contact tracker: {}", e);
                            }
                        }
                    } else {
                        eprintln!("No announce URL available, cannot contact tracker.");
                    }
                }
            }
            if ui.button("Download Piece 0").clicked() {
                if let (Some(ref torrent), Some(peer)) = (self.torrent.as_ref(), self.peers.first())
                {
                    let info_hash = compute_info_hash(&torrent.info);
                    let peer_id = crate::peer::generate_peer_id(); // Generate new peer_id

                    // Attempt to connect to the first peer
                    match std::net::TcpStream::connect((peer.ip.as_str(), peer.port)) {
                        Ok(mut stream) => {
                            println!("Connected to peer {}:{}", peer.ip, peer.port);

                            if crate::peer::perform_handshake(&mut stream, &info_hash, &peer_id)
                                .is_ok()
                                && crate::peer::send_interested(&mut stream).is_ok()
                                && crate::peer::wait_for_unchoke(&mut stream).is_ok()
                            {
                                let piece_length = torrent.info.piece_length as u32; // Always safe to cast here
                                match crate::peer::download_piece(&mut stream, 0, piece_length) {
                                    Ok(piece_data) => {
                                        if std::fs::write("piece_0.bin", &piece_data).is_ok() {
                                            println!("Successfully downloaded and saved piece 0!");
                                        } else {
                                            eprintln!("Failed to save piece 0 to disk.");
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to download piece: {}", e);
                                    }
                                }
                            } else {
                                eprintln!("Handshake or interested/unchoke failed.");
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to peer: {}", e);
                        }
                    }
                } else {
                    eprintln!("No torrent loaded or no peers available!");
                }
            }
            // doesnt work for some reason, please delete this comment if it working
            // PLEASE
            if let Some(ref torrent) = self.torrent {
                if let Some(ref announce_url) = torrent.announce {
                    ui.label(format!("Announce URL: {}", announce_url));
                } else {
                    ui.label("Announce URL: (None found)");
                }

                ui.label(format!("Name: {}", torrent.info.name));
                if let Some(length) = torrent.info.length {
                    ui.label(format!("Length: {} bytes", length));
                }
                ui.label(format!("Piece Length: {} bytes", torrent.info.piece_length));
                ui.separator();
                ui.heading("Connected Peers:");
                if self.peers.is_empty() {
                    ui.label("No peers found.");
                } else {
                    for peer in &self.peers {
                        ui.label(format!("{}:{}", peer.ip, peer.port));
                    }
                }
            }
        });
    }
}

// Bencode data gets printed recursively for debugging purposes, might comment out since it's slowing
// The terminal (i think)
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

// Compute the SHA-1 hash of the serialized 'info' dictionary for tracker and peer identification
pub fn compute_info_hash(info: &Info) -> [u8; 20] {
    let encoded_info = serde_bencode::to_bytes(info).expect("Failed to encode info dict");
    let mut hasher = Sha1::new();
    hasher.update(encoded_info);
    let result = hasher.finalize();
    result.into()
}

// Only loads the torrent file and parses it into a Torrent struct, doesn't contact tracker yet
pub fn parse_torrent_file(path: &str) -> Result<Torrent, Box<dyn std::error::Error>> {
    // Trim quotes around path just incase, this is unnecessary tbh
    let path = path.trim_matches('"');
    println!("Trying to load file: {}", path);

    // Like any other good program, check if the object (file) is there, if not, yell at the user
    if !std::path::Path::new(path).exists() {
        eprintln!("Error: File '{}' does not exist!", path);
        return Err("File not found".into());
    }

    // Reads raw bytes and prints hex data
    let data = fs::read(path)?;
    println!("Raw data (hex): {:?}", hex::encode(&data));

    // Try to decode bencode
    // https://en.wikipedia.org/wiki/Bencode it's pronounced BEE-encode btw
    match serde_bencode::from_bytes::<Value>(&data) {
        Ok(decoded) => println!("Decoded Bencode: {:?}", decoded),
        Err(e) => eprintln!("Failed to decode raw bencode: {}", e),
    }

    // Deserialize decoded data into a Torrent struct
    let mut torrent: Torrent = from_bytes(&data)?;

    // If announce field is missing, try to fallback to first tracker in announce-list
    if torrent.announce.is_none() {
        if let Some(lists) = &torrent.announce_list {
            if let Some(first_list) = lists.first() {
                if let Some(first_tracker) = first_list.first() {
                    torrent.announce = Some(first_tracker.clone());
                    println!(
                        "Using tracker from announce-list: {}",
                        torrent.announce.as_ref().unwrap()
                    );
                }
            }
        }
    }

    // Final safety: still error if no tracker found
    if torrent.announce.is_none() {
        return Err("No announce URL found in torrent file.".into());
    }

    if let Ok(decoded) = serde_bencode::from_bytes::<Value>(&data) {
        println!("Decoded Bencode Tree:");
        print_bencode_tree(&decoded, 0);
    }

    // Return the loaded torrent, tracker contact is now separate
    Ok(torrent)
}
