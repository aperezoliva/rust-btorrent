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
    status_message: String,
}

// Default initialization for the app (empty torrent, default file path, no peers)
impl Default for TorrentApp {
    fn default() -> Self {
        Self {
            torrent: None,
            file_path: "example.torrent".to_string(),
            peers: Vec::new(),
            status_message: String::new(),
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
                        self.peers.clear();
                        self.status_message = "Torrent loaded successfully.".to_string();
                    }
                    Err(e) => {
                        eprintln!("Failed to parse: {}", e);
                        self.status_message = format!("Failed to load torrent: {}", e);
                        self.torrent = None;
                        self.peers.clear();
                    }
                }
            }

            // buttont to find peers, worked with .unwrap but appearently that's not really recommended in rust
            if ui.button("Find Peers").clicked() {
                if let Some(ref torrent) = self.torrent {
                    let info_hash = compute_info_hash(&torrent.info);
                    let mut handles = Vec::new();
                    let peer_id = crate::peer::generate_peer_id(); // Single peer_id for all connections
                                                                   // Try primary announce URL first
                    if let Some(ref announce_url) = torrent.announce {
                        let info_hash = info_hash.clone();
                        let announce_url = announce_url.clone();
                        let peer_id = peer_id.clone();
                        handles.push(std::thread::spawn(move || {
                            if announce_url.starts_with("http") {
                                crate::tracker::contact_tracker(
                                    &announce_url,
                                    &info_hash,
                                    0, // Dummy filesize for now
                                )
                                .ok()
                            } else if announce_url.starts_with("udp") {
                                crate::tracker::contact_udp_tracker(
                                    &announce_url,
                                    &info_hash,
                                    &peer_id,
                                )
                                .ok()
                                .map(|peers| {
                                    peers
                                        .into_iter()
                                        .map(|(ip, port)| crate::tracker::PeerInfo { ip, port })
                                        .collect()
                                })
                            } else {
                                None
                            }
                        }));
                    }
                    // Try all trackers in announce-list
                    if let Some(ref announce_list) = torrent.announce_list {
                        for tracker_list in announce_list {
                            for tracker_url in tracker_list {
                                let tracker_url = tracker_url.clone();
                                let info_hash = info_hash.clone();
                                let peer_id = peer_id.clone();

                                handles.push(std::thread::spawn(move || {
                                    if tracker_url.starts_with("http") {
                                        crate::tracker::contact_tracker(
                                            &tracker_url,
                                            &info_hash,
                                            0, // Dummy filesize
                                        )
                                        .ok()
                                    } else if tracker_url.starts_with("udp") {
                                        crate::tracker::contact_udp_tracker(
                                            &tracker_url,
                                            &info_hash,
                                            &peer_id,
                                        )
                                        .ok()
                                        .map(|peers| {
                                            peers
                                                .into_iter()
                                                .map(|(ip, port)| crate::tracker::PeerInfo {
                                                    ip,
                                                    port,
                                                })
                                                .collect()
                                        })
                                    } else {
                                        None
                                    }
                                }));
                            }
                        }
                    }
                    // Collect results
                    let mut all_peers = Vec::new();
                    for handle in handles {
                        if let Ok(Some(peers)) = handle.join() {
                            all_peers.extend(peers);
                        }
                    }
                    self.peers = all_peers;

                    // Update status
                    if self.peers.is_empty() {
                        self.status_message = "No peers found.".to_string();
                    } else {
                        self.status_message = format!("Found {} peers.", self.peers.len());
                    }
                } else {
                    eprintln!("No torrent loaded!");
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
                                            self.status_message =
                                                "Piece 0 downloaded successfully.".to_string();
                                            println!("Successfully downloaded and saved piece 0!");
                                        } else {
                                            self.status_message =
                                                "Failed to download piece 0.".to_string();
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
                    ui.label(format!("Tracker URL: {}", announce_url));
                } else {
                    ui.label("Tracker URL: (None found)");
                }

                ui.label(format!("Name: {}", torrent.info.name));
                if let Some(length) = torrent.info.length {
                    ui.label(format!("Length: {} bytes", length));
                }
                ui.label(format!("Piece Length: {} bytes", torrent.info.piece_length));
                ui.separator();
            }
            ui.separator();
            ui.label(format!("Status: {}", self.status_message));
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

    // If announce field is missing, fallback to first HTTP tracker in announce-list
    if torrent.announce.is_none() {
        if let Some(lists) = &torrent.announce_list {
            for tracker_list in lists {
                for tracker in tracker_list {
                    if tracker.starts_with("http") {
                        torrent.announce = Some(tracker.clone());
                        println!("Using HTTP tracker from announce-list: {}", tracker);
                        break;
                    }
                }
                if torrent.announce.is_some() {
                    break;
                }
            }
        }
    }

    // Final safety check
    if torrent.announce.is_none() {
        return Err("No HTTP announce URL found in torrent file.".into());
    }

    if let Ok(decoded) = serde_bencode::from_bytes::<Value>(&data) {
        println!("Decoded Bencode Tree:");
        print_bencode_tree(&decoded, 0);
    }

    // Return parsed torrent
    Ok(torrent)
}
