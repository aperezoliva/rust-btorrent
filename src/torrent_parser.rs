use crate::peer::read_bitfield;
use crate::tracker::PeerInfo;
use egui::ProgressBar;
use serde::{Deserialize, Serialize};
use serde_bencode::{from_bytes, value::Value};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};
use std::fs::OpenOptions;

// Struct representing the 'info' dictionary usually supplied by a torrent file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Info {
    pub name: String,
    pub length: Option<u64>, // single file
    #[serde(default)]
    pub files: Option<Vec<FileEntry>>, // multi-file
    #[serde(default)]
    pub piece_length: u64,
    pub pieces: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub length: u64,
    pub path: Vec<String>,
}

// Main structure of a torrent file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Torrent {
    #[serde(default)]
    pub announce: Option<String>, // Now optional, because modern torrents might not have it WTF
    #[serde(rename = "announce-list", default)]
    pub announce_list: Option<Vec<Vec<String>>>, // Nested list of tracker URLs
    pub info: Info,
}

// Struct returned when parsing a .torrent file
pub struct LoadedTorrent {
    pub torrent: Torrent,
    pub info_bytes: Vec<u8>,
}

// Gui state for the app
pub struct TorrentApp {
    loaded_torrent: Option<LoadedTorrent>,
    file_path: String,
    peers: Vec<PeerInfo>,
    status_message: String,
    progress: f32,
}

// Default initialization for the app (empty torrent, default file path, no peers)
impl Default for TorrentApp {
    fn default() -> Self {
        Self {
            loaded_torrent: None,
            file_path: "example.torrent".to_string(),
            peers: Vec::new(),
            status_message: String::new(),
            progress: 0.0,
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
                    Ok(loaded_torrent) => {
                        self.loaded_torrent = Some(loaded_torrent);
                        self.peers.clear();
                        self.status_message = "Torrent loaded successfully.".to_string();
                    }
                    Err(e) => {
                        eprintln!("Failed to parse: {}", e);
                        self.status_message = format!("Failed to load torrent: {}", e);
                        self.loaded_torrent = None;
                        self.peers.clear();
                    }
                }
            }

            if ui.button("Find Peers").clicked() {
                if let Some(ref loaded_torrent) = self.loaded_torrent {
                    let torrent = &loaded_torrent.torrent;
                    let info_hash = compute_info_hash(&loaded_torrent.info_bytes);
                    let mut handles = Vec::new();
                    let peer_id = crate::peer::generate_peer_id();

                    if let Some(ref announce_url) = torrent.announce {
                        let info_hash = info_hash.clone();
                        let announce_url = announce_url.clone();
                        let peer_id = peer_id.clone();
                        handles.push(std::thread::spawn(move || {
                            if announce_url.starts_with("http") {
                                crate::tracker::contact_tracker(&announce_url, &info_hash, 0).ok()
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

                    if let Some(ref announce_list) = torrent.announce_list {
                        for tracker_list in announce_list {
                            for tracker_url in tracker_list {
                                let tracker_url = tracker_url.clone();
                                let info_hash = info_hash.clone();
                                let peer_id = peer_id.clone();
                                handles.push(std::thread::spawn(move || {
                                    if tracker_url.starts_with("http") {
                                        crate::tracker::contact_tracker(&tracker_url, &info_hash, 0)
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

                    let mut all_peers = Vec::new();
                    for handle in handles {
                        if let Ok(Some(peers)) = handle.join() {
                            all_peers.extend(peers);
                        }
                    }
                    self.peers = all_peers;
                    self.status_message = if self.peers.is_empty() {
                        "No peers found.".to_string()
                    } else {
                        format!("Found {} peers.", self.peers.len())
                    };
                } else {
                    eprintln!("No torrent loaded!");
                }
            }

            if ui.button("Download Piece 0").clicked() {
                if let Some(ref loaded_torrent) = self.loaded_torrent {
                    let torrent = &loaded_torrent.torrent;
                    let info_bytes = &loaded_torrent.info_bytes;
                    match download_pieces(&self.peers, torrent, info_bytes, Some(0)) {
                        Ok(_) => {
                            self.status_message = "Piece 0 downloaded successfully.".to_string()
                        }
                        Err(e) => {
                            self.status_message = format!("Failed to download piece 0: {}", e)
                        }
                    }
                }
            }

            if ui.button("Download All Pieces").clicked() {
                if let Some(ref loaded_torrent) = self.loaded_torrent {
                    let torrent = &loaded_torrent.torrent;
                    let info_bytes = &loaded_torrent.info_bytes;
                    match download_pieces(&self.peers, torrent, info_bytes, None) {
                        Ok(_) => {
                            self.status_message = "All pieces downloaded successfully.".to_string()
                        }
                        Err(e) => {
                            self.status_message = format!("Failed to download all pieces: {}", e)
                        }
                    }
                }
            }

            if let Some(ref loaded_torrent) = self.loaded_torrent {
                let torrent = &loaded_torrent.torrent;
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
            ui.label("Download Progress:");
            ui.add(ProgressBar::new(self.progress).show_percentage());
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

// Compute the SHA-1 hash of the serialized 'info' dictionary
pub fn compute_info_hash(info_bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(info_bytes);
    let result = hasher.finalize();
    result.into()
}

// Only loads the torrent file and parses it into a Torrent struct, doesn't contact tracker yet
pub fn parse_torrent_file(path: &str) -> Result<LoadedTorrent, Box<dyn std::error::Error>> {
    // Trim quotes around path just in case, this is unnecessary tbh
    let path = path.trim_matches('"');
    println!("Trying to load file: {}", path);

    // Like any other good program, check if the object (file) is there, if not, yell at the user
    if !std::path::Path::new(path).exists() {
        eprintln!("Error: File '{}' does not exist!", path);
        return Err("File not found".into());
    }

    // Reads raw bytes and prints hex data
    let data = std::fs::read(path)?;
    println!("Raw data (hex): {:?}", hex::encode(&data));

    // Try to decode raw bencode
    // https://en.wikipedia.org/wiki/Bencode (it's pronounced BEE-encode btw)
    let decoded = serde_bencode::from_bytes::<Value>(&data)?;

    // Dig inside top-level dictionary to find the 'info' dictionary
    let info_value = match &decoded {
        Value::Dict(dict) => dict.get(&b"info"[..]).ok_or("Missing 'info' field")?,
        _ => return Err("Torrent file is not a bencoded dictionary".into()),
    };

    // Re-serialize just the 'info' dictionary back into bencode
    // Important: because tracker and peers expect EXACT same info_hash
    let info_bytes = serde_bencode::to_bytes(info_value)?;

    // Deserialize full .torrent file into Torrent struct
    let torrent: Torrent = from_bytes(&data)?;

    let mut torrent = torrent;

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

    // Print a pretty debug tree of the decoded bencode structure
    if let Ok(decoded) = serde_bencode::from_bytes::<Value>(&data) {
        println!("Decoded Bencode Tree:");
        print_bencode_tree(&decoded, 0);
    }

    // Return both the parsed Torrent and the raw info dict bytes
    Ok(LoadedTorrent {
        torrent,
        info_bytes,
    })
}

pub fn download_pieces(
    peers: &[PeerInfo],
    torrent: &Torrent,
    info_bytes: &[u8],
    piece_index: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    use rand::seq::SliceRandom;

    let mut rng = rand::thread_rng();
    let mut shuffled_peers = peers.to_vec();
    shuffled_peers.shuffle(&mut rng);

    let info_hash = compute_info_hash(info_bytes);
    let peer_id = crate::peer::generate_peer_id();

    for peer in &shuffled_peers {
        println!("Trying to connect to {}:{}", peer.ip, peer.port);

        match std::net::TcpStream::connect((peer.ip.as_str(), peer.port)) {
            Ok(mut stream) => {
                println!("Connected to peer {}:{}", peer.ip, peer.port);

                match crate::peer::peer_loop(
                    &mut stream,
                    &peer_id,
                    &info_hash,
                    torrent,
                    info_bytes,
                    piece_index,
                ) {
                    Ok(_) => {
                        println!("Download completed successfully from peer.");
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!(
                            "Peer loop failed with peer {}:{} — {}",
                            peer.ip, peer.port, e
                        );
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "Failed to connect to peer {}:{} — {}",
                    peer.ip, peer.port, e
                );
            }
        }
    }

    Err("Failed to download from any peer.".into())
}
