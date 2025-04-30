use crate::tracker::PeerInfo;
use serde::{Deserialize, Serialize};
use serde_bencode::{from_bytes, value::Value};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};

// Struct representing the 'info' dictionary usually supplied by a torrent file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Info {
    pub name: String,
    pub length: Option<u64>, // single file
    #[serde(default)]
    pub files: Option<Vec<FileEntry>>, // multi-file
    #[serde(rename = "piece length")]
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
    download_dir: Option<String>,
    peers: Vec<PeerInfo>,
    status_message: String,
}

// Default initialization for the app (empty torrent, default file path, no peers)
impl Default for TorrentApp {
    fn default() -> Self {
        Self {
            loaded_torrent: None,
            file_path: "example.torrent".to_string(),
            download_dir: None, // ← Initialize here
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
            if ui.button("Select Download Folder").clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    self.download_dir = Some(folder.display().to_string());
                    println!(
                        "Selected download folder: {}",
                        self.download_dir.as_ref().unwrap()
                    );
                }
            }
            if ui.button("Browse .torrent file").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Torrent", &["torrent"])
                    .pick_file()
                {
                    self.file_path = path.display().to_string();
                }
            }

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

            if ui
                .button("Download Pieces with aria2c (fallback)")
                .clicked()
            {
                if let Some(ref _loaded_torrent) = self.loaded_torrent {
                    let output_dir = self
                        .download_dir
                        .clone()
                        .unwrap_or_else(|| "downloads".to_string());

                    match crate::peer::launch_aria2c_with_torrent_in_dir(
                        &self.file_path,
                        &output_dir,
                    ) {
                        Ok(_) => {
                            self.status_message = "aria2c started successfully.".to_string();
                        }
                        Err(e) => {
                            self.status_message = format!("aria2c failed: {}", e);
                        }
                    }
                }
            }

            if ui
                .button("Download Pieces with personal protocol (not properly functioning)")
                .clicked()
            {
                if let Some(ref loaded_torrent) = self.loaded_torrent {
                    let torrent = &loaded_torrent.torrent;
                    let info_bytes = &loaded_torrent.info_bytes;
                    let dir = self
                        .download_dir
                        .clone()
                        .unwrap_or_else(|| "downloads".to_string());
                    match download_pieces(&self.peers, torrent, info_bytes, None, &dir) {
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
        });
    }
}
// Bencode data gets printed recursively for debugging purposes, might comment out since it's slowing
// The terminal (i think)
// fn print_bencode_tree(value: &Value, indent: usize) {
//     let pad = " ".repeat(indent);
//     match value {
//         Value::Int(i) => println!("{}Int: {}", pad, i),
//         Value::Bytes(bytes) => {
//             if let Ok(s) = std::str::from_utf8(bytes) {
//                 println!("{}Bytes: {:?}", pad, s);
//             } else {
//                 println!("{}Bytes: ({} bytes)", pad, bytes.len());
//             }
//         }
//         Value::List(list) => {
//             println!("{}List [", pad);
//             for item in list {
//                 print_bencode_tree(item, indent + 2);
//             }
//             println!("{}]", pad);
//         }
//         Value::Dict(dict) => {
//             println!("{}Dict {{", pad);
//             for (key, val) in dict {
//                 let key_display = match std::str::from_utf8(key) {
//                     Ok(s) => format!("{:?}", s),
//                     Err(_) => format!("(binary key: {} bytes)", key.len()),
//                 };
//                 println!("{}  Key: {}", pad, key_display);
//                 print_bencode_tree(val, indent + 4);
//             }
//             println!("{}}}", pad);
//         }
//     }
// }

// Compute the SHA-1 hash of the serialized 'info' dictionary
pub fn compute_info_hash(info_bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(info_bytes);
    let result = hasher.finalize();
    result.into()
}

// Only loads the torrent file and parses it into a Torrent struct, doesn't contact tracker yet
pub fn parse_torrent_file(path: &str) -> Result<LoadedTorrent, Box<dyn std::error::Error>> {
    let path = path.trim_matches('"');
    println!("Trying to load file: {}", path);

    if !std::path::Path::new(path).exists() {
        return Err("File not found".into());
    }

    let data = std::fs::read(path)?;
    let root: Value = serde_bencode::from_bytes(&data)?;
    let info_value = match &root {
        Value::Dict(dict) => dict.get(&b"info"[..]).ok_or("Missing 'info' field")?,
        _ => return Err("Torrent file is not a bencoded dictionary".into()),
    };

    // DEBUG: print raw info dictionary before decoding
    println!("Raw 'info' bencode: {:?}", info_value);

    // Re-serialize just the 'info' dictionary
    let info_bytes = serde_bencode::to_bytes(info_value)?;

    // Deserialize 'info' into Info struct
    let info: Info = from_bytes(&info_bytes)?;
    println!(
        "Decoded Info struct:\n  piece_length: {}\n  name: {}\n  pieces.len(): {}",
        info.piece_length,
        info.name,
        info.pieces.len()
    );

    // Manually extract announce and announce-list
    let (announce, announce_list) = match &root {
        Value::Dict(dict) => {
            let announce = dict.get(&b"announce"[..]).and_then(|v| match v {
                Value::Bytes(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
                _ => None,
            });

            let announce_list = dict.get(&b"announce-list"[..]).and_then(|v| match v {
                Value::List(list_of_lists) => {
                    let mut outer = Vec::new();
                    for inner in list_of_lists {
                        if let Value::List(inner_list) = inner {
                            let urls = inner_list
                                .iter()
                                .filter_map(|v| {
                                    if let Value::Bytes(b) = v {
                                        Some(String::from_utf8_lossy(b).to_string())
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>();
                            outer.push(urls);
                        }
                    }
                    Some(outer)
                }
                _ => None,
            });

            (announce, announce_list)
        }
        _ => (None, None),
    };

    let torrent = Torrent {
        announce,
        announce_list,
        info,
    };

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
    download_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use rand::seq::SliceRandom;
    let mut rng = rand::rng();
    let mut shuffled_peers = peers.to_vec();
    shuffled_peers.shuffle(&mut rng);

    let info_hash = compute_info_hash(info_bytes);
    let peer_id = crate::peer::generate_peer_id();

    if torrent.info.piece_length == 0 {
        return Err("Loaded .torrent file has invalid piece_length = 0".into());
    }

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
                    download_dir,
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

    eprintln!("All peer attempts failed. Falling back to aria2c...");
    let path = crate::peer::write_metadata_to_file(info_bytes)?;
    let output_dir = "downloads";
    crate::peer::launch_aria2c_with_torrent_in_dir(&path, output_dir)?;
    let _ = std::fs::remove_file(&path);
    Ok(())
}
