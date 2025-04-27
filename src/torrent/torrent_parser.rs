use tokio::fs;
use crate::Info;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tracker::{contact_tracker};



#[derive(Debug, Serialize, Deserialize)]
pub struct Torrent {
    announce: String,
    info: Info,
}

pub fn compute_info_hash(info: &Info) -> [u8; 20] {
    let encoded_info = serde_bencode::to_bytes(info).expect("Failed to encode info dict");
    let mut hasher = Sha1::new();
    hasher.update(encoded_info);
    let result = hasher.finalize();
    result.into()
}

pub fn parse_torrent_file(path: &str) -> Result<Torrent, Box<dyn std::error::Error>> {
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