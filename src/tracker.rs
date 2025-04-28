use serde_bencode::{from_bytes, value::Value};

// Basic peer info
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub ip: String,
    pub port: u16,
}

// Takes raw bytes and encodes them
// Need this for trackers
fn percent_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("%{:02X}", b)).collect()
}

/* Not sure why im not using comment blocks more often
regardless, this is for contacting trackers
info_hash -> identifies torrents
peer_id -> identifies client (hardcoded) */
pub fn contact_tracker(
    announce_url: &str,
    info_hash: &[u8; 20],
    file_size: u64,
) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error>> {
    let peer_id = "-RT0001-123456789012";
    let info_hash_encoded = percent_encode(info_hash);
    let peer_id_encoded = percent_encode(peer_id.as_bytes());
    let mut peers_list = Vec::new();
    if !announce_url.starts_with("http") {
        // Skipping non-HTTP trackers for now, will implement HTTPS and UDP ones later (when i feel like it)
        println!("Skipping non-HTTP tracker: {}", announce_url);
        return Ok((Vec::new()));
    }

    // Constructs the full announce url
    let url = format!(
        "{}?info_hash={}&peer_id={}&port=36363&uploaded=0&downloaded=0&left={}&compact=1",
        announce_url, info_hash_encoded, peer_id_encoded, file_size
    );

    let response = reqwest::blocking::get(&url)?.bytes()?;
    println!("Raw tracker response (hex): {:?}", hex::encode(&response));

    // Parse tracker response as bencoded dictionary
    let tracker_response: Value = from_bytes(&response)?;

    // Extracts peers from response
    if let Value::Dict(dict) = tracker_response {
        if let Some(peers_value) = dict.get(&b"peers"[..]) {
            if let Value::Bytes(peers) = peers_value {
                for chunk in peers.chunks(6) {
                    if chunk.len() < 6 {
                        continue;
                    }
                    let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                    println!("Peer: {}:{}", ip, port);
                    peers_list.push(PeerInfo { ip, port });
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

    // Returns list of peers
    Ok(peers_list)
}
