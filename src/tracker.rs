use rand::Rng;
use serde_bencode::{from_bytes, value::Value};
use std::net::UdpSocket;
use std::thread::sleep;
use std::time::Duration;
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
        return Ok(Vec::new());
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

/// Connects to a UDP tracker and gets a list of peers.
/// `tracker_addr` should be something like "tracker.opentrackr.org:1337"
pub fn contact_udp_tracker(
    tracker_addr: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
) -> std::io::Result<Vec<(String, u16)>> {
    let mut attempts = 0;

    loop {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;

        let mut rng = rand::rng();
        let transaction_id: u32 = rng.random();

        // Build connect request
        let mut connect_req = Vec::with_capacity(16);
        connect_req.extend_from_slice(&0x41727101980u64.to_be_bytes()); // Protocol ID
        connect_req.extend_from_slice(&0u32.to_be_bytes()); // Connect action
        connect_req.extend_from_slice(&transaction_id.to_be_bytes()); // Transaction ID

        if socket.send_to(&connect_req, tracker_addr).is_err() {
            if attempts >= 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Failed to send connect request after retries",
                ));
            } else {
                attempts += 1;
                sleep(Duration::from_secs(1));
                continue;
            }
        }

        let mut buf = [0u8; 2048];
        let recv = socket.recv_from(&mut buf);
        if recv.is_err() {
            if attempts >= 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "No response from tracker after retries",
                ));
            } else {
                attempts += 1;
                sleep(Duration::from_secs(1));
                continue;
            }
        }
        let (size, _) = recv?;

        if size < 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid connect response",
            ));
        }
        let action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let recv_transaction_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if action != 0 || recv_transaction_id != transaction_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Connect failed",
            ));
        }
        let connection_id = &buf[8..16];

        // Announce
        let transaction_id: u32 = rng.random();
        let mut announce_req = Vec::with_capacity(98);
        announce_req.extend_from_slice(connection_id);
        announce_req.extend_from_slice(&1u32.to_be_bytes()); // Announce action
        announce_req.extend_from_slice(&transaction_id.to_be_bytes());
        announce_req.extend_from_slice(info_hash);
        announce_req.extend_from_slice(peer_id);
        announce_req.extend_from_slice(&0u64.to_be_bytes()); // downloaded
        announce_req.extend_from_slice(&0u64.to_be_bytes()); // left
        announce_req.extend_from_slice(&0u64.to_be_bytes()); // uploaded
        announce_req.extend_from_slice(&0u32.to_be_bytes()); // event
        announce_req.extend_from_slice(&0u32.to_be_bytes()); // IP address
        announce_req.extend_from_slice(&0u32.to_be_bytes()); // key
        announce_req.extend_from_slice(&(-1i32).to_be_bytes()); // num_want
        announce_req.extend_from_slice(&6881u16.to_be_bytes()); // port

        if socket.send_to(&announce_req, tracker_addr).is_err() {
            if attempts >= 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Failed to send announce request after retries",
                ));
            } else {
                attempts += 1;
                sleep(Duration::from_secs(1));
                continue;
            }
        }

        let recv = socket.recv_from(&mut buf);
        if recv.is_err() {
            if attempts >= 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "No announce response after retries",
                ));
            } else {
                attempts += 1;
                sleep(Duration::from_secs(1));
                continue;
            }
        }
        let (size, _) = recv?;

        if size < 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid announce response",
            ));
        }
        let action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let recv_transaction_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if action != 1 || recv_transaction_id != transaction_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Announce failed",
            ));
        }

        // Parse peers
        let peers_bytes = &buf[20..size];
        let mut peers = Vec::new();
        for chunk in peers_bytes.chunks(6) {
            if chunk.len() < 6 {
                continue;
            }
            let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
            let port = u16::from_be_bytes([chunk[4], chunk[5]]);
            peers.push((ip, port));
        }

        return Ok(peers);
    }
}
