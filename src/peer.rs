// for generating random peer ids and handshake operations
use crate::torrent_parser::Torrent;
use rand::{distr::Alphanumeric, rngs::ThreadRng, Rng};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

/// Safely reads a message from a peer, returning (id, payload)
fn read_message(stream: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let mut length_buf = [0u8; 4];
    stream.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf);

    if length == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "keep-alive"));
    }

    if length > 1_048_576 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unrealistic message size: {}", length),
        ));
    }

    let mut payload = vec![0u8; length as usize];
    let mut total_read = 0;
    while total_read < payload.len() {
        match stream.read(&mut payload[total_read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Peer closed during message",
                ))
            }
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }

    let id = payload[0];
    Ok((id, payload[1..].to_vec()))
}

pub fn write_metadata_to_file(metadata: &[u8]) -> std::io::Result<String> {
    let path = "temp_metadata.torrent";
    let mut file = File::create(path)?;
    file.write_all(metadata)?;
    Ok(path.to_string())
}

pub fn launch_aria2c_with_torrent_in_dir(
    torrent_path: &str,
    download_dir: &str,
) -> std::io::Result<()> {
    let status = Command::new("aria2c")
        .arg(format!("--dir={}", download_dir))
        .arg("--seed-time=0")
        .arg(torrent_path)
        .status()?;

    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "aria2c exited with failure",
        ));
    }

    Ok(())
}

// Generates peer id
pub fn generate_peer_id() -> [u8; 20] {
    let prefix = b"-TR3000-"; // refers to the client
    let mut peer_id = [0u8; 20]; // Fill first 8 bytes with prefix

    peer_id[..8].copy_from_slice(prefix);

    // Fill remaining 12 bytes with random alphanumeric characters
    for byte in &mut peer_id[8..] {
        *byte = ThreadRng::default().sample(Alphanumeric) as u8;
    }

    peer_id
}

// pub fn download_metadata_multi_peer(
//     peers: &[PeerInfo],
//     info_hash: &[u8; 20],
//     peer_id: &[u8; 20],
// ) -> io::Result<()> {
//     for peer in peers {
//         println!(
//             "Attempting metadata download from {}:{}",
//             peer.ip, peer.port
//         );

//         match TcpStream::connect((peer.ip.as_str(), peer.port)) {
//             Ok(mut stream) => {
//                 if perform_handshake(&mut stream, info_hash, peer_id).is_err() {
//                     continue;
//                 }
//                 if send_interested(&mut stream).is_err() {
//                     continue;
//                 }
//                 if wait_until_unchoked(&mut stream).is_err() {
//                     continue;
//                 }

//                 let _ = stream.write_all(&[0, 0, 0, 5, 4, 0, 0, 0, 0]);
//                 let _ = stream.write_all(&[0, 0, 0, 2, 5, 0]);

//                 match send_extended_handshake(&mut stream) {
//                     Ok((ut_metadata_id, metadata_size)) => {
//                         match download_metadata(&mut stream, ut_metadata_id, metadata_size) {
//                             Ok(metadata) => {
//                                 let path = write_metadata_to_file(&metadata)?;
//                                 launch_aria2c_with_torrent(&path)?;
//                                 let _ = std::fs::remove_file(&path);
//                                 return Ok(());
//                             }
//                             Err(e) => {
//                                 eprintln!("Metadata fetch failed: {}", e);
//                                 continue;
//                             }
//                         }
//                     }
//                     Err(e) => {
//                         eprintln!("Extended handshake failed: {}", e);
//                         continue;
//                     }
//                 }
//             }
//             Err(e) => {
//                 eprintln!("Connection failed: {}", e);
//                 continue;
//             }
//         }
//     }

//     Err(io::Error::new(
//         io::ErrorKind::Other,
//         "Failed to download metadata from all peers",
//     ))
// }

pub fn peer_loop(
    stream: &mut TcpStream,
    peer_id: &[u8; 20],
    info_hash: &[u8; 20],
    torrent: &Torrent,
    info_bytes: &[u8],
    piece_index: Option<u32>,
    download_dir: &str,
) -> io::Result<()> {
    perform_handshake(stream, info_hash, peer_id)?;
    send_interested(stream)?;
    wait_until_unchoked(stream)?;

    let _ = stream.write_all(&[0, 0, 0, 5, 4, 0, 0, 0, 0]); // fake 'have'
    let _ = stream.write_all(&[0, 0, 0, 2, 5, 0]); // fake bitfield

    let (_torrent, total_len, piece_len, _) = (
        torrent.clone(),
        torrent.info.length.unwrap_or(0),
        torrent.info.piece_length,
        info_bytes.to_vec(),
    );

    if piece_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid piece length",
        ));
    }

    let piece_len = piece_len as u32;
    let num_pieces = ((total_len + piece_len as u64 - 1) / piece_len as u64) as usize;

    let mut output = OpenOptions::new()
        .create(true)
        .write(true)
        .open("final_output.bin")?;

    let pieces_to_get: Vec<u32> = match piece_index {
        Some(idx) => vec![idx],
        _none => (0..num_pieces as u32).collect(),
    };

    for i in pieces_to_get {
        let expected_len = if (i as usize) == num_pieces - 1 {
            let r = (total_len % piece_len as u64) as u32;
            if r == 0 {
                piece_len
            } else {
                r
            }
        } else {
            piece_len
        };

        match download_piece(stream, i, expected_len) {
            Ok(data) => {
                output.seek(SeekFrom::Start(i as u64 * piece_len as u64))?;
                output.write_all(&data)?;
                println!("Wrote piece {} to output", i);
            }
            Err(e) => {
                eprintln!("Retrying piece {} failed: {}", i, e);
                return Err(e); // Abort and try next peer
            }
        }
    }

    Ok(())
}

// Performs bittorrent handshake over open TCP stream
// Wikipedia article on handshakes: https://en.wikipedia.org/wiki/Handshake_(computing)
// Documentation on TcpStream https://doc.rust-lang.org/std/net/struct.TcpStream.html
// Chatgpt did the bulk of this one.. I admit.. :(
pub fn perform_handshake(
    stream: &mut TcpStream,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
) -> io::Result<()> {
    // Build the handshake message
    let mut handshake = Vec::with_capacity(68);

    // pstrlen (1 byte)
    // Single byte that says "The following byte will be 19 bytes long"
    // Tells the peer that they will receive a 19 byte string
    handshake.push(19);

    // pstr (19 bytes)
    // It's the official protocol identifier, required for being accepted by a peer
    handshake.extend_from_slice(b"BitTorrent protocol");

    // reserved (8 bytes) - all zeroes for now
    // reserved for future protocol extensions
    // Sets extension protocol bit (extension handshake support)
    handshake.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00]);

    // info_hash (20 bytes) <sha-1 hash is always 160 bits>
    // contains torrent's info dictionary
    handshake.extend_from_slice(info_hash);

    // peer_id (20 bytes)
    // our unique peer id
    handshake.extend_from_slice(peer_id);

    // Send the handshake
    stream.write_all(&handshake)?;

    // Read handshake response (68 bytes)
    let mut response = [0u8; 68];
    let mut total_read = 0;
    while total_read < 68 {
        match stream.read(&mut response[total_read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Peer closed connection during handshake (read {} bytes)",
                        total_read
                    ),
                ));
            }
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    // Validate response
    if response[0] != 19 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid pstrlen in handshake",
        ));
    }
    if &response[1..20] != b"BitTorrent protocol" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid protocol string in handshake",
        ));
    }
    if &response[28..48] != info_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Info hash mismatch",
        ));
    }
    println!("Handshake response (raw): {:?}", &response);
    println!("Handshake successful with peer!");

    Ok(())
}

// Sends an 'interested' message to the peer
pub fn send_interested(stream: &mut TcpStream) -> io::Result<()> {
    let msg = [
        0u8, 0, 0, 1,   // Length prefix: 1
        2u8, // Message ID: 2 (Interested)
    ];
    stream.write_all(&msg)?;
    println!("Sent Interested message.");
    Ok(())
}

// Unchoke refers to peers allowing the client to download pieces
/* Implemented some new changes per https://stackoverflow.com/questions/53531493/peers-not-sending-back-unchoke-message */

pub fn wait_until_unchoked(stream: &mut TcpStream) -> io::Result<()> {
    use std::time::{Duration, Instant};
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let start = Instant::now();

    loop {
        if start.elapsed().as_secs() > 60 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Timed out waiting for unchoke",
            ));
        }

        match read_message(stream) {
            Ok((1, _)) => {
                println!("Received unchoke.");
                return Ok(());
            }
            Ok((0, _)) => println!("Keep-alive"),
            Ok((4, payload)) => {
                if payload.len() >= 4 {
                    let index =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    println!("Peer has piece {}", index);
                }
            }
            Ok((5, payload)) => {
                println!("Received bitfield ({} bytes)", payload.len());
            }
            Ok((id, payload)) => {
                println!("Received message ID {} ({} bytes)", id, payload.len());
                // You can optionally skip or parse these
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                println!("Peer closed connection or sent keep-alive");
                return Err(e);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to read message: {}", e),
                ));
            }
        }
    }
}

pub fn send_request(
    stream: &mut TcpStream,
    piece_index: u32,
    block_offset: u32,
    block_length: u32,
) -> io::Result<()> {
    let mut request = Vec::with_capacity(17);

    // Length prefix (13 bytes follow)
    request.extend_from_slice(&13u32.to_be_bytes());

    // Message ID (6 = Request)
    request.push(6u8);

    // Piece index (which piece)
    request.extend_from_slice(&piece_index.to_be_bytes());

    // Block offset (inside piece)
    request.extend_from_slice(&block_offset.to_be_bytes());

    // Block length (how many bytes you want)
    request.extend_from_slice(&block_length.to_be_bytes());

    // Send request to peer
    stream.write_all(&request)?;
    println!(
        "Sent Request for piece {} offset {} length {}",
        piece_index, block_offset, block_length
    );

    Ok(())
}

// Receives a 'piece' message from the peer, returns the piece data as Vec<u8>
pub fn receive_piece(stream: &mut TcpStream) -> io::Result<(u32, u32, Vec<u8>)> {
    let mut length_buf = [0u8; 4];
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf);

    if length < 9 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Piece message too short: {} bytes", length),
        ));
    }

    let mut header_buf = [0u8; 9]; // 1 byte message_id + 4 index + 4 offset
    stream.read_exact(&mut header_buf)?;
    let message_id = header_buf[0];

    if message_id != 7 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected Piece (7), got message ID {}", message_id),
        ));
    }

    let piece_index = u32::from_be_bytes(header_buf[1..5].try_into().unwrap());
    let block_offset = u32::from_be_bytes(header_buf[5..9].try_into().unwrap());

    let block_len = length as usize - 9;
    let mut block_data = vec![0u8; block_len];
    let mut total_read = 0;

    while total_read < block_len {
        match stream.read(&mut block_data[total_read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Peer closed connection after reading {} of {} bytes",
                        total_read, block_len
                    ),
                ));
            }
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    println!(
        "Received piece index {}, offset {}, length {}",
        piece_index,
        block_offset,
        block_data.len()
    );

    Ok((piece_index, block_offset, block_data))
}

// Downloads a full piece by repeatedly requesting 16KB blocks
pub fn download_piece(
    stream: &mut TcpStream,
    piece_index: u32,
    piece_length: u32,
) -> io::Result<Vec<u8>> {
    const BLOCK_SIZE: u32 = 16384; // 16 KB

    let mut piece_data = Vec::with_capacity(piece_length as usize);
    let mut offset = 0;

    while offset < piece_length {
        let request_size = std::cmp::min(BLOCK_SIZE, piece_length - offset);

        // Send request for this block
        send_request(stream, piece_index, offset, request_size)?;

        // Receive the block
        let (_piece_idx, block_offset, block_data) = receive_piece(stream)?;

        // Validate the block (optional but good practice)
        if block_offset != offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected block offset",
            ));
        }

        // Append data to the full piece
        piece_data.extend_from_slice(&block_data);

        offset += request_size;
    }

    println!(
        "Finished downloading piece {} ({} bytes)",
        piece_index,
        piece_data.len()
    );

    Ok(piece_data)
}

// pub fn send_extended_handshake(stream: &mut TcpStream) -> io::Result<(u8, u64)> {
//     use serde_bencode::de;

//     let mut payload = b"d1:md11:ut_metadatai1ee".to_vec();
//     let mut message = Vec::new();
//     let total_length = payload.len() as u32 + 2;
//     message.extend_from_slice(&total_length.to_be_bytes());
//     message.push(20); // extended message
//     message.push(0); // extended handshake
//     message.extend_from_slice(&payload);
//     stream.write_all(&message)?;
//     println!("Sent Extended Handshake.");

//     let mut length_buf = [0u8; 4];
//     let mut msg_id_buf = [0u8; 1];
//     let mut ext_id_buf = [0u8; 1];

//     loop {
//         stream.read_exact(&mut length_buf)?;
//         let length = u32::from_be_bytes(length_buf);

//         if length < 2 {
//             let mut skip = vec![0u8; length as usize];
//             stream.read_exact(&mut skip)?;
//             println!("Skipping short or keep-alive message: length={}", length);
//             continue;
//         }

//         stream.read_exact(&mut msg_id_buf)?;
//         stream.read_exact(&mut ext_id_buf)?;
//         let msg_id = msg_id_buf[0];
//         let ext_id = ext_id_buf[0];

//         if msg_id != 20 || ext_id != 0 {
//             let mut skip = vec![0u8; length as usize - 2];
//             stream.read_exact(&mut skip)?;
//             println!(
//                 "Skipping unexpected extended message: msg_id={}, ext_id={}, len={}",
//                 msg_id, ext_id, length
//             );
//             continue;
//         }

//         // Now we expect a valid bencoded payload
//         let payload_len = length as usize - 2;
//         let mut payload_buf = vec![0u8; payload_len];
//         let mut read_total = 0;

//         while read_total < payload_len {
//             match stream.read(&mut payload_buf[read_total..]) {
//                 Ok(0) => {
//                     return Err(io::Error::new(
//                         io::ErrorKind::UnexpectedEof,
//                         "Connection closed during metadata payload",
//                     ));
//                 }
//                 Ok(n) => read_total += n,
//                 Err(e) => {
//                     return Err(io::Error::new(
//                         io::ErrorKind::Other,
//                         format!("Failed to read metadata payload: {}", e),
//                     ))
//                 }
//             }
//         }

//         println!("Received Extended Handshake payload: {:?}", payload_buf);

//         // Decode bencoded dictionary
//         let val: Value = de::from_bytes(&payload_buf).map_err(|e| {
//             io::Error::new(io::ErrorKind::InvalidData, format!("bencode error: {}", e))
//         })?;

//         if let Value::Dict(map) = val {
//             let mut ut_metadata = 0;
//             let mut metadata_size = 0;

//             if let Some(Value::Dict(m)) = map.get(&b"m"[..]) {
//                 if let Some(Value::Int(id)) = m.get(&b"ut_metadata"[..]) {
//                     ut_metadata = *id as u8;
//                 }
//             }
//             if let Some(Value::Int(size)) = map.get(&b"metadata_size"[..]) {
//                 metadata_size = *size as u64;
//             }

//             if ut_metadata == 0 || metadata_size == 0 {
//                 return Err(io::Error::new(
//                     io::ErrorKind::InvalidData,
//                     "ut_metadata or metadata_size missing from extended handshake",
//                 ));
//             }

//             println!(
//                 "Peer supports ut_metadata (id {}) with metadata_size {} bytes",
//                 ut_metadata, metadata_size
//             );

//             return Ok((ut_metadata, metadata_size));
//         } else {
//             return Err(io::Error::new(
//                 io::ErrorKind::InvalidData,
//                 "Extended handshake was not a dictionary",
//             ));
//         }
//     }
// }

// Request a specific metadata piece from a peer
// pub fn request_metadata_piece(
//     stream: &mut TcpStream,
//     ut_metadata_id: u8,
//     piece_index: u32,
// ) -> io::Result<Vec<u8>> {
//     use serde_bencode::value::Value;
//     use serde_bencode::{de, ser};
//     use std::collections::HashMap;

//     // 1. Build request dictionary
//     let mut dict = HashMap::new();
//     dict.insert(b"msg_type".to_vec(), Value::Int(0)); // 0 = request
//     dict.insert(b"piece".to_vec(), Value::Int(piece_index as i64));

//     let payload = ser::to_bytes(&Value::Dict(dict))
//         .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bencode error: {}", e)))?;

//     // 2. Construct the extended message
//     let mut message = Vec::new();
//     let total_length = payload.len() as u32 + 2;
//     message.extend_from_slice(&total_length.to_be_bytes());
//     message.push(20); // extended message
//     message.push(ut_metadata_id); // message ID for ut_metadata
//     message.extend_from_slice(&payload);

//     // 3. Send metadata request
//     stream.write_all(&message)?;
//     println!("Requested metadata piece {}", piece_index);

//     // 4. Read response header
//     let mut length_buf = [0u8; 4];
//     stream.read_exact(&mut length_buf)?;
//     let length = u32::from_be_bytes(length_buf);
//     if length < 2 {
//         return Err(io::Error::new(
//             io::ErrorKind::InvalidData,
//             "Extended message too short",
//         ));
//     }

//     let mut msg_id_buf = [0u8; 1];
//     stream.read_exact(&mut msg_id_buf)?;
//     if msg_id_buf[0] != 20 {
//         return Err(io::Error::new(
//             io::ErrorKind::InvalidData,
//             format!("Expected extended message (20), got {}", msg_id_buf[0]),
//         ));
//     }

//     let mut ext_id_buf = [0u8; 1];
//     stream.read_exact(&mut ext_id_buf)?;
//     if ext_id_buf[0] != ut_metadata_id {
//         return Err(io::Error::new(
//             io::ErrorKind::InvalidData,
//             format!(
//                 "Expected ut_metadata id {}, got {}",
//                 ut_metadata_id, ext_id_buf[0]
//             ),
//         ));
//     }

//     let payload_len = length as usize - 2;
//     let mut payload_buf = vec![0u8; payload_len];
//     let mut total_read = 0;

//     while total_read < payload_len {
//         match stream.read(&mut payload_buf[total_read..]) {
//             Ok(0) => {
//                 return Err(io::Error::new(
//                     io::ErrorKind::UnexpectedEof,
//                     "Connection closed",
//                 ))
//             }
//             Ok(n) => total_read += n,
//             Err(e) => {
//                 return Err(io::Error::new(
//                     io::ErrorKind::Other,
//                     format!("Read error: {}", e),
//                 ))
//             }
//         }
//     }

//     // 5. Split bencoded headers from raw metadata
//     let split_at = payload_buf
//         .windows(2)
//         .position(|w| w == b"ee")
//         .ok_or_else(|| {
//             io::Error::new(
//                 io::ErrorKind::InvalidData,
//                 "Failed to find end of bencode headers",
//             )
//         })?;

//     let metadata_start = split_at + 2;
//     if metadata_start >= payload_buf.len() {
//         return Err(io::Error::new(
//             io::ErrorKind::InvalidData,
//             "No metadata payload after headers",
//         ));
//     }

//     let metadata = payload_buf[metadata_start..].to_vec();
//     println!(
//         "Received metadata piece {} ({} bytes)",
//         piece_index,
//         metadata.len()
//     );

//     Ok(metadata)
// }
// /// Downloads the full metadata by requesting all metadata pieces
// pub fn download_metadata(
//     stream: &mut TcpStream,
//     ut_metadata_id: u8,
//     metadata_size: u64,
// ) -> io::Result<Vec<u8>> {
//     const METADATA_BLOCK_SIZE: u64 = 16384;
//     let num_pieces = (metadata_size + METADATA_BLOCK_SIZE - 1) / METADATA_BLOCK_SIZE;

//     let mut full_metadata = Vec::with_capacity(metadata_size as usize);

//     for piece_index in 0..num_pieces {
//         println!("Requesting metadata piece {}", piece_index);
//         let piece_data = request_metadata_piece(stream, ut_metadata_id, piece_index as u32)
//             .map_err(|e| {
//                 io::Error::new(
//                     io::ErrorKind::Other,
//                     format!("Piece {} error: {}", piece_index, e),
//                 )
//             })?;
//         full_metadata.extend_from_slice(&piece_data);
//     }

//     if full_metadata.len() > metadata_size as usize {
//         full_metadata.truncate(metadata_size as usize);
//     }

//     println!(
//         "Finished downloading metadata ({} bytes from {} pieces)",
//         full_metadata.len(),
//         num_pieces
//     );

//     Ok(full_metadata)
// }
