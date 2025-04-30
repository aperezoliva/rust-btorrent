// for generating random peer ids and handshake operations
use crate::torrent_parser::{Info, Torrent};
use rand::{distr::Alphanumeric, rngs::ThreadRng, Rng};
use serde_bencode::de;
use serde_bencode::from_bytes;
use serde_bencode::value::Value;
use sha1::Digest;
use sha1::Sha1;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

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
pub enum PeerState {
    Unchoked,
    NotUnchoked,
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
    if let Err(e) = stream.read_exact(&mut response) {
        eprintln!("Failed to read handshake response: {}", e);
        return Err(e);
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
    if let Err(e) = stream.read_exact(&mut response) {
        eprintln!("Failed to read handshake response: {}", e);
        return Err(e);
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

pub fn decode_bitfield(payload: &[u8]) -> Vec<u32> {
    let mut pieces = Vec::new();

    for (byte_index, byte) in payload.iter().enumerate() {
        for bit in 0..8 {
            if byte & (0b1000_0000 >> bit) != 0 {
                let piece_index = (byte_index * 8 + bit) as u32;
                pieces.push(piece_index);
            }
        }
    }

    pieces
}

// Unchoke refers to peers allowing the client to download pieces
/* Implemented some new changes per https://stackoverflow.com/questions/53531493/peers-not-sending-back-unchoke-message */
const CHOKE: u8 = 0;
const UNCHOKE: u8 = 1;
const INTERESTED: u8 = 2;
const NOT_INTERESTED: u8 = 3;
const HAVE: u8 = 4;
const BITFIELD: u8 = 5;
const REQUEST: u8 = 6;
const PIECE: u8 = 7;
const CANCEL: u8 = 8;
const PORT: u8 = 9;

pub fn wait_until_unchoked(stream: &mut std::net::TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let start = Instant::now();

    let mut length_buf = [0u8; 4];
    let mut id_buf = [0u8; 1];

    loop {
        if start.elapsed().as_secs() > 60 {
            stream.write_all(&[0, 0, 0, 0])?;
            println!("Sent keep-alive");
        }

        // Read the length prefix
        match stream.read_exact(&mut length_buf) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        }

        let length = u32::from_be_bytes(length_buf);
        if length == 0 {
            println!("Received keep-alive");
            continue;
        }
        if length > 2_000_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Peer sent absurd message length: {}", length),
            ));
        }

        // Read the message ID
        match stream.read_exact(&mut id_buf) {
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        }

        let message_id = id_buf[0];
        let payload_len = length as usize - 1;

        println!("Received message ID {} ({} bytes)", message_id, length);
        match message_id {
            0 => println!("Keep-alive (0)"),
            1 => println!("Unchoke (1)"),
            2 => println!("Interested (2)"),
            3 => println!("Not Interested (3)"),
            4 => println!("Have (4)"),
            5 => println!("Bitfield (5)"),
            6 => println!("Request (6)"),
            7 => println!("Piece (7)"),
            8 => println!("Cancel (8)"),
            20 => println!("Extended Message (20)"),
            other => println!("Unknown message ID {}", other),
        }

        // Handle specific messages
        match message_id {
            UNCHOKE => {
                println!("Peer unchoked us. Proceeding to download.");
                return Ok(());
            }
            CHOKE => {
                println!("Peer choked us.");
            }
            HAVE => {
                let mut have_buf = [0u8; 4];
                match stream.read_exact(&mut have_buf) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
                let index = u32::from_be_bytes(have_buf);
                println!("Peer has piece {}", index);
            }
            BITFIELD => {
                let mut bitfield = vec![0u8; payload_len];
                stream.read_exact(&mut bitfield)?;
                println!("Received bitfield ({} bytes)", bitfield.len());
            }
            PIECE => {
                println!("Received piece message (but skipping payload)");
                let mut skip_buf = vec![0u8; payload_len];
                stream.read_exact(&mut skip_buf)?;
            }
            _ => {
                println!(
                    "Unhandled message {}, skipping {} bytes",
                    message_id, payload_len
                );
                let mut skip_buf = vec![0u8; payload_len];
                stream.read_exact(&mut skip_buf)?;
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
    let mut id_buf = [0u8; 1];

    // Read 4-byte length prefix
    stream.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf);

    if length < 9 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Piece message too short",
        ));
    }

    // Read 1-byte message ID
    stream.read_exact(&mut id_buf)?;
    let message_id = id_buf[0];

    if message_id != 7 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected Piece (7), got {}", message_id),
        ));
    }

    // Read 4-byte piece index
    let mut piece_index_buf = [0u8; 4];
    stream.read_exact(&mut piece_index_buf)?;
    let piece_index = u32::from_be_bytes(piece_index_buf);

    // Read 4-byte block offset
    let mut block_offset_buf = [0u8; 4];
    stream.read_exact(&mut block_offset_buf)?;
    let block_offset = u32::from_be_bytes(block_offset_buf);

    // Remaining bytes = actual block data
    let block_length = length - 9;
    let mut block_data = vec![0u8; block_length as usize];
    stream.read_exact(&mut block_data)?;

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

pub fn download_one_block(stream: &mut TcpStream, piece_length: u32) -> io::Result<Vec<u8>> {
    const STANDARD_BLOCK_SIZE: u32 = 16384; // 16 KB standard request size

    let piece_index = 0;
    let block_offset = 0;

    if piece_length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Piece length is zero — cannot request data.",
        ));
    }

    let request_size = piece_length.min(STANDARD_BLOCK_SIZE); // Cap to piece size if needed

    send_request(stream, piece_index, block_offset, request_size)?;

    let (_piece_idx, _block_offset, block_data) = receive_piece(stream)?;

    Ok(block_data)
}

pub fn send_extended_handshake(stream: &mut TcpStream) -> io::Result<(u8, u64)> {
    // Build the Extended Handshake message
    let mut payload = b"d1:md11:ut_metadatai1ee".to_vec(); // Bencoded dictionary: {"m":{"ut_metadata":1}}

    let mut message = Vec::new();

    // Length = payload length + 2 bytes (1 for message ID, 1 for extended ID)
    let total_length = payload.len() as u32 + 2;
    message.extend_from_slice(&total_length.to_be_bytes());

    // Message ID 20 (extended message)
    message.push(20);

    // Extended message ID 0 (extended handshake)
    message.push(0);

    // Payload (bencoded dictionary)
    message.extend_from_slice(&payload);

    // Send it
    stream.write_all(&message)?;
    println!("Sent Extended Handshake.");

    // Now read peer's Extended Handshake response
    let mut length_buf = [0u8; 4];
    stream.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf);

    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Peer closed connection after extended handshake.",
        ));
    }

    let mut msg_id_buf = [0u8; 1];
    stream.read_exact(&mut msg_id_buf)?;
    let msg_id = msg_id_buf[0];

    if msg_id != 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected extended message (20), got {}", msg_id),
        ));
    }

    // Extended message type
    let mut ext_type_buf = [0u8; 1];
    stream.read_exact(&mut ext_type_buf)?;
    let ext_type = ext_type_buf[0];

    if ext_type != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected extended handshake (0), got {}", ext_type),
        ));
    }

    // Remaining payload
    let payload_len = length as usize - 2;
    let mut payload_buf = vec![0u8; payload_len];
    stream.read_exact(&mut payload_buf)?;

    println!("Received Extended Handshake payload: {:?}", payload_buf);

    // Parse the bencoded payload
    let parsed: Value = de::from_bytes(&payload_buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to decode bencode: {}", e),
        )
    })?;

    // Extract ut_metadata extension ID and metadata size
    if let Value::Dict(root) = parsed {
        let mut metadata_size: u64 = 0;
        let mut ut_metadata_id: u8 = 0;

        if let Some(Value::Dict(m_dict)) = root.get(&b"m"[..]) {
            if let Some(Value::Int(id)) = m_dict.get(&b"ut_metadata"[..]) {
                ut_metadata_id = *id as u8;
            }
        }

        if let Some(Value::Int(size)) = root.get(&b"metadata_size"[..]) {
            metadata_size = *size as u64;
        }

        if ut_metadata_id == 0 || metadata_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Peer did not provide ut_metadata extension or metadata size.",
            ));
        }

        println!(
            "Peer supports ut_metadata (id {}) with metadata_size {} bytes",
            ut_metadata_id, metadata_size
        );

        Ok((ut_metadata_id, metadata_size))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Extended handshake payload not a dictionary",
        ))
    }
}

/// Request a specific metadata piece from a peer
pub fn request_metadata_piece(
    stream: &mut TcpStream,
    ut_metadata_id: u8,
    piece_index: u32,
) -> io::Result<Vec<u8>> {
    use serde_bencode::ser;

    // Build request dictionary
    let mut dict = std::collections::HashMap::new();
    dict.insert(b"msg_type".to_vec(), Value::Int(0)); // 0 = request
    dict.insert(b"piece".to_vec(), Value::Int(piece_index as i64));

    let payload = ser::to_bytes(&Value::Dict(dict))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bencode error: {}", e)))?;

    // Full message = 1-byte message ID (20), 1-byte extended message ID (ut_metadata ID), then payload
    let mut message = Vec::new();
    let total_length = payload.len() as u32 + 2;
    message.extend_from_slice(&total_length.to_be_bytes());
    message.push(20); // Extended message
    message.push(ut_metadata_id); // Specific extension ID
    message.extend_from_slice(&payload);

    // Send the metadata piece request
    stream.write_all(&message)?;
    println!("Requested metadata piece {}", piece_index);

    // Read peer's response
    let mut length_buf = [0u8; 4];
    stream.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf);

    let mut msg_id_buf = [0u8; 1];
    stream.read_exact(&mut msg_id_buf)?;
    if msg_id_buf[0] != 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected extended message (20), got {}", msg_id_buf[0]),
        ));
    }

    let mut ext_id_buf = [0u8; 1];
    stream.read_exact(&mut ext_id_buf)?;
    if ext_id_buf[0] != ut_metadata_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected ut_metadata extended message ID ({}), got {}",
                ut_metadata_id, ext_id_buf[0]
            ),
        ));
    }

    // Remaining payload
    let payload_len = length as usize - 2;
    let mut payload_buf = vec![0u8; payload_len];
    stream.read_exact(&mut payload_buf)?;

    // Split metadata headers and actual block
    // The payload looks like: {headers-dict}raw-metadata
    // We need to find where headers end
    let split_at = payload_buf
        .windows(2)
        .position(|w| w == b"ee")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to find end of bencode headers",
            )
        })?;

    let metadata_start = split_at + 2; // after the "ee"
    let metadata = payload_buf[metadata_start..].to_vec();

    println!(
        "Received metadata piece {} ({} bytes)",
        piece_index,
        metadata.len()
    );

    Ok(metadata)
}

/// Downloads the full metadata by requesting all metadata pieces
pub fn download_metadata(
    stream: &mut TcpStream,
    ut_metadata_id: u8,
    metadata_size: u64,
) -> io::Result<Vec<u8>> {
    const METADATA_BLOCK_SIZE: u64 = 16384;

    let num_pieces = (metadata_size + METADATA_BLOCK_SIZE - 1) / METADATA_BLOCK_SIZE;
    println!(
        "Downloading metadata: {} bytes across {} pieces",
        metadata_size, num_pieces
    );

    let mut full_metadata = Vec::with_capacity(metadata_size as usize);

    for piece_index in 0..num_pieces {
        println!("Requesting metadata piece {}", piece_index);

        let piece_data = request_metadata_piece(stream, ut_metadata_id, piece_index as u32)?;

        full_metadata.extend_from_slice(&piece_data);
    }

    // Safety check: trim if we downloaded slightly too much
    if full_metadata.len() > metadata_size as usize {
        full_metadata.truncate(metadata_size as usize);
    }

    println!(
        "Finished downloading full metadata ({} bytes)",
        full_metadata.len()
    );

    Ok(full_metadata)
}

pub fn compute_info_hash(metadata: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(metadata);
    let result = hasher.finalize();
    result.into()
}

fn parse_metadata(metadata: &[u8]) -> Result<Torrent, Box<dyn std::error::Error>> {
    let info_value: Info = from_bytes(metadata)?;

    let torrent = Torrent {
        announce: None,      // No announce URL from metadata
        announce_list: None, // No announce-list either
        info: info_value,
    };

    Ok(torrent)
}

/// Reads and interprets a bitfield message from a peer.
/// Returns a `Vec<bool>` where each entry is true if the peer has that piece.
pub fn read_bitfield(stream: &mut TcpStream, num_pieces: usize) -> io::Result<Vec<bool>> {
    let mut length_buf = [0u8; 4];
    stream.read_exact(&mut length_buf)?;
    let length = u32::from_be_bytes(length_buf);

    if length < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Bitfield message too short",
        ));
    }

    let mut id_buf = [0u8; 1];
    stream.read_exact(&mut id_buf)?;
    let message_id = id_buf[0];

    if message_id != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected bitfield message (5), got {}", message_id),
        ));
    }

    let bitfield_len = (length - 1) as usize;
    let mut bitfield = vec![0u8; bitfield_len];
    stream.read_exact(&mut bitfield)?;

    let mut pieces = vec![false; num_pieces];
    for (byte_index, byte) in bitfield.iter().enumerate() {
        for bit in 0..8 {
            let piece_index = byte_index * 8 + bit;
            if piece_index >= num_pieces {
                break;
            }
            if byte & (0x80 >> bit) != 0 {
                pieces[piece_index] = true;
            }
        }
    }

    println!(
        "Peer has pieces: {:?}",
        pieces
            .iter()
            .enumerate()
            .filter(|(_, b)| **b)
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    );

    Ok(pieces)
}
