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
    use std::io::ErrorKind;
    use std::time::{Duration, Instant};

    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let start = Instant::now();
    let mut last_sent = Instant::now();

    // Send fake "have" message (pretend we have piece 0)
    let have_msg = [0u8, 0, 0, 5, 4, 0, 0, 0, 0]; // length=5, ID=4, piece=0
    stream.write_all(&have_msg)?;
    println!("Sent fake 'have' message for piece 0");

    // Send fake bitfield (pretend we have 64 pieces — adjust as needed)
    let fake_bitfield = vec![0xFF; 8]; // 8 bytes = 64 bits
    let bitfield_len = fake_bitfield.len() + 1;
    stream.write_all(&(bitfield_len as u32).to_be_bytes())?;
    stream.write_all(&[5])?;
    stream.write_all(&fake_bitfield)?;
    println!("Sent fake bitfield");

    let mut length_buf = [0u8; 4];
    let mut id_buf = [0u8; 1];

    loop {
        if start.elapsed().as_secs() > 60 {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "Timed out waiting for unchoke",
            ));
        }

        // Periodic keep-alive every 25 seconds
        if last_sent.elapsed().as_secs() >= 25 {
            stream.write_all(&[0, 0, 0, 0])?;
            println!("Sent keep-alive");
            last_sent = Instant::now();
        }

        match stream.read_exact(&mut length_buf) {
            Ok(_) => {}
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
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
                ErrorKind::InvalidData,
                format!("Peer sent absurd message length: {}", length),
            ));
        }

        match stream.read_exact(&mut id_buf) {
            Ok(_) => {}
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }

        let message_id = id_buf[0];
        let payload_len = length as usize - 1;

        println!("Received message ID {} ({} bytes)", message_id, length);
        match message_id {
            0 => println!("Keep-alive (0)"),
            1 => {
                println!("Unchoke (1)");
                println!("Peer unchoked us. Proceeding to download.");
                return Ok(());
            }
            2 => println!("Interested (2)"),
            3 => println!("Not Interested (3)"),
            4 => {
                let mut have_buf = [0u8; 4];
                stream.read_exact(&mut have_buf)?;
                let index = u32::from_be_bytes(have_buf);
                println!("Peer has piece {}", index);
            }
            5 => {
                let mut bitfield = vec![0u8; payload_len];
                stream.read_exact(&mut bitfield)?;
                println!("Received bitfield ({} bytes)", bitfield.len());
            }
            7 => {
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
    use serde_bencode::de;

    let mut payload = b"d1:md11:ut_metadatai1ee".to_vec(); // {"m": {"ut_metadata": 1}}
    let mut message = Vec::new();
    let total_length = payload.len() as u32 + 2;
    message.extend_from_slice(&total_length.to_be_bytes());
    message.push(20); // extended message
    message.push(0); // extended handshake
    message.extend_from_slice(&payload);
    stream.write_all(&message)?;
    println!("Sent Extended Handshake.");

    let mut length_buf = [0u8; 4];
    let mut msg_id_buf = [0u8; 1];
    let mut ext_type_buf = [0u8; 1];

    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > 10 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Timed out waiting for extended handshake response",
            ));
        }

        // Read length prefix
        stream.read_exact(&mut length_buf)?;
        let length = u32::from_be_bytes(length_buf);

        if length == 0 {
            println!("Received keep-alive during extended handshake.");
            continue;
        }
        if length < 2 {
            println!(
                "Skipping short message during extended handshake: length={}",
                length
            );
            let mut skip_buf = vec![0u8; length as usize];
            stream.read_exact(&mut skip_buf)?;
            continue;
        }

        // Read message ID and extended message ID
        stream.read_exact(&mut msg_id_buf)?;
        stream.read_exact(&mut ext_type_buf)?;
        let msg_id = msg_id_buf[0];
        let ext_type = ext_type_buf[0];

        if msg_id != 20 {
            let mut skip_buf = vec![0u8; (length as usize) - 1];
            stream.read_exact(&mut skip_buf)?;
            println!("Skipping non-extension message ID {}", msg_id);
            continue;
        }

        if ext_type != 0 {
            // Not the extended handshake we're looking for — skip payload
            let mut skip_buf = vec![0u8; (length as usize) - 2];
            stream.read_exact(&mut skip_buf)?;
            println!(
                "Skipping non-handshake extension message (ext_id = {})",
                ext_type
            );
            continue;
        }

        // This is the extended handshake payload we want
        let payload_len = (length as usize) - 2;
        let mut payload_buf = vec![0u8; payload_len];
        stream.read_exact(&mut payload_buf)?;

        println!("Received Extended Handshake payload: {:?}", payload_buf);

        // Decode it
        let parsed: Value = de::from_bytes(&payload_buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to decode bencode: {}", e),
            )
        })?;

        if let Value::Dict(root) = parsed {
            let mut ut_metadata_id = 0u8;
            let mut metadata_size = 0u64;

            if let Some(Value::Dict(m)) = root.get(&b"m"[..]) {
                if let Some(Value::Int(id)) = m.get(&b"ut_metadata"[..]) {
                    ut_metadata_id = *id as u8;
                }
            }
            if let Some(Value::Int(size)) = root.get(&b"metadata_size"[..]) {
                metadata_size = *size as u64;
            }

            if ut_metadata_id == 0 || metadata_size == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Peer did not advertise ut_metadata or metadata_size",
                ));
            }

            println!(
                "Peer supports ut_metadata (id {}) with metadata_size {} bytes",
                ut_metadata_id, metadata_size
            );
            return Ok((ut_metadata_id, metadata_size));
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Extended handshake payload was not a dictionary",
            ));
        }
    }
}

/// Request a specific metadata piece from a peer
pub fn request_metadata_piece(
    stream: &mut TcpStream,
    ut_metadata_id: u8,
    piece_index: u32,
) -> io::Result<Vec<u8>> {
    use serde_bencode::value::Value;
    use serde_bencode::{de, ser};

    // Build bencoded request: { "msg_type": 0, "piece": piece_index }
    let mut dict = std::collections::HashMap::new();
    dict.insert(b"msg_type".to_vec(), Value::Int(0));
    dict.insert(b"piece".to_vec(), Value::Int(piece_index as i64));
    let payload = ser::to_bytes(&Value::Dict(dict)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to encode bencode: {}", e),
        )
    })?;

    // Send: [len][id=20][ext_id][payload]
    let mut message = Vec::with_capacity(payload.len() + 2 + 4);
    let total_length = payload.len() as u32 + 2;
    message.extend_from_slice(&total_length.to_be_bytes());
    message.push(20);
    message.push(ut_metadata_id);
    message.extend_from_slice(&payload);
    stream.write_all(&message)?;
    println!("Requested metadata piece {}", piece_index);

    // Receive and loop until matching metadata piece response
    loop {
        // Read header
        let mut length_buf = [0u8; 4];
        stream.read_exact(&mut length_buf)?;
        let length = u32::from_be_bytes(length_buf);
        if length < 2 {
            let mut skip = vec![0u8; length as usize];
            stream.read_exact(&mut skip)?;
            println!("Skipping short or malformed extended message.");
            continue;
        }

        let mut msg_id_buf = [0u8; 1];
        stream.read_exact(&mut msg_id_buf)?;
        if msg_id_buf[0] != 20 {
            let mut skip = vec![0u8; length as usize - 1];
            stream.read_exact(&mut skip)?;
            println!(
                "Received non-extended message (ID {}). Skipping.",
                msg_id_buf[0]
            );
            continue;
        }

        let mut ext_id_buf = [0u8; 1];
        stream.read_exact(&mut ext_id_buf)?;
        if ext_id_buf[0] != ut_metadata_id {
            let mut skip = vec![0u8; length as usize - 2];
            stream.read_exact(&mut skip)?;
            println!(
                "Unexpected extended message ID ({}). Expected {}. Skipping.",
                ext_id_buf[0], ut_metadata_id
            );
            continue;
        }

        let payload_len = length as usize - 2;
        let mut payload_buf = vec![0u8; payload_len];
        stream.read_exact(&mut payload_buf)?;

        // Split the payload: {bencoded header} + raw metadata
        if let Some(split_at) = payload_buf.windows(2).position(|w| w == b"ee") {
            let header_bytes = &payload_buf[..split_at + 2];
            let metadata_bytes = &payload_buf[split_at + 2..];

            let header_val: Value = de::from_bytes(header_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to decode metadata piece header: {}", e),
                )
            })?;

            if let Value::Dict(dict) = header_val {
                if let Some(Value::Int(msg_type)) = dict.get(&b"msg_type"[..]) {
                    if *msg_type == 1 {
                        println!(
                            "Received metadata piece {} ({} bytes)",
                            piece_index,
                            metadata_bytes.len()
                        );
                        return Ok(metadata_bytes.to_vec());
                    } else {
                        println!("Received unexpected msg_type: {}. Ignoring.", msg_type);
                    }
                } else {
                    println!("Header missing msg_type field");
                }
            } else {
                println!("Header is not a dictionary");
            }
        } else {
            println!("Could not find 'ee' marker in extended metadata piece");
        }

        // No valid metadata, try next message
        println!("Retrying to receive correct metadata piece...");
    }
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

pub fn parse_metadata(metadata: &[u8]) -> Result<Torrent, Box<dyn std::error::Error>> {
    let info_value: Info = from_bytes(metadata)?;

    // Validate required fields
    if info_value.piece_length == 0 {
        return Err("Parsed metadata missing valid piece length".into());
    }

    // Return full Torrent struct with only the announce/announce-list omitted (as expected)
    Ok(Torrent {
        announce: None,
        announce_list: None,
        info: info_value,
    })
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
