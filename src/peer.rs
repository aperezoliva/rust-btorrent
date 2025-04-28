// for generating random peer ids and handshake operations
use rand::{distr::Alphanumeric, rngs::ThreadRng, Rng};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// Generates peer id
pub fn generate_peer_id() -> [u8; 20] {
    let prefix = b"-MY0100-"; // refers to the client
    let mut peer_id = [0u8; 20]; // Fill first 8 bytes with prefix

    peer_id[..8].copy_from_slice(prefix);

    // Fill remaining 12 bytes with random alphanumeric characters
    for byte in &mut peer_id[8..] {
        *byte = ThreadRng::default().sample(Alphanumeric) as u8;
    }

    peer_id
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
    handshake.extend_from_slice(&[0; 8]);

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
    stream.read_exact(&mut response)?;

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
pub fn wait_for_unchoke(stream: &mut TcpStream) -> io::Result<()> {
    let mut length_buf = [0u8; 4];
    let mut id_buf = [0u8; 1];

    stream.set_read_timeout(Some(Duration::from_secs(10)))?; // Timeout to avoid infinite hang

    loop {
        // Read 4-byte length prefix
        stream.read_exact(&mut length_buf)?;
        let length = u32::from_be_bytes(length_buf);

        if length == 0 {
            println!("Received keep-alive message (length 0). Ignoring.");
            continue;
        }
        if length != 1 {
            println!(
                "Received non-unchoke message (length {}). Skipping.",
                length
            );
            let mut skip_buf = vec![0u8; length as usize];
            stream.read_exact(&mut skip_buf)?;
            continue;
        }

        // Read 1-byte message ID
        stream.read_exact(&mut id_buf)?;
        let message_id = id_buf[0];

        if message_id == 1 {
            println!("Received Unchoke. Ready to request pieces.");
            return Ok(());
        } else {
            println!("Received message ID {}. Waiting for unchoke...", message_id);
            continue;
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
