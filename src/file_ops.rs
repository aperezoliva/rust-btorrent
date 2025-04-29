use crate::torrent_parser::{Info, Torrent};
use serde_bencode::from_bytes;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

/// Combines all downloaded piece files into a single output file
pub fn combine_pieces(output_filename: &str, num_pieces: u64) -> io::Result<()> {
    let mut output = File::create(output_filename)?;

    for piece_index in 0..num_pieces {
        let filename = format!("piece_{}.bin", piece_index);
        let path = Path::new(&filename);

        if path.exists() {
            let mut piece_file = File::open(&path)?;
            let mut buffer = Vec::new();
            piece_file.read_to_end(&mut buffer)?;
            output.write_all(&buffer)?;
            println!("Appended {}", filename);
        } else {
            eprintln!("Warning: piece file {} is missing!", filename);
        }
    }

    println!(
        "Successfully combined all pieces into '{}'",
        output_filename
    );
    Ok(())
}

pub fn cleanup_pieces(num_pieces: u64) -> io::Result<()> {
    for piece_index in 0..num_pieces {
        let filename = format!("piece_{}.bin", piece_index);
        let path = Path::new(&filename);

        if path.is_file() {
            match fs::remove_file(&path) {
                Ok(_) => println!("Deleted {}", filename),
                Err(e) => eprintln!("Failed to delete {}: {}", filename, e),
            }
        }
        // If the piece doesn't exist, silently ignore
    }

    println!("Piece files cleanup complete.");
    Ok(())
}
