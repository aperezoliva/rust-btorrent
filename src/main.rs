mod torrent_parser;
mod tracker;
use torrent_parser::TorrentApp;

fn main() {
    let options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "Torrent Parser",
        options,
        Box::new(|_cc| Ok(Box::new(TorrentApp::default()))),
    );
}
