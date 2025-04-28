/* Note for self, main.rs still needs other modules even though mod.rs exposes them publicly due to
each binary crate needs its own mod declarations to know what it’s working with directly. */
mod peer;
mod torrent_parser;
mod tracker;

fn main() {
    let options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "Torrent Parser",
        options,
        Box::new(|_cc| Ok(Box::new(torrent_parser::TorrentApp::default()))),
    );
}
