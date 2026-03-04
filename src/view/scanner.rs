use comfy_table::{presets::NOTHING, Table};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::models::scanner::AccessPoint;

pub fn print_table(networks_arc: &Arc<Mutex<HashMap<String, AccessPoint>>>) {
    // Lock the mutex to read the data
    let networks = networks_arc.lock().unwrap();

    // ANSI Escape codes: Clear the screen and move the cursor to the top-left
    print!("{}[2J", 27 as char);
    print!("{}[1;1H", 27 as char);

    println!("Scanning... Press Ctrl+C to stop.\n");

    let mut table = Table::new();
    table.load_preset(NOTHING);
    table.set_header(vec![
        "BSSID",
        "SSID",
        "Channel",
        "Beacons",
        "Clients Connected",
    ]);

    for (bssid, ap) in networks.iter() {
        table.add_row(vec![
            bssid,
            &ap.ssid,
            &ap.channel.to_string(),
            &ap.beacon_count.to_string(),
            &ap.clients.len().to_string(),
        ]);
    }

    println!("{table}");
}
