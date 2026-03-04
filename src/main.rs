use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use clap::{Arg, Command};
use pcap::{Active, Capture};

use crate::models::scanner;

mod error;
mod models;
mod view;

fn main() {
    let cmd = Command::new("wifislam")
        .about(
            r#"
     __       __  __  ________  __            __                         
    /  |  _  /  |/  |/        |/  |          /  |                        
    $$ | / \ $$ |$$/ $$$$$$$$/ $$/   _______ $$ |  ______   _____  ____  
    $$ |/$  \$$ |/  |$$ |__    /  | /       |$$ | /      \ /     \/    \ 
    $$ /$$$  $$ |$$ |$$    |   $$ |/$$$$$$$/ $$ | $$$$$$  |$$$$$$ $$$$  |
    $$ $$/$$ $$ |$$ |$$$$$/    $$ |$$      \ $$ | /    $$ |$$ | $$ | $$ |
    $$$$/  $$$$ |$$ |$$ |      $$ | $$$$$$  |$$ |/$$$$$$$ |$$ | $$ | $$ |
    $$$/    $$$ |$$ |$$ |      $$ |/     $$/ $$ |$$    $$ |$$ | $$ | $$ |
    $$/      $$/ $$/ $$/       $$/ $$$$$$$/  $$/  $$$$$$$/ $$/  $$/  $$/ 
                                                                     
            
    A toolbox for WiFi scanning and attacking.
    
    WARNING: Do not use for illegal purposes!"#,
        )
        .version("0.1")
        .subcommand(Command::new("ifaces").about("List WiFi available WiFi interfaces."))
        .subcommand(
            Command::new("scan")
                .about("Scan for available WiFi devices nearby.")
                .arg(
                    Arg::new("iface")
                        .help("The wireless interface to use (e.g., wlan0)")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("kick")
                .about("Send deauthentication frames to disconnect a client or AP.")
                .arg(
                    Arg::new("iface")
                        .help("The wireless interface to use")
                        .required(true),
                )
                .arg(
                    Arg::new("address")
                        .required(true)
                        .help("The address of the device you want to kick."),
                ),
        )
        .subcommand(
            Command::new("slam")
                .about("Continuously scan for, and deauth all detected WiFi devices.")
                .arg(
                    Arg::new("iface")
                        .help("The wireless interface to use")
                        .required(true),
                ),
        );

    // Parse the command line arguments
    let matches = cmd.get_matches();

    // Handle the subcommands
    match matches.subcommand() {
        Some(("ifaces", _)) => list_interfaces(),
        Some(("scan", sub_matches)) => {
            let iface = sub_matches
                .get_one::<String>("iface")
                .expect("No interface provided");
            scan(iface);
        }
        Some(("kick", sub_matches)) => {
            let iface = sub_matches
                .get_one::<String>("iface")
                .expect("No interface provided");
            let address = sub_matches
                .get_one::<String>("address")
                .expect("No address provided");
            kick(iface, address);
        }
        Some(("slam", sub_matches)) => {
            let iface = sub_matches
                .get_one::<String>("iface")
                .expect("No interface provided");
            slam(iface);
        }
        _ => {
            println!("No valid subcommand provided. Use --help to see available commands.");
        }
    }
}
fn list_interfaces() {
    let interfaces = models::interfaces::detect_interfaces();
    view::interfaces::print_interfaces(&interfaces);
}

fn scan(iface: &String) {
    println!("Starting WiFi scan on {}...", iface);

    // 1. Wrap the HashMap in an Arc<Mutex<>>
    let networks = Arc::new(Mutex::new(HashMap::new()));

    // 2. Clone the Arc for the UI thread
    let networks_print = Arc::clone(&networks);

    // 3. Spawn the background UI thread
    thread::spawn(move || {
        loop {
            // Update the UI every 1.5 seconds
            thread::sleep(Duration::from_millis(1000));
            view::scanner::print_table(&networks_print);
        }
    });

    // 4. Main thread blocks here, running the capture loop
    // Because this handles Ctrl+C, it will gracefully exit and clean up the interface
    run_monitor_handler(iface, |cap| {
        models::scanner::capture_packets(cap, &networks);
    });

    // // 5. Print the final summary after the user presses Ctrl+C and the loop exits
    println!();

    let final_networks = networks.lock().unwrap();

    println!("\nScan finished. Results: {:#?}", final_networks);
}

fn kick(iface: &String, address: &String) {
    println!("[ ] Kicking {} on {}...", address, iface);

    // Accept `cap` here too!
    run_monitor_handler(iface, |cap| {
        // TODO: Implement actual deauth packet injection here
    });
}

fn slam(iface: &String) {
    println!("[ ] Slamming all WiFi devices on {}...", iface);

    // Accept `cap` here too!
    run_monitor_handler(iface, |cap| {
        // TODO: Implement slam logic here
    });
}

/// A helper function to manage the Ctrl+C state and keep the monitor mode guard alive
fn run_monitor_handler<F>(iface: &String, mut action: F)
where
    // UPDATE: The closure now requires a mutable reference to the Capture handle
    F: FnMut(&mut Capture<Active>),
{
    // 1. Set up the interrupt flag
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // 2. Register the Ctrl+C handler
    ctrlc::set_handler(move || {
        println!("\n[ ] Ctrl+C detected! Initiating graceful shutdown...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("[-] Error setting Ctrl-C handler");

    // 3. Enable monitor mode (this creates the RAII guard)
    // UPDATE: Make the guard mutable so we can borrow the capture handle inside it
    let mut monitor_guard = match models::interfaces::enable_monitor_mode(iface) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            return;
        }
    };

    println!("[ ] Running... Press Ctrl+C to stop.");

    // 4. Run the continuous loop
    while running.load(Ordering::SeqCst) {
        // UPDATE: Pass the capture handle to the closure
        action(&mut monitor_guard.capture_handle);

        // REMOVED `thread::sleep` here!
        // pcap handles its own sleeping via the timeout we set.
        // Sleeping here would cause you to miss packets!
    }

    println!("[ ] Exiting process...");
    // When this function finishes, `_monitor_guard` goes out of scope
    // and its `Drop` implementation safely restores the network card.
}
