use std::{
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use pcap::{Active, Capture, Device};
use pnet::datalink::{self, NetworkInterface};

use crate::error::iface_errors::MonitorModeError;

pub struct MonitorInterface {
    pub capture_handle: Capture<Active>,
    pub iface_name: String,
}

impl Drop for MonitorInterface {
    fn drop(&mut self) {
        println!(
            "\n[ ] Releasing {} from monitor mode and restoring to managed...",
            self.iface_name
        );

        // 1. Bring the interface DOWN
        let down_status = Command::new("ip")
            .args(["link", "set", &self.iface_name, "down"])
            .status();

        if down_status.is_err() {
            eprintln!("[-] Failed to bring interface down during cleanup.");
        }

        // 2. Set the interface to MANAGED mode using 'iw'
        let iw_status = Command::new("iw")
            .args(["dev", &self.iface_name, "set", "type", "managed"])
            .status();

        if iw_status.is_err() {
            eprintln!("[-] Failed to set interface to managed mode during cleanup.");
        }

        // 3. Bring the interface back UP
        let up_status = Command::new("ip")
            .args(["link", "set", &self.iface_name, "up"])
            .status();

        if up_status.is_err() {
            eprintln!("[-] Failed to bring interface up during cleanup.");
        }

        println!(
            "[+] {} successfully restored to normal operations.",
            self.iface_name
        );
    }
}

pub fn detect_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| iface.clone())
        .collect()
}

/// Function sets a specified network interface in monitor mode.
/// This allows for the capture of packets that are not destined for the device.
/// It does however, disrupt the normal networking capability of the device.
/// So it is essential that we turn the device back into managed mode after we are done capturing packets.
/// Therefore we have implemented a drop handle that safely returns the card into managed mode after the user presses `ctrl+c`.
pub fn enable_monitor_mode(iface_name: &String) -> Result<MonitorInterface, MonitorModeError> {
    println!("Attempting to open {} in monitor mode...", iface_name);

    // --- 1. OS-LEVEL INTERFACE CONFIGURATION ---

    // Bring the interface DOWN
    Command::new("ip")
        .args(["link", "set", iface_name, "down"])
        .status()
        .map_err(|_| "Failed to bring interface down".to_string())?; // Adapt this map_err to your custom MonitorModeError if needed

    // Set to MONITOR mode using 'iw'
    let iw_status = Command::new("iw")
        .args(["dev", iface_name, "set", "type", "monitor"])
        .status()
        .map_err(|_| "Failed to execute iw command".to_string())?;

    if !iw_status.success() {
        eprintln!("Warning: 'iw' command did not return success. Ensure the adapter supports monitor mode.");
    }

    // Bring the interface back UP
    Command::new("ip")
        .args(["link", "set", iface_name, "up"])
        .status()
        .map_err(|_| "Failed to bring interface up".to_string())?;

    // --- 2. PCAP INITIALIZATION ---

    // Find the device by name
    let main_device = Device::list()?
        .into_iter()
        .find(|d| d.name == *iface_name)
        .ok_or("Interface not found. Ensure the adapter is plugged in.")?;

    // Open the capture handle WITHOUT rfmon(true) because the OS already did the work
    let cap = Capture::from_device(main_device)?
        .promisc(true) // Promiscuous mode
        .immediate_mode(true) // Deliver packets immediately
        .timeout(250) // IMPORTANT: Required to let main.rs break the loop and check for Ctrl+C
        .open()?;

    println!("Successfully attached to {} in monitor mode.", iface_name);

    // Return the capture handle
    Ok(MonitorInterface {
        capture_handle: cap,
        iface_name: iface_name.clone(),
    })
}

/// Spawns a background thread that continuously cycles the wireless
/// adapter through 2.4GHz and 5GHz channels.
pub fn start_channel_hopper(
    iface: String,
    running: Arc<AtomicBool>,
    current_channel: Arc<AtomicU16>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Standard 2.4GHz channels and common non-DFS 5GHz channels
        let channels = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165,
        ];

        let mut index = 0;

        while running.load(Ordering::SeqCst) {
            // Get the current channel from the list
            let ch = channels[index];

            // Store the channel as a shared variable across threads
            current_channel.store(ch, Ordering::SeqCst);

            // Execute the Linux command: iw dev wlan0 set channel X
            // We use `.output()` instead of `.status()` to completely suppress
            // any stdout/stderr spam. If an adapter doesn't support 5GHz,
            // this command will just silently fail and move to the next channel!
            let _ = Command::new("iw")
                .args(["dev", &iface, "set", "channel", &ch.to_string()])
                .output();

            // Move to the next channel, wrapping around to the beginning
            index = (index + 1) % channels.len();

            // Wait long enough to catch beacons (102.4ms is standard)
            thread::sleep(Duration::from_millis(100));
        }
    })
}
