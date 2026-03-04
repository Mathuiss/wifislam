use std::collections::HashMap;

use libwifi;
use libwifi::Frame;
use pcap::Active;
use pcap::Capture;

#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid: String,
    pub ssid: String,
    pub beacon_count: u32,
}

pub fn capture_packets(cap: &mut Capture<Active>, networks: &mut HashMap<String, AccessPoint>) {
    match cap.next_packet() {
        Ok(packet) => {
            // Pass the raw bytes to our new scanner model
            if let Some(ap) = self::process_packet(packet.data) {
                // Update the existing entry or insert the new one
                networks
                    .entry(ap.bssid.clone())
                    .and_modify(|existing_ap| existing_ap.beacon_count += 1)
                    .or_insert_with(|| {
                        // This closure only runs if it's a completely new network
                        println!("[+] New Network: {:<17} | SSID: {}", ap.bssid, ap.ssid);
                        ap
                    });
            }
        }
        Err(pcap::Error::TimeoutExpired) => {
            // Timeouts are normal (we set a 250ms timeout in our Capture handle).
            // It just unblocks the loop so we can check for Ctrl+C.
        }
        Err(e) => {
            eprintln!("Capture error: {:?}", e);
        }
    }
}

/// Takes raw packet bytes from pcap, strips the Radiotap header,
/// and attempts to parse it as an 802.11 Beacon frame.
fn process_packet(packet: &[u8]) -> Option<AccessPoint> {
    // 1. Skip the Radiotap Header
    // The length is always a little-endian u16 at bytes 2 and 3.
    if packet.len() < 4 {
        return None;
    }
    let rtap_len = u16::from_le_bytes([packet[2], packet[3]]) as usize;

    // Ensure there is actual data after the Radiotap header
    if packet.len() <= rtap_len {
        return None;
    }

    // Slice off the Radiotap header
    let wifi_data = &packet[rtap_len..];

    let frame = match libwifi::parse_frame(wifi_data, false) {
        Ok(f) => f,
        Err(e) => {
            println!("{:?}", e);
            return None;
        }
    };

    // println!("[+] Packet captured of type: {:?}", frame);
    print_frame(&frame);

    // 2. Parse the pure 802.11 frame using libwifi
    match frame {
        Frame::Beacon(beacon) => {
            let bssid = beacon.header.address_3.to_string();
            let ssid = beacon.station_info.ssid();

            Some(AccessPoint {
                bssid,
                ssid,
                beacon_count: 1, // Initial count when first discovered
            })
        }
        _ => None,
    }
}

fn print_frame(frame: &Frame) {
    match frame {
        // Management Frames
        Frame::Beacon(d) => println!(
            "Beacon: TO: {}\t FROM: {}",
            d.header.address_1, d.header.address_2
        ),
        Frame::ProbeRequest(d) => println!(
            "Probe Request: TO: {}\tFROM: {}",
            d.header.address_1, d.header.address_2
        ),
        Frame::ProbeResponse(d) => println!(
            "Probe Response: TO: {} FROM: {}",
            d.header.address_1, d.header.address_2
        ),
        Frame::AssociationRequest(_) => println!("Association Request"),
        Frame::AssociationResponse(_) => println!("Association Response"),
        Frame::ReassociationRequest(_) => println!("Reassociation Request"),
        Frame::ReassociationResponse(_) => println!("Reassociation Response"),
        Frame::Action(_) => println!("Action"),

        // Authentication
        Frame::Authentication(_) => println!("Authentication"),
        Frame::Deauthentication(_) => println!("Deauthentication"),

        // Control Frames
        Frame::Rts(_) => println!("RTS"),
        Frame::Cts(_) => println!("CTS"),
        Frame::Ack(_) => println!("ACK"),
        Frame::BlockAckRequest(_) => println!("Block ACK Request"),
        Frame::BlockAck(_) => println!("Block ACK"),

        // Data Frames
        Frame::Data(_) => println!("Data"),
        Frame::QosData(_) => println!("QoS Data"),
        Frame::DataCfAck(_) => println!("Data + CF-ACK"),
        Frame::DataCfPoll(_) => println!("Data + CF-Poll"),
        Frame::DataCfAckCfPoll(_) => println!("Data + CF-ACK + CF-Poll"),
        Frame::CfAck(_) => println!("CF-ACK"),
        Frame::CfPoll(_) => println!("CF-Poll"),
        Frame::CfAckCfPoll(_) => println!("CF-ACK + CF-Poll"),
        Frame::QosDataCfAck(_) => println!("QoS Data + CF-ACK"),
        Frame::QosDataCfPoll(_) => println!("QoS Data + CF-Poll"),
        Frame::QosDataCfAckCfPoll(_) => println!("QoS Data + CF-ACK + CF-Poll"),

        // Null / No EAPOL
        Frame::QosCfPoll(_) => println!("QoS CF-Poll"),
        Frame::QosCfAckCfPoll(_) => println!("QoS CF-ACK + CF-Poll"),
        Frame::QosNull(_) => println!("QoS Null"),
        Frame::NullData(_) => println!("Null Data"),
    }
}
