use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use libwifi;
use libwifi::frame::components::FrameControl;
use libwifi::frame::components::MacAddress;
use libwifi::Frame;
use pcap::Active;
use pcap::Capture;

#[derive(Debug, Clone)]
pub struct Client {
    pub mac: String,
    pub packet_count: u32,
}

#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid: String,
    pub ssid: String,
    pub beacon_count: u32,
    // A map of connected clients, keyed by the client's MAC address
    pub clients: HashMap<String, Client>,
}

/// Represents the actionable data we extracted from a raw packet
pub enum ParsedPacket {
    /// A router broadcasting its existence
    ApBeacon { bssid: String, ssid: String },
    /// A device actively communicating with a router
    ClientActivity { bssid: String, client_mac: String },
}

pub fn capture_packets(
    cap: &mut Capture<Active>,
    networks_arc: &Arc<Mutex<HashMap<String, AccessPoint>>>,
) {
    match cap.next_packet() {
        Ok(packet) => {
            if let Some(parsed) = process_packet(packet.data) {
                // Lock the Mutex only when we have data to write
                let mut networks = networks_arc.lock().unwrap();

                match parsed {
                    ParsedPacket::ApBeacon { bssid, ssid } => {
                        // Insert or update the AP
                        networks
                            .entry(bssid.clone())
                            .and_modify(|ap| {
                                ap.beacon_count += 1;
                                // If we previously inferred this AP from client traffic,
                                // update its SSID now that we have a real Beacon!
                                if ap.ssid == "<Unknown>" && ssid != "<Hidden>" {
                                    ap.ssid = ssid.clone();
                                }
                            })
                            .or_insert_with(|| {
                                AccessPoint {
                                    bssid,
                                    ssid,
                                    beacon_count: 1,
                                    clients: HashMap::new(), // Initialize empty client map
                                }
                            });
                    }
                    ParsedPacket::ClientActivity { bssid, client_mac } => {
                        // 1. Fetch the AP, or create a placeholder if we haven't seen it yet
                        let ap = networks.entry(bssid.clone()).or_insert_with(|| {
                            AccessPoint {
                                bssid: bssid.clone(),
                                ssid: "<Unknown>".to_string(), // We don't know this until a beacon arrives
                                beacon_count: 0,
                                clients: HashMap::new(),
                            }
                        });

                        // 2. Now insert or update the client within that AP
                        ap.clients
                            .entry(client_mac.clone())
                            .and_modify(|client| client.packet_count += 1)
                            .or_insert_with(|| Client {
                                mac: client_mac,
                                packet_count: 1,
                            });
                    }
                }
            }
        }
        Err(pcap::Error::TimeoutExpired) => {
            // Timeouts are normal, just unblocks the loop
        }
        Err(e) => {
            eprintln!("[-] Capture error: {:?}", e);
            return;
        }
    }
}

fn process_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 4 {
        return None;
    }
    let rtap_len = u16::from_le_bytes([packet[2], packet[3]]) as usize;
    if packet.len() <= rtap_len {
        return None;
    }
    let wifi_data = &packet[rtap_len..];

    let frame = match libwifi::parse_frame(wifi_data, false) {
        Ok(f) => f,
        Err(_) => return None,
    };

    match frame {
        // ==========================================
        // 1. AP Discovery (Frames containing SSIDs)
        // ==========================================
        Frame::Beacon(f) => Some(ParsedPacket::ApBeacon {
            bssid: f.header.address_3.to_string(),
            ssid: f.station_info.ssid(),
        }),
        Frame::ProbeResponse(f) => {
            // Probe Responses are essentially directed Beacons sent back to a client.
            Some(ParsedPacket::ApBeacon {
                bssid: f.header.address_3.to_string(),
                ssid: f.station_info.ssid(),
            })
        }

        // ==========================================
        // 2. Management & Auth (Map Clients to APs)
        // ==========================================
        Frame::AssociationRequest(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),
        Frame::AssociationResponse(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),
        Frame::ReassociationRequest(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),
        Frame::ReassociationResponse(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),
        Frame::Authentication(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),
        Frame::Deauthentication(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),
        Frame::Action(f) => extract_mgmt_activity(
            &f.header.address_1,
            &f.header.address_2,
            &f.header.address_3,
        ),

        // Probe requests are broadcasted by clients looking for APs.
        // We ignore them here because they don't usually give us a solid AP<->Client link.
        Frame::ProbeRequest(_) => None,

        // ==========================================
        // 3. Control Frames (Not enough info)
        // ==========================================
        // Control frames usually only have 1 or 2 MAC addresses and no BSSID context.
        Frame::Rts(_) => None,
        Frame::Cts(_) => None,
        Frame::Ack(_) => None,
        Frame::BlockAckRequest(_) => None,
        Frame::BlockAck(_) => None,

        // ==========================================
        // 4. Data Frames (Map Clients to APs)
        // ==========================================
        // All of these share the exact same Header structure containing Frame Control flags.
        Frame::Data(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::QosData(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::NullData(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::QosNull(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),

        Frame::DataCfAck(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::DataCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::DataCfAckCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::CfAck(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::CfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::CfAckCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),

        Frame::QosDataCfAck(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::QosDataCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::QosDataCfAckCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::QosCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
        Frame::QosCfAckCfPoll(f) => extract_data_activity(
            &f.header.frame_control,
            &f.header.address_1,
            &f.header.address_2,
        ),
    }
}

/// Extracts Client/AP relationships from standard Data frames using the ToDS and FromDS direction flags.
fn extract_data_activity(
    fc: &FrameControl,
    addr1: &MacAddress,
    addr2: &MacAddress,
) -> Option<ParsedPacket> {
    let a1 = addr1.to_string();
    let a2 = addr2.to_string();

    // Ignore broadcast frames (like ARP requests)
    if a1 == "ffffffffffff" || a2 == "ffffffffffff" {
        return None;
    }

    if fc.to_ds() && !fc.from_ds() {
        // Client uploading to AP. Addr1 = AP (Receiver), Addr2 = Client (Transmitter)
        Some(ParsedPacket::ClientActivity {
            bssid: a1,
            client_mac: a2,
        })
    } else if !fc.to_ds() && fc.from_ds() {
        // AP downloading to Client. Addr1 = Client (Receiver), Addr2 = AP (Transmitter)
        Some(ParsedPacket::ClientActivity {
            bssid: a2,
            client_mac: a1,
        })
    } else {
        // Ad-hoc, Mesh, or malformed, ignore for now
        None
    }
}

/// Extracts Client/AP relationships from Management/Auth frames.
/// In Management frames, Address 3 is almost always the BSSID.
fn extract_mgmt_activity(
    addr1: &MacAddress,
    addr2: &MacAddress,
    addr3: &MacAddress,
) -> Option<ParsedPacket> {
    let a1 = addr1.to_string();
    let a2 = addr2.to_string();
    let bssid = addr3.to_string();

    // Ignore broadcast frames (like a router indiscriminately deauthing everything)
    if a1 == "ffffffffffff" || a2 == "ffffffffffff" {
        return None;
    }

    if a2 == bssid {
        // Addr2 is the AP. Therefore, the AP is sending a packet to the Client (Addr1)
        Some(ParsedPacket::ClientActivity {
            bssid,
            client_mac: a1,
        })
    } else if a1 == bssid {
        // Addr1 is the AP. Therefore, the Client (Addr2) is sending a packet to the AP
        Some(ParsedPacket::ClientActivity {
            bssid,
            client_mac: a2,
        })
    } else {
        None
    }
}
