use comfy_table::{presets::NOTHING, Table};
use pnet::datalink::NetworkInterface;

pub fn print_interfaces(interfaces: &Vec<NetworkInterface>) {
    let mut table = Table::new();
    table.set_header(vec![
        "NAME",
        "MAC ADDRESS",
        "IS UP",
        "IS RUNNING",
        "DESCRIPTION",
    ]);

    table.load_preset(NOTHING);

    for interface in interfaces {
        table.add_row(vec![
            interface.name.clone(),
            interface.mac.unwrap().to_string(),
            interface.is_up().to_string(),
            interface.is_running().to_string(),
            interface.description.clone(),
        ]);
    }

    println!("{}", table);
}
