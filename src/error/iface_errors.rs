#[derive(Debug)]
#[allow(dead_code)]
pub struct MonitorModeError {
    msg: String,
}

impl From<std::string::String> for MonitorModeError {
    fn from(value: std::string::String) -> Self {
        Self { msg: value }
    }
}

impl From<&str> for MonitorModeError {
    fn from(value: &str) -> Self {
        Self {
            msg: String::from_utf8_lossy(value.as_bytes()).to_string(),
        }
    }
}

impl From<pcap::Error> for MonitorModeError {
    fn from(value: pcap::Error) -> Self {
        Self {
            msg: format!("{:?}", value),
        }
    }
}
