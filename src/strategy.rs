use std::io::{self, ErrorKind};
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

#[derive(Debug)]
pub enum ScanResult {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl ScanResult {
    // Converts the scan result to a human-readable string (state).
    pub fn to_state(&self) -> &'static str {
        match *self {
            ScanResult::Open => "open",
            ScanResult::Closed => "closed",
            ScanResult::Filtered => "filtered",
            ScanResult::Unknown => "unknown",
        }
    }
}

pub trait ScanStrategy: Send + Sync {
    // Scan the target IP and port.
    fn scan(&self, ip: &str, port: u16) -> ScanResult;
}

pub struct TcpConnectScan;

impl ScanStrategy for TcpConnectScan {
    fn scan(&self, ip: &str, port: u16) -> ScanResult {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        
        // Attempt a TCP connection with a timeout of 1 second.
        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(_) => ScanResult::Open, // If connection is successful, port is open.
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => ScanResult::Closed, // Connection refused means the port is closed.
                ErrorKind::TimedOut => ScanResult::Filtered, // Likely firewall or network filtering.
                _ => ScanResult::Unknown, // Other errors are considered unknown.
            }
        }
    }
}

// Helper function to map a port to its commonly known service name.
pub fn get_service_name(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        80 => "http",
        443 => "https",
        21 => "ftp",
        25 => "smtp",
        3306 => "mysql",
        6379 => "redis",
        8080 => "http-alt",
        1433 => "ms-sql-s",
        _ => "unknown", // Default to "unknown" for other ports.
    }
}
