use std::io::ErrorKind;
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanResult {
    Open,
    Closed,
    Filtered,
    Unknown,
}

pub trait ScanStrategy: Send + Sync {
    fn scan(&self, ip: &str, port: u16) -> ScanResult;
}

pub struct TcpConnectScan;

impl ScanStrategy for TcpConnectScan {
    fn scan(&self, ip: &str, port: u16) -> ScanResult {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => ScanResult::Open,
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => ScanResult::Closed,
                ErrorKind::TimedOut => ScanResult::Filtered, 
                _ => ScanResult::Unknown, 
            }
        }
    }
}




pub struct UdpScan;

impl ScanStrategy for UdpScan {
    fn scan(&self, ip: &str, port: u16) -> ScanResult {
        use std::net::UdpSocket;
        use std::time::Duration;
        use std::net::SocketAddr;

        let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
            Ok(a) => a,
            Err(_) => return ScanResult::Unknown,
        };

        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return ScanResult::Unknown,
        };

        socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

        // Prepare payload
        let payload: &[u8] = if port == 53 {
            // Simple DNS query for "A" record for "example.com"
            &[
                0x12, 0x34, // Transaction ID
                0x01, 0x00, // Standard query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, // Answer RRs
                0x00, 0x00, // Authority RRs
                0x00, 0x00, // Additional RRs
                0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
                0x03, b'c', b'o', b'm', // "com"
                0x00, // Null terminator of domain name
                0x00, 0x01, // Type A
                0x00, 0x01, // Class IN
            ]
        } else {
            &[]
        };

        if let Err(_) = socket.send_to(payload, addr) {
            return ScanResult::Unknown;
        }

        let mut buf = [0u8; 1024];

        match socket.recv_from(&mut buf) {
            Ok((_size, _src)) => ScanResult::Open, // Got UDP response → open
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                ScanResult::Filtered // No response → filtered or host down
            }
            Err(_) => ScanResult::Unknown,
        }
    }
}