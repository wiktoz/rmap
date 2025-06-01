use std::io::ErrorKind;
use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use crate::parallel_scanner::PortStatus;

pub trait ScanStrategy: Send + Sync {
    fn scan(&self, ip: &str, port: u16) -> PortStatus;
}

/* Implementation of TCP Connect Scan */
pub struct TcpConnectScan;

impl ScanStrategy for TcpConnectScan {
    fn scan(&self, ip: &str, port: u16) -> PortStatus {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
        
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => PortStatus::Open,
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => PortStatus::Closed,
                ErrorKind::TimedOut => PortStatus::Filtered, 
                _ => PortStatus::Unknown, 
            }
        }
    }
}

/* Implementation of UdpScan */
pub struct UdpScan;

impl ScanStrategy for UdpScan {
    fn scan(&self, ip: &str, port: u16) -> PortStatus {
        use std::net::UdpSocket;
        use std::time::Duration;
        use std::net::SocketAddr;

        let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
            Ok(a) => a,
            Err(_) => return PortStatus::Unknown,
        };

        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return PortStatus::Unknown,
        };

        socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

        // DNS Request Payload
        let payload: &[u8] = if port == 53 {
            &[
                0x12, 0x34,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                0x03, b'c', b'o', b'm',
                0x00,
                0x00, 0x01,
                0x00, 0x01,
            ]
        } else {
            &[]
        };

        if let Err(_) = socket.send_to(payload, addr) {
            return PortStatus::Unknown;
        }

        let mut buf = [0u8; 1024];

        match socket.recv_from(&mut buf) {
            Ok((_size, _src)) => PortStatus::Open,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                PortStatus::Filtered
            }
            Err(_) => PortStatus::Unknown,
        }
    }
}