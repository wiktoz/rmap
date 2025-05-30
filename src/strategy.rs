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

impl ScanResult {
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