use std::io::{self, ErrorKind};
use std::net::{TcpStream, SocketAddr, Ipv4Addr};
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // Added Copy, PartialEq, Eq, Hash for use in HashSet
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
        
        // Attempt a TCP connection with a timeout of 3 seconds.
        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(_) => ScanResult::Open, // If connection is successful, port is open.
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => ScanResult::Closed, // Connection refused means the port is closed.
                // TimedOut could be filtered or simply a very slow host.
                // For a connect scan, it often indicates a firewall dropping packets (filtered).
                ErrorKind::TimedOut => ScanResult::Filtered, 
                // Other errors like NetworkUnreachable, HostUnreachable, etc.,
                // also typically indicate filtering or a down host.
                _ => ScanResult::Unknown, 
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

// --- New code for scanner logic ---

// Struct to hold information about a detected open port
#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub state: ScanResult,
    pub service: &'static str,
}

// Function to calculate a simple subnet range from an IP and a prefix length
fn get_subnet_range(ip: Ipv4Addr, prefix_len: u8) -> (Ipv4Addr, Ipv4Addr) {
    let ip_u32 = u32::from(ip);
    let mask_u32 = !((1u32 << (32 - prefix_len)) - 1);
    let network_address = Ipv4Addr::from(ip_u32 & mask_u32);
    let broadcast_address = Ipv4Addr::from(ip_u32 | !mask_u32);
    (network_address, broadcast_address)
}

fn main() {
    // --- Configuration for your LAN scan ---
    // IMPORTANT: Replace with your actual local IP and subnet prefix length.
    // Example: If your IP is 192.168.1.100 and your subnet mask is 255.255.255.0,
    // then local_ip = Ipv4Addr::new(192, 168, 1, 100) and subnet_prefix_len = 24.
    let local_ip = Ipv4Addr::new(192, 168, 1, 100); 
    let subnet_prefix_len = 24; 

    let (network_addr, broadcast_addr) = get_subnet_range(local_ip, subnet_prefix_len);

    println!("Scanning subnet from {} to {}", network_addr, broadcast_addr);
    println!("Please ensure your firewall allows outbound connections for this scan.");
    println!("Scanning may take some time depending on the subnet size and timeout settings.");

    let common_ports = vec![
        22,    // SSH
        80,    // HTTP
        443,   // HTTPS
        21,    // FTP
        23,    // Telnet
        25,    // SMTP
        53,    // DNS (TCP, though UDP is more common for queries)
        110,   // POP3
        135,   // RPC
        139,   // NetBIOS Session Service
        445,   // SMB (Microsoft-DS)
        3389,  // RDP
        5900,  // VNC
        8080,  // HTTP Alt
        8443,  // HTTPS Alt
        8000,  // HTTP Alt
    ];

    let all_scan_results = Arc::new(Mutex::new(Vec::new()));
    let detected_ips = Arc::new(Mutex::new(HashSet::new())); // To keep track of unique IPs found

    let mut handles = vec![];

    let start_ip_u32 = u32::from(network_addr);
    let end_ip_u32 = u32::from(broadcast_addr);

    // Limit concurrency to avoid overwhelming the system or network
    let max_concurrent_scans = 200; // Increased for potentially faster scanning, adjust as needed
    let (tx, rx) = std::sync::mpsc::channel();


    let scan_strategy = Arc::new(TcpConnectScan); // Create one instance of the strategy

    for i in start_ip_u32..=end_ip_u32 {
        let ip_to_scan = Ipv4Addr::from(i);
        
        // Skip network address, broadcast address, and the scanner's own IP
        if ip_to_scan == network_addr || ip_to_scan == broadcast_addr || ip_to_scan == local_ip {
            continue; 
        }

        let ports_to_scan = common_ports.clone(); // Clone ports for each thread
        let all_scan_results_clone = Arc::clone(&all_scan_results);
        let detected_ips_clone = Arc::clone(&detected_ips);
        let tx_clone = tx.clone();
        let current_scan_strategy = Arc::clone(&scan_strategy); // Clone Arc for strategy

        let handle = thread::spawn(move || {
            let ip_str = ip_to_scan.to_string();
            let mut found_open_on_ip = false;

            for port in ports_to_scan {
                let result = current_scan_strategy.scan(&ip_str, port);
                
                if result == ScanResult::Open {
                    found_open_on_ip = true;
                    let service = get_service_name(port);
                    let scan_result_entry = PortScanResult {
                        ip: ip_to_scan,
                        port: port,
                        state: result,
                        service: service,
                    };
                    all_scan_results_clone.lock().unwrap().push(scan_result_entry);
                    detected_ips_clone.lock().unwrap().insert(ip_to_scan);
                }
            }
            // Signal that this IP scan is complete
            tx_clone.send(()).unwrap();
        });
        handles.push(handle);

        // rudimentary rate limiting: if we have too many active threads, wait for one to finish
        if handles.len() >= max_concurrent_scans {
            // Wait for one task to complete to free up a slot
            rx.recv().unwrap();
            // This does not clean up the `handles` vector, but it ensures we don't
            // spawn too many threads and exhaust system resources.
        }
    }

    // Wait for all remaining threads to complete
    drop(tx); // Close the sending half of the channel
    while let Ok(_) = rx.recv() {} // Consume all remaining messages

    println!("\n--- Scan Complete ---");
    let results = all_scan_results.lock().unwrap();
    let unique_detected_ips: Vec<Ipv4Addr> = detected_ips.lock().unwrap().iter().cloned().collect();

    if unique_detected_ips.is_empty() {
        println!("No active devices with open TCP ports found in the specified subnet.");
    } else {
        println!("\nSummary of detected devices with open ports:");
        for ip in &unique_detected_ips {
            println!("Host: {}", ip);
            for res in results.iter().filter(|r| r.ip == *ip) {
                println!("  Port: {:<5} ({}) -> {}", res.port, res.service, res.state.to_state());
            }
            println!("--------------------");
        }

        println!("\nTotal unique active hosts found: {}", unique_detected_ips.len());
    }
}