use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Instant, Duration};
use crate::ip_range::IpRange;
use crate::strategy::{ScanResult, ScanStrategy};
use crate::constants::DEFAULT_SCAN_PORTS;

#[derive(Clone)]
#[allow(dead_code)]
pub struct PortScanResult {
    pub port: u16,
    pub state: ScanResult,
    pub service: &'static str,
}

type PortScanMap = HashMap<Ipv4Addr, Vec<PortScanResult>>;

#[allow(dead_code)]
pub struct ScanResults {
    pub results: HashMap<Ipv4Addr, Vec<PortScanResult>>,
    pub active_hosts: usize,
    pub scanned_hosts: usize,
    pub duration: Duration,
}

pub struct ParallelScanner {
    strategy: Arc<dyn ScanStrategy + Send + Sync>,
    num_workers: usize,
}

impl ParallelScanner {
    pub fn new<T>(strategy: T, num_workers: usize) -> Self 
    where T: ScanStrategy + Send + Sync + 'static {
        Self {
            strategy: Arc::new(strategy),
            num_workers,
        }
    }

    pub fn scan(&self, ip_range: IpRange, ports: Option<Vec<u16>>) -> ScanResults {
        let ports = Arc::new(ports.unwrap_or_else(|| DEFAULT_SCAN_PORTS.to_vec()));

        let results: Arc<Mutex<PortScanMap>> = Arc::new(Mutex::new(HashMap::new()));
        let (job_tx, job_rx) = mpsc::channel::<Ipv4Addr>();
        let job_rx = Arc::new(Mutex::new(job_rx));

        let start = Instant::now();

        let mut handles = Vec::with_capacity(self.num_workers);
        for _ in 0..self.num_workers {
            let job_rx = Arc::clone(&job_rx);
            let results = Arc::clone(&results);
            let strategy = Arc::clone(&self.strategy);
            let ports = Arc::clone(&ports);

            let handle = thread::spawn(move || {
                while let Ok(ip) = {
                    let lock = job_rx.lock().unwrap();
                    lock.recv()
                } {
                    let ip_str = ip.to_string();

                    let mut open_ports = Vec::new();
                    ports.iter().for_each(|&port| {
                        if strategy.scan(&ip_str, port) == ScanResult::Open {
                            open_ports.push(port);
                        }
                    });

                    if !open_ports.is_empty() {
                        let mut results_map = results.lock().unwrap();
                        let entry = results_map.entry(ip).or_insert_with(Vec::new);
                        for port in open_ports {
                            entry.push(PortScanResult {
                                port,
                                state: ScanResult::Open,
                                service: get_service_name(port),
                            });
                        }
                    }
                }
            });
            handles.push(handle);
        }

        for ip in ip_range.iter() {
            job_tx.send(ip).unwrap();
        }
        drop(job_tx);

        for handle in handles {
            handle.join().unwrap();
        }

        let duration = start.elapsed();
        let complete_results = results.lock().unwrap();

        ScanResults {
            results: complete_results.clone(),
            scanned_hosts: ip_range.len(),
            active_hosts: complete_results.len(),
            duration,
        }
    }
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        587 => "SMTP (TLS)",
        993 => "IMAPS",
        995 => "POP3S",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP Alt",
        8443 => "HTTPS Alt",
        _ => "Unknown",
    }
}
