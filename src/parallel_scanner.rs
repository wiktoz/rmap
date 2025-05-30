use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Instant;
use crate::ip_range::IpRange;
use crate::strategy::{ScanResult, ScanStrategy};
use crate::constants::DEFAULT_SCAN_PORTS;

struct PortScanResult {
    port: u16,
    state: ScanResult,
    service: &'static str,
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

    pub fn scan(&self, ip_range: IpRange, ports: Option<Vec<u16>>) {
        let ports = Arc::new(ports.unwrap_or_else(|| DEFAULT_SCAN_PORTS.to_vec()));

        let results: Arc<Mutex<HashMap<Ipv4Addr, Vec<PortScanResult>>>> = Arc::new(Mutex::new(HashMap::new()));
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

                    // Collect open ports for this IP locally
                    let mut open_ports = Vec::new();
                    ports.iter().for_each(|&port| {
                        if strategy.scan(&ip_str, port) == ScanResult::Open {
                            open_ports.push(port);
                        }
                    });

                    // Update the results map once per IP
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

        println!("");
        println!(
            "Done: {} IP addresses scanned ({} host/s up) in {:.2} seconds.",
            ip_range.len(),
            complete_results.len(),
            duration.as_secs_f64()
        );

        for (ip, port_results) in complete_results.iter() {
            println!("");
            println!("Scan report for {}:", ip);
            println!("PORT   STATE   SERVICE");

            for result in port_results {
                println!("{}/tcp   {}   {}", result.port, result.state.to_state(), result.service);
            }
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
