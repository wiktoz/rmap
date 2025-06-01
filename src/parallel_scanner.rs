use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Instant, Duration};
use std::fmt;
use crate::ip_range::IpRange;
use crate::strategy::ScanStrategy;
use crate::constants::DEFAULT_SCAN_PORTS;

use pyo3::prelude::*;


#[pyclass(module = "rmap")]
pub struct ScanResults {
    pub results: HashMap<Ipv4Addr, Vec<PortScanResult>>,
    pub active_hosts: usize,
    pub scanned_hosts: usize,
    pub duration: Duration,
}

#[pymethods]
impl ScanResults {
    #[getter]
    fn results(&self) -> HashMap<String, Vec<PortScanResult>> {
        self.results
            .iter()
            .map(|(ip, ports)| (ip.to_string(), ports.clone()))
            .collect()
    }

    #[getter]
    fn active_hosts(&self) -> usize {
        self.active_hosts
    }

    #[getter]
    fn scanned_hosts(&self) -> usize {
        self.scanned_hosts
    }

    #[getter]
    fn duration_secs(&self) -> f64 {
        self.duration.as_secs_f64()
    }

    fn __repr__(&self) -> String {
        format!(
            "<ScanResults active_hosts={}, scanned_hosts={}, duration={:.2}s>",
            self.active_hosts,
            self.scanned_hosts,
            self.duration_secs()
        )
    }

    fn ips(&self) -> Vec<String> {
        self.results.keys().map(|ip| ip.to_string()).collect()
    }
}


#[pyclass(module = "rmap")]
#[derive(Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub state: PortStatus,
    pub service: &'static str,
}

#[pymethods]
impl PortScanResult {
    #[getter]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[getter]
    pub fn state(&self) -> PortStatus {
        self.state.clone()
    }

    #[getter]
    pub fn service(&self) -> &str {
        self.service
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "<PortScanResult port={} state={} service='{}'>",
            self.port,
            self.state,
            self.service
        ))
    }
}

type PortScanMap = HashMap<Ipv4Addr, Vec<PortScanResult>>;

#[pyclass(eq, eq_int, module = "rmap")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PortStatus::Open => "Open",
            PortStatus::Closed => "Closed",
            PortStatus::Filtered => "Filtered",
            PortStatus::Unknown => "Unknown",
        };
        write!(f, "{}", s)
    }
}

#[pymethods]
impl PortStatus {
    fn __str__(&self) -> PyResult<String> {
        Ok(self.to_string())  // Uses Display impl
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("PortStatus::{}", self.to_string()))
    }
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
                        if strategy.scan(&ip_str, port) == PortStatus::Open {
                            open_ports.push(port);
                        }
                    });

                    if !open_ports.is_empty() {
                        let mut results_map = results.lock().unwrap();
                        let entry = results_map.entry(ip).or_insert_with(Vec::new);
                        for port in open_ports {
                            entry.push(PortScanResult {
                                port,
                                state: PortStatus::Open,
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
