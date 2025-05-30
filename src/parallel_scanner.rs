use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use crate::ip_range::IpRange;
use crate::strategy::{ScanResult, ScanStrategy, get_service_name};
use clap::{Command, Arg}; // Command from clap for CLI argument parsing
use std::process::Command as StdCommand;
use std::io;

#[derive(Debug)]
struct ScanTask {
    ip: Ipv4Addr,
    port: u16,
}

pub struct ParallelScanner {
    strategy: Arc<dyn ScanStrategy + Send + Sync>,
    num_workers: usize,
}

impl ParallelScanner {
    pub fn new(strategy: Arc<dyn ScanStrategy + Send + Sync>, num_workers: usize) -> Self {
        Self {
            strategy,
            num_workers,
        }
    }

    // Scan the IP range and ports
    pub fn scan(&self, ip_range: IpRange, ports: Vec<u16>) {
        let (tx, rx) = mpsc::channel::<ScanTask>();
        let rx = Arc::new(Mutex::new(rx));
        let results = Arc::new(Mutex::new(HashMap::<Ipv4Addr, Vec<(u16, ScanResult)>>::new()));

        let strategy = Arc::clone(&self.strategy);
        let num_workers = self.num_workers;

        let mut workers = Vec::new();
        for _ in 0..num_workers {
            let rx = Arc::clone(&rx);
            let strategy = Arc::clone(&strategy);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                loop {
                    let task_opt = {
                        let lock = rx.lock().unwrap();
                        lock.recv().ok()
                    };

                    match task_opt {
                        Some(task) => {
                            // Only proceed if the host is up
                            if !is_host_up(&task.ip) {
                                return; // Skip this host if it is not up
                            }

                            let result = strategy.scan(&task.ip.to_string(), task.port);

                            // Only record if the port is not closed
                            match result {
                                ScanResult::Closed => { /* skip closed ports */ }
                                ScanResult::Open | ScanResult::Filtered | ScanResult::Unknown => {
                                    let mut map = results.lock().unwrap();
                                    map.entry(task.ip)
                                        .or_default()
                                        .push((task.port, result));
                                }
                            }
                        }
                        None => break, // No more tasks
                    }
                }
            });

            workers.push(handle);
        }

        // Dispatch tasks to worker threads
        for ip in ip_range.iter() {
            for &port in &ports {
                tx.send(ScanTask { ip, port }).unwrap();
            }
        }

        drop(tx); // Close the sender channel
        for worker in workers {
            worker.join().unwrap();
        }

        // Now print the results in Nmap-like format
        let results = Arc::try_unwrap(results)
            .expect("Failed to unwrap Arc")
            .into_inner()
            .expect("Failed to unlock Mutex");

        for (ip, port_results) in results {
            self.print_nmap_report(ip, port_results);
        }
    }

    fn print_nmap_report(&self, ip: Ipv4Addr, port_results: Vec<(u16, ScanResult)>) {
        let latency = self.get_latency(&ip); // Latency function should be implemented here

        // Print header like Nmap
        println!("Nmap scan report for {} ({})", ip, ip);
        println!("Host is up ({:.3}s latency).\n", latency);
        println!("PORT    STATE    SERVICE");

        // Print port results
        for (port, result) in port_results {
            let state = result.to_state();
            let service = get_service_name(port);
            println!("{:<7}/tcp  {:<8} {}", port, state, service);
        }

        println!("\nNmap done: 1 IP address (1 host up) scanned in 1.0 seconds");
    }

    fn get_latency(&self, ip: &Ipv4Addr) -> f64 {
        // Simulate latency for simplicity
        // You can calculate the actual latency based on the TCP connect time.
        0.053
    }
}

// Check if the host is alive by attempting to connect to port 80 (or other common port).
fn is_host_up(ip: &Ipv4Addr) -> bool {
    // Run the ping command
    let output = StdCommand::new("ping")
        .arg("-c 1") // Send 1 ping request
        .arg(ip.to_string())
        .output();

    match output {
        Ok(output) if output.status.success() => true, // Host is up (ping successful)
        Ok(output) if is_filtered(&output) => false, // ICMP is filtered
        Ok(_) => false, // Host is unreachable (no device or no route)
        Err(_) => false, // Error during ping (e.g., no route)
    }
}

// Helper function to check if the ping response indicates that ICMP is filtered
fn is_filtered(output: &std::process::Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // If the ping result contains "Request timeout" or network errors, it's likely filtered
    stdout.contains("Request timeout") || stderr.contains("Network is unreachable")
}
