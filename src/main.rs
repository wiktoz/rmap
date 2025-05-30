mod ip_range;
mod parallel_scanner;
mod strategy;  
mod constants;

use clap::{Command, Arg};

use crate::parallel_scanner::ParallelScanner;
use crate::strategy::{TcpConnectScan};
use crate::ip_range::IpRange;

fn parse_ports(s: &str) -> Result<Option<Vec<u16>>, String> {
    if s.trim().is_empty() {
        return Ok(None);
    }

    let mut ports = Vec::new();
    for part in s.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue; 
        }
        let port_num = trimmed.parse::<u16>()
            .map_err(|_| format!("Invalid port number: '{}'", trimmed))?;
        ports.push(port_num);
    }

    if ports.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ports))
    }
}

fn main() {
    let matches = Command::new("rmap")
        .version("1.0")
        .about("Scan hosts and ports")
        .arg(
            Arg::new("ip_range")
                .help("IP range to scan, e.g. 192.168.1.0/24 or 192.168.1.1-254")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .help("Comma separated list of ports to scan, e.g. 22,80,443")
        )
        .arg(
            Arg::new("parallel")
                .long("parallel")
                .help("Number of parallel threads")
                .default_value("256")
                .value_parser(clap::value_parser!(usize))
        )
        .get_matches();

    let ports_str = matches.get_one::<String>("ports").map(|s| s.as_str()).unwrap_or("");
    let ports = match parse_ports(ports_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing ports: {}", e);
            std::process::exit(1);
        }
    };

    let parallel = *matches.get_one::<usize>("parallel").unwrap();

    let ip_range_str = matches.get_one::<String>("ip_range").expect("IP Range is required");

    let scanner = ParallelScanner::new(TcpConnectScan, parallel);
    let ip_range = IpRange::parse(ip_range_str);

    match ip_range {
        Ok(range) => {
            println!("Scanning IP range ({} host/s)...", range.len());
            scanner.scan(range, ports);
        }
        Err(e) => {
            eprintln!("Error parsing IP range: {}", e);
            return;
        }
    }
    
}