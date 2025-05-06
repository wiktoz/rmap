use std::net::Ipv4Addr;
use cidr::Ipv4Inet;
use ipnetwork::Ipv4Network;
use regex::Regex;

pub enum IpRange {
    Cidr(Ipv4Inet),
    Range { start: Ipv4Addr, end: Ipv4Addr }
}

impl IpRange {
    pub fn parse(s: &str) -> Result<IpRange, String> {
        if s.contains("/") {
            let cidr: Ipv4Inet = s.parse().map_err(|e| format!("CIDR parse error: {e}"))?;
            Ok(IpRange::Cidr(cidr))
        }
        else {
            let re = Regex::new(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$").unwrap();
            if let Some(caps) = re.captures(s) {
                let base = &caps[1];
                let start: u8 = caps[2].parse().map_err(|_| "Invalid start byte")?;
                let end: u8 = caps[3].parse().map_err(|_| "Invalid end byte")?;

                if start > end {
                    return Err("Invalid range".into());
                }

                let start_ip = format!("{}.{}", base, start).parse().unwrap();
                let end_ip = format!("{}.{}", base, end).parse().unwrap();

                Ok(IpRange::Range {
                    start: start_ip,
                    end: end_ip,
                })
            } else {
                Err("Invalid format".into())
            }
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = Ipv4Addr>> {
        match self {
            IpRange::Cidr(cidr) => {
                let network: Ipv4Network = cidr.to_string().parse().unwrap();
                Box::new(network.iter())
            },
            IpRange::Range {start, end} => {
                let start = u32::from(*start);
                let end = u32::from(*end);
                Box::new((start..=end).map(Ipv4Addr::from))
            }
        }
    }
}