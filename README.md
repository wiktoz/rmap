# RMap - nmap inspired scanner library for Python
*A fast and simple Rust-based port scanner inspired by Nmap for effortless network scanning.*

**author**: Wiktor Zawadzki\
**github**: https://github.com/wiktoz/rmap

## Features
- Multithreaded scanning for high performance and speed
- Supports multiple scan strategies
- Parses and scans various IP ranges and formats (single IPs, CIDR blocks, ranges)

## Build
In order to build a library use a script based on OS:
- `.\run\win.ps1` for Windows
- `./run/linux.sh` for UNIX

## Test
Simple file presenting library usage you can start using:

```bash 
python ./python.test.py
```

## API Reference

### Functions

```python
rmap.scan(ip_range: str, scan_type: Optional[str] = "T", ports: Optional[List[int]] = [22, 80, 443 ...], threads: Optional[int] = 256) -> ScanResults
```
**Arguments**

- **ip_range**: The IP range to scan, supports single IPs, CIDR notation, or ranges (e.g. "192.168.1.0/24", "10.0.0.1-10.0.0.255").

- **scan_type**: (Optional) Specify scan strategy. Possible scan strategies:
    - `T` - TCP Connect,
    - `U` - UDP Scan.

- **ports**: (Optional) List of ports to scan. Defaults to common ports if not specified.

- **threads**: (Optional) Number of worker threads to use. Defaults to 256.

**Return value**

- **ScanResults** object.

## Data types

**ScanResults**

- `.results` — dict mapping IP string to list of PortScanResult

- `.active_hosts` — number of hosts with at least one open port

- `.scanned_hosts` — total number of hosts scanned

- `.duration_secs` — scan duration in seconds

- `.ips()` — method returning list of scanned IPs as strings


**PortScanResult**

- `.port` — port number (int)

- `.state` — port state (PortStatus) — e.g. Open, Closed, Filtered

- `.service` — recognized service name (str), or "Unknown"

**PortStatus**

Enum of possible port states:

- `Open`

- `Closed`

- `Filtered`

- `Unknown`