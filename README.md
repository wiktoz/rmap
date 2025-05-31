# RMap - nmap inspired scanner in Rust
*A fast and simple Rust-based port scanner inspired by Nmap for effortless network scanning.*

**author**: Wiktor Zawadzki\
**github**: https://github.com/wiktoz/rmap

## Features
- Multithreaded scanning for high performance and speed
- Supports multiple scan strategies
- Parses and scans various IP ranges and formats (single IPs, CIDR blocks, ranges)

## Usage
`./rmap.exe [-hv] [-p <ports>] [-pl <threads_number>] [ip_range]`

### Flags
`-h` **help** - prints help

`-p` **ports** - specify ports to scan separated with space

`-t` **threads** - specify number of threads used

`-s` **scan technique** - specify scan technique used, currently available:
- `T` - _TCP Connect_
- `U` - _UDP Scan_

`-V` **version** - prints installed rmap version

### Examples
Scan ports `21,22,80` on every host on network `192.168.1.0/24` using `TCP Connect` scan technique and parallelize the operation using up to `256` threads.

`./rmap.exe -p 21,22,80 -sT -t 256 192.168.1.0/24`