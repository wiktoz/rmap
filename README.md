# RMap - nmap inspired scanner in Rust
*A fast and simple Rust-based port scanner inspired by Nmap for effortless network scanning.*

**author**: Wiktor Zawadzki\
**github**: https://github.com/wiktoz/rmap

## Features
- Multithreaded scanning for high performance and speed
- Supports multiple scan strategies (e.g., TCP connect, SYN scan)
- Parses and scans various IP ranges and formats (single IPs, CIDR blocks, ranges)

## Usage
`./rmap.exe [-r] [-tedpnfm] [-h] [dir1 dir2 ...]`

### Flags
`-h` **help** - prints help

`-p` **ports** - specify ports to scan separated with space

`-pl` **parallel** - specify number of threads used

`-V` **version** - prints installed rmap version
