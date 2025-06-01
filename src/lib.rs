use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

mod ip_range;
mod parallel_scanner;
mod strategy;
mod constants;

use crate::ip_range::IpRange;
use crate::parallel_scanner::{ParallelScanner, ScanResults, PortScanResult, PortStatus};
use crate::strategy::{TcpConnectScan, UdpScan};

/// Scans a range of IP addresses for open ports.
///
/// Args:
///     ip_range (str): IP range to scan, e.g. "192.168.1.1-192.168.1.255" or in CIDR format.
///     scan_type (Optional[str]): Type of scan: "T" for TCP (default), "U" for UDP.
///     ports (Optional[List[int]]): Comma-separated list of ports to scan, e.g. "22,80,443".
///                            If empty or None, scans default ports.
///     threads (Optional[int]): Number of concurrent threads to use (default 256).
///
/// Returns:
///     PyScanResult: An object containing scan results summary.
///
/// Raises:
///     ValueError: If any input is invalid, such as bad IP range or ports.
#[pyfunction]
#[pyo3(signature = (ip_range, scan_type=None, ports=None, threads=None))]
fn scan(
    ip_range: &str,
    scan_type: Option<&str>,
    ports: Option<Vec<u16>>,
    threads: Option<usize>,
) -> PyResult<ScanResults> {
    let ips = IpRange::parse(ip_range).map_err(|e| PyValueError::new_err(e))?;

    let threads = threads.unwrap_or(256);

    let scan_type = scan_type.unwrap_or("T").to_uppercase();

    let scanner = match scan_type.as_str() {
        "T" => ParallelScanner::new(TcpConnectScan, threads),
        "U" => ParallelScanner::new(UdpScan, threads),
        other => return Err(PyValueError::new_err(format!(
            "Invalid scan type '{}'. Use 'T' or 'U'.", other
        ))),
    };

    let results = scanner.scan(ips, ports);

    Ok(results)
}

#[pymodule]
fn rmap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_class::<ScanResults>()?;
    m.add_class::<PortScanResult>()?;
    m.add_class::<PortStatus>()?;
    Ok(())
}
