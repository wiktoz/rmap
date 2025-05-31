use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

mod ip_range;
mod parallel_scanner;
mod strategy;
mod constants;

use crate::ip_range::IpRange;
use crate::parallel_scanner::ParallelScanner;
use crate::strategy::{TcpConnectScan, UdpScan};

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

#[pyclass]
pub struct PyScanResult {
    // Wrap your ScanResults here, or just a placeholder
    inner: crate::parallel_scanner::ScanResults,
}

#[pymethods]
impl PyScanResult {
    #[getter]
    pub fn active_hosts(&self) -> usize {
        self.inner.active_hosts
    }
    #[getter]
    pub fn scanned_hosts(&self) -> usize {
        self.inner.scanned_hosts
    }
    #[getter]
    pub fn duration_secs(&self) -> f64 {
        self.inner.duration.as_secs_f64()
    }
}

#[pyfunction]
/// Scans a range of IP addresses for open ports.
///
/// Args:
///     ip_range_str (str): IP range to scan, e.g. "192.168.1.1-192.168.1.255".
///     scan_type (Optional[str]): Type of scan: "T" for TCP (default), "U" for UDP.
///     ports (Optional[str]): Comma-separated list of ports to scan, e.g. "22,80,443".
///                            If empty or None, scans default ports.
///     threads (Optional[int]): Number of concurrent threads to use (default 256).
///
/// Returns:
///     PyScanResult: An object containing scan results summary.
///
/// Raises:
///     ValueError: If any input is invalid, such as bad IP range or ports.
fn scan(
    ip_range_str: &str,
    scan_type: Option<&str>,
    ports: Option<&str>,
    threads: Option<usize>,
) -> PyResult<PyScanResult> {
    let ports = ports.unwrap_or("");
    let ports = parse_ports(ports).map_err(|e| PyValueError::new_err(e))?;

    let ip_range = IpRange::parse(ip_range_str).map_err(|e| PyValueError::new_err(e))?;

    let threads = threads.unwrap_or(256);

    let scan_type = scan_type.unwrap_or("T").to_uppercase();

    let scanner = match scan_type.as_str() {
        "T" => ParallelScanner::new(TcpConnectScan, threads),
        "U" => ParallelScanner::new(UdpScan, threads),
        other => return Err(PyValueError::new_err(format!(
            "Invalid scan type '{}'. Use 'T' or 'U'.", other
        ))),
    };

    let results = scanner.scan(ip_range, ports);

    Ok(PyScanResult { inner: results })
}

#[pymodule]
fn rmap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_class::<PyScanResult>()?;
    Ok(())
}
