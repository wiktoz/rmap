from rmap import scan

scanner = scan("192.168.1.0/24", scan_type="T", threads=256)

print("=============")
print("Scan results")
print("=============")
print("")
print("Active hosts:", scanner.active_hosts)
print("Scanned hosts:", scanner.scanned_hosts)
print("Duration (secs):", scanner.duration_secs)
print("")

for ip, scan_results in scanner.results.items():
    print(f"Results for IP: {ip}")

    for res in scan_results:
        print(f"  Port: {res.port}, State: {res.state}, Service: {res.service}")