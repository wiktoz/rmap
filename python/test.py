import rmap

result = rmap.scan("192.168.1.0/24", scan_type="U", threads=256)

print("Active hosts:", result.active_hosts)
print("Scanned hosts:", result.scanned_hosts)
print("Duration (secs):", result.duration_secs)