#!/usr/bin/env python3
"""
Mini Port Scanner (Presets + CSV/JSON export)
- Preset port ranges (well-known, web, common services) or custom lists/ranges
- Threads for speed
- Pretty console summary + file log
- Optional CSV and/or JSON export of results
"""

import socket
import concurrent.futures
import time
from datetime import datetime
import logging
import sys
import json
import csv

LOG_FILE = "port_scan_log.txt"

# ---------- logging setup ----------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
)
logger = logging.getLogger("port_scanner")
# -----------------------------------

# Small, practical “common services” preset
COMMON_SERVICES = [
    21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 2049, 2375, 2380, 2483, 2484,
    3000, 3306, 3389, 4444, 5432, 5601, 6379, 6443, 8000, 8008, 8080,
    8081, 8088, 8443, 9000, 9092, 9200, 9300
]
WEB_PRESET = [80, 443, 8000, 8080, 8081, 8088, 8443, 8888]

def parse_ports(port_input: str):
    """
    Accepts strings containing ports and ranges and returns a sorted unique list of ints.
    Supports "22 80 443", "21,22,23", "20-25" or any combination.
    """
    tokens = port_input.replace(",", " ").split()
    ports = set()
    for token in tokens:
        if "-" in token:
            try:
                start, end = token.split("-", 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                if start < 1 or end > 65535:
                    raise ValueError
                ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid range token: '{token}'")
        else:
            try:
                p = int(token)
                if p < 1 or p > 65535:
                    raise ValueError
                ports.add(p)
            except ValueError:
                raise ValueError(f"Invalid port token: '{token}'")
    return sorted(ports)

def scan_port(host: str, port: int, timeout: float = 1.0) -> tuple:
    """
    Attempt to connect to host:port.
    Returns (port, is_open:bool, err:str|None, elapsed_seconds:float)
    """
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((host, port))  # 0 == success
            elapsed = time.time() - start
            if code == 0:
                return (port, True, None, elapsed)
            else:
                return (port, False, None, elapsed)
    except Exception as e:
        elapsed = time.time() - start
        return (port, False, str(e), elapsed)

def scan_ports_concurrent(host: str, ports, timeout=1.0, max_workers=100):
    """
    Scan ports using a thread pool.
    Returns dict with keys: open (list of dicts), closed (list of dicts)
    """
    results_open = []
    results_closed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        try:
            for fut in concurrent.futures.as_completed(futures):
                p = futures[fut]
                try:
                    port, is_open, err, elapsed = fut.result()
                    if is_open:
                        print(f"[OPEN]   {port} (took {elapsed:.3f}s)")
                        results_open.append({"port": port, "elapsed": elapsed})
                    else:
                        print(f"[closed] {port} (took {elapsed:.3f}s)")
                        results_closed.append({"port": port, "error": err, "elapsed": elapsed})
                except Exception as exc:
                    print(f"[error]  {p} -> {exc}")
                    results_closed.append({"port": p, "error": str(exc), "elapsed": 0.0})
        except KeyboardInterrupt:
            print("\nScan interrupted by user. Shutting down threads...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise
    return {"open": results_open, "closed": results_closed}

def log_scan(host: str, ports, open_ports, elapsed_total):
    logger.info(f"Scan of {host} | ports: {len(ports)} | open: {len(open_ports)} | duration: {elapsed_total:.3f}s")
    if open_ports:
        logger.info("Open ports:")
        for item in sorted(open_ports, key=lambda x: x["port"]):
            logger.info(f" - {item['port']} (response {item['elapsed']:.3f}s)")
    logger.info("-" * 60)

def export_json(filename: str, metadata: dict, results: dict):
    data = {
        "metadata": metadata,
        "open": results["open"],
        "closed": results["closed"],
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"✅ JSON saved as {filename}")

def export_csv(filename: str, metadata: dict, results: dict):
    """
    Writes two CSV sections in one file:
    - A small metadata header (#-prefixed comment rows)
    - A table of results with columns: status, port, elapsed, error
    """
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # metadata as commented rows
        writer.writerow([f"# host: {metadata['host']}"])
        writer.writerow([f"# started_at: {metadata['started_at']}"])
        writer.writerow([f"# duration_sec: {metadata['duration_sec']:.3f}"])
        writer.writerow([f"# timeout: {metadata['timeout']}"])
        writer.writerow([f"# workers: {metadata['workers']}"])
        writer.writerow([f"# scanned_ports_count: {metadata['scanned_ports_count']}"])
        writer.writerow([])

        # header
        writer.writerow(["status", "port", "elapsed_seconds", "error"])
        for item in sorted(results["open"], key=lambda x: x["port"]):
            writer.writerow(["open", item["port"], f"{item['elapsed']:.3f}", ""])
        for item in sorted(results["closed"], key=lambda x: x["port"]):
            writer.writerow(["closed", item["port"], f"{item['elapsed']:.3f}", item.get("error") or ""])
    print(f"✅ CSV saved as {filename}")

def choose_preset_or_custom():
    print("\nPort selection:")
    print("1) Well-known ports (1–1024)")
    print("2) Common web ports (80, 443, 8000, 8080, 8081, 8088, 8443, 8888)")
    print("3) Common services (curated small list)")
    print("4) Custom (e.g. '22 80 443' or '1-1024' or '22,80,8000-8005')")
    choice = input("Choose 1–4: ").strip()
    if choice == "1":
        return list(range(1, 1025))
    elif choice == "2":
        return sorted(set(WEB_PRESET))
    elif choice == "3":
        return sorted(set(COMMON_SERVICES))
    else:
        port_input = input("Enter ports/ranges: ").strip()
        return parse_ports(port_input)

def main():
    print("Mini Port Scanner — Only scan machines you are authorised to scan.")
    host = input("Enter host or IP (e.g. 127.0.0.1): ").strip()
    if not host:
        print("No host provided. Exiting.")
        return

    # Resolve host to ensure valid target
    try:
        socket.gethostbyname(host)
    except Exception as e:
        print(f"Failed to resolve host '{host}': {e}")
        return

    # Choose ports by preset or custom input
    try:
        ports = choose_preset_or_custom()
    except ValueError as e:
        print(f"Port input error: {e}")
        return

    try:
        timeout = float(input("Socket timeout in seconds (default 1.0): ").strip() or "1.0")
    except ValueError:
        timeout = 1.0

    try:
        max_workers = int(input("Max worker threads (default 200): ").strip() or "200")
        max_workers = max(1, min(1000, max_workers))
    except ValueError:
        max_workers = 200

    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nScanning {host} on {len(ports)} ports (timeout {timeout}s, workers {max_workers})...\n")
    t0 = time.time()
    try:
        results = scan_ports_concurrent(host, ports, timeout=timeout, max_workers=max_workers)
    except KeyboardInterrupt:
        print("Scan aborted by user.")
        return
    elapsed = time.time() - t0

    open_ports = results["open"]

    # Summary
    print("\n--- Scan complete ---")
    print(f"Host: {host}")
    print(f"Scanned ports: {len(ports)}")
    print(f"Open ports: {len(open_ports)}")
    if open_ports:
        print("Open ports (port : response_time):")
        for item in sorted(open_ports, key=lambda x: x["port"]):
            print(f"  {item['port']} : {item['elapsed']:.3f}s")
    else:
        print("No open ports found.")
    print(f"Total time: {elapsed:.3f}s")

    # Log summary
    log_scan(host, ports, open_ports, elapsed)
    print(f"Summary appended to '{LOG_FILE}'")

    # Export options
    export = input("\nExport results? (n / csv / json / both): ").strip().lower()
    if export not in {"csv", "json", "both"}:
        print("No export requested.")
        return

    # Common metadata for exports
    safe_host = host.replace(":", "_").replace("/", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    metadata = {
        "host": host,
        "started_at": started_at,
        "duration_sec": elapsed,
        "timeout": timeout,
        "workers": max_workers,
        "scanned_ports_count": len(ports),
    }

    if export in {"csv", "both"}:
        export_csv(f"scan_{safe_host}_{stamp}.csv", metadata, results)
    if export in {"json", "both"}:
        export_json(f"scan_{safe_host}_{stamp}.json", metadata, results)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
