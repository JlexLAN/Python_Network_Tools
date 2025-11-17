import subprocess
import ipaddress
import concurrent.futures
import time
import socket

# ---------- PING PHASE ----------

def ping_ip(ip):
    """Return True if host responds to a ping request (Windows)."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", str(ip)],  # 1 echo, 300ms timeout
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def discover_active_hosts(subnet_input, max_workers=100):
    """Threaded ping sweep. Returns list of active IPs as strings."""
    try:
        network = ipaddress.ip_network(subnet_input, strict=False)
    except ValueError:
        print("Invalid subnet format.")
        return []

    hosts = list(network.hosts())
    if not hosts:
        print("No usable hosts in this subnet.")
        return []

    print(f"\n[+] Scanning subnet {subnet_input} for live hosts ...")
    print(f"    Total hosts to scan: {len(hosts)}")

    active_hosts = []
    start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_ip, ip): ip for ip in hosts}

        try:
            for i, future in enumerate(concurrent.futures.as_completed(future_to_ip), start=1):
                ip = future_to_ip[future]
                try:
                    is_up = future.result()
                    if is_up:
                        print(f"🟢 Host up:   {ip}")
                        active_hosts.append(str(ip))
                    else:
                        # comment this out if you don't want to see downs
                        print(f"🔴 Host down: {ip}")
                except Exception as e:
                    print(f"Error checking {ip}: {e}")

                # simple progress indicator
                if i % 10 == 0 or i == len(hosts):
                    print(f"Progress: {i}/{len(hosts)} hosts scanned...", end="\r")
        except KeyboardInterrupt:
            print("\nPing sweep interrupted by user.")
            return []

    elapsed = time.time() - start
    print("\n\n[+] Host discovery complete.")
    print(f"    Active hosts found: {len(active_hosts)}")
    print(f"    Time taken: {elapsed:.2f} seconds\n")

    return active_hosts

# ---------- PORT SCAN PHASE ----------

def scan_port(host, port, timeout=1.0):
    """Return True if TCP port is open on host, else False."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))  # 0 = open
            return result == 0
    except Exception:
        return False


def parse_ports_simple(port_input):
    """
    Parse a simple list of ports like: '22 80 443'
    Returns a list of ints.
    """
    ports = []
    for token in port_input.split():
        ports.append(int(token))  # will raise ValueError if not int
    return ports


def scan_ports_for_host(host, ports, timeout=1.0):
    """Scan given ports on a single host. Returns list of open ports."""
    print(f"\n--- Port scan for {host} ---")
    open_ports = []
    for port in ports:
        is_open = scan_port(host, port, timeout=timeout)
        if is_open:
            print(f"  ✅ Port {port} is OPEN")
            open_ports.append(port)
        else:
            print(f"  ❌ Port {port} is closed")
    if open_ports:
        print(f"  Open ports on {host}: {', '.join(str(p) for p in open_ports)}")
    else:
        print(f"  No open ports found on {host}.")
    return open_ports

# ---------- MAIN GLUE ----------

def network_and_port_scanner():
    print("🕵️ Network Scanner + Per-Host Port Scan")
    print("⚠️ Only scan networks/hosts you are authorised to scan.\n")

    subnet_input = input("Enter subnet in CIDR format (e.g. 192.168.1.0/24): ").strip()
    try:
        max_workers = int(input("Max worker threads for ping (default 100): ").strip() or "100")
        max_workers = max(1, min(500, max_workers))
    except ValueError:
        max_workers = 100

    active_hosts = discover_active_hosts(subnet_input, max_workers=max_workers)

    if not active_hosts:
        print("No active hosts found. Exiting.")
        return

    # Ask which ports to scan on each active host
    print("\nNow choose which ports to scan on each active host.")
    print("Example: 22 80 443 3389")
    port_input = input("Enter ports separated by spaces: ").strip()

    try:
        ports = parse_ports_simple(port_input)
    except ValueError:
        print("Invalid port list. Please enter whole numbers only.")
        return

    try:
        timeout = float(input("TCP connect timeout in seconds (default 1.0): ").strip() or "1.0")
    except ValueError:
        timeout = 1.0

    # Port scan each active host
    print("\n[+] Starting per-host port scans...")
    summary = {}
    for host in active_hosts:
        open_ports = scan_ports_for_host(host, ports, timeout=timeout)
        summary[host] = open_ports

    # Final summary
    print("\n=== Final Summary ===")
    for host, open_ports in summary.items():
        if open_ports:
            print(f"{host}: open ports -> {', '.join(str(p) for p in open_ports)}")
        else:
            print(f"{host}: no scanned ports open.")

if __name__ == "__main__":
    network_and_port_scanner()
