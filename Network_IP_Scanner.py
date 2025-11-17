import subprocess
import ipaddress
import concurrent.futures
import time


def ping_ip(ip):

    #Return True if host responds to a ping request. 

    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False
    
def threaded_network_scan():
    print("Threaded Network Scanner (Ping)")
    subnet_input = input("Enter subnet in CIDR format (e.g. 192.168.1.0/24): ").strip()

    try:
        network = ipaddress.ip_network(subnet_input, strict=False)
    except:
        print("Invalid subnet format.")
        return
    
    hosts = list(network.hosts()) # list of IP objects
    if not hosts:
        print("No usable hosts in this subnet")
        return
    
    
    print(f"\nScanning {subnet_input} ...\n")
    print(f"Total hosts to scan: {len(hosts)}")

    try:


        max_workers = int(input("Max worker threads (default 100): ").strip() or "100")
        max_workers = max(1, min(500, max_workers))  # clamp between 1 and 500
    except ValueError:
        max_workers = 100

    start_time = time.time()
    active_hosts = []

    # Use a thread pool to ping multiple IPs at once
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(ping_ip, ip): ip for ip in hosts}

        try:
            for i, future in enumerate(concurrent.futures.as_completed(future_to_ip), start=1):
                ip = future_to_ip[future]
                try:
                    is_up = future.result()
                    if is_up:
                        print(f"🟢 Host up: {ip}")
                        active_hosts.append(str(ip))
                    else:
                        # comment this out if you don’t want to see downs
                        print(f"🔴 Host down: {ip}")
                except Exception as e:
                    print(f"Error checking {ip}: {e}")

                # simple progress indicator
                if i % 10 == 0 or i == len(hosts):
                    print(f"Progress: {i}/{len(hosts)} hosts scanned...", end="\r")

        except KeyboardInterrupt:
            print("\nScan interrupted by user. Stopping...")
            executor.shutdown(wait=False, cancel_futures=True)

    elapsed = time.time() - start_time

    print("\n\n--- Scan complete ---")
    print(f"Subnet: {subnet_input}")
    print(f"Hosts scanned: {len(hosts)}")
    print(f"Active hosts found: {len(active_hosts)}")
    if active_hosts:
        print("\nActive hosts:")
        for ip in active_hosts:
            print(f"  {ip}")
    print(f"\nTotal time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    threaded_network_scan()
   
    
    


