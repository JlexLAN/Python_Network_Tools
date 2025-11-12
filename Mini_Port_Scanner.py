import socket

def scan_port(host, port, timeout=1.0):
    """Try to connect to a single port. Return True if open, False if closed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((host, port))  # 0 means success
        return result == 0

def mini_port_scanner():
    """Ask the user for a host and some ports, then scan them."""
    host = input("Enter a host/IP to scan (e.g. 127.0.0.1 or scanme.nmap.org): ").strip()

    ports_input = input("Enter ports to scan, separated by spaces (e.g. 21 22 80 443): ")
    try:
        ports = [int(p) for p in ports_input.split()]
    except ValueError:
        print("Invalid port list. Please enter numbers only.")
        return

    print(f"\nScanning {host} ...\n")
    open_ports = []

    for port in ports:
        is_open = scan_port(host, port)
        if is_open:
            print(f"✅ Port {port} is OPEN")
            open_ports.append(port)
        else:
            print(f"❌ Port {port} is closed")

    print("\n--- Scan complete ---")
    if open_ports:
        print("Open ports:", ", ".join(str(p) for p in open_ports))
    else:
        print("No open ports found.")

# run it
if __name__ == "__main__":
    mini_port_scanner()
