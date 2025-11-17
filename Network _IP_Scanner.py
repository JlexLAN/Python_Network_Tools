import subprocess
import ipaddress

def ping_ip(ip):

    #Return True if host responds to a ping request. 

    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "300", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False
    
def simple_network_scan():
    print("Simple Network Scanner (Ping)")
    subnet_input = input("Enter subnet in CIDR format (e.g. 192.168.1.0/24): ").strip()

    try:
        network = ipaddress.ip_network(subnet_input, strict=False)
    except:
        print("Invalid subnet format.")
        return
    
    print(f"\nScanning {subnet_input} ...\n")
    active_hosts = []

    for ip in network.hosts(): #skip network and broadcast addresses
        if ping_ip(ip):
            print(f"Host up: {ip}")
            active_hosts.append(str(ip))
        else:
            print(f"Host down: {ip}")

    print("\nScan complete.")
    print(f"Active hosts found: {len(active_hosts)}")
    if active_hosts:
        print("\n".join(active_hosts))

#Run
if __name__=="__main__":
    simple_network_scan()
    
    


