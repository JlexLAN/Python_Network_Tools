import socket

def is_port_open(host, port, proto):
    if proto == 'TCP':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif proto == 'UDP':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        raise ValueError("Invalid protocol")
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    if result == 0:
        return True
    else:
        return False

host = input("Enter the host to be scanned: ")
protocol = input("Enter the protocol to be used (TCP/UDP): ")
for port in range(20, 443):
    if is_port_open(host, port, protocol):
        print("Port {} is open on {}".format(port, protocol))
