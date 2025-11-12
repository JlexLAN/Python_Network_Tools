import socket

def get_ip_address(domain_name):
    return socket.gethostbyname(domain_name)

domain_name = "willyramos.com"
ip_address = get_ip_address(domain_name)
print(f"The IP address of {domain_name} is {ip_address}")
