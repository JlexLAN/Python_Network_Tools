import socket

def is_up(addr, port, family):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(1)
    if s.connect_ex((addr, port)) == 0:
        return True
    else:
        return False

ipv4_range = "192.168.0."
ipv6_range = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
for i in range(1, 16):
    addr = ipv4_range + str(i)
    if is_up(addr, 135, socket.AF_INET):
        print(addr, "is up")
    else:
        print(addr, "is down")

if is_up(ipv6_range, 135, socket.AF_INET6):
    print(ipv6_range, "is up")
else:
    print(ipv6_range, "is down")
