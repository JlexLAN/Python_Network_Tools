import socket

def is_up(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    if s.connect_ex((addr, 135)) == 0:
        return True
    else:
        return False

ip_range = "192.168.0."
for i in range(1, 20):
    addr = ip_range + str(i)
    if is_up(addr):
        print(addr, "is up")
    else:
        print(addr, "is down")
