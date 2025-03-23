import socket

# Default DNS port is 53
port = 53

# Local Host
local_host = '127.0.0.1'

# AF_INET -> Using IPv4
# SOCK_DGRAM -> Tells Socket that we want to use UDP and not TCP 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((local_host, port))

while True:
  data, addr = sock.recvfrom(512) # Check rfc1035.txt for details, 512 Bytes
  print(data)