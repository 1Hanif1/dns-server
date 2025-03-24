import socket

# Default DNS port is 53
port = 53

# Local Host
local_host = '127.0.0.1'

# AF_INET -> Using IPv4
# SOCK_DGRAM -> Tells Socket that we want to use UDP and not TCP 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((local_host, port))

def get_flags(flags):
  byte1 = bytes(flags[:1])
  byte2 = bytes(flags[1:2])
  response_flags = ''
  QR = '1'
  OPCODE = ''.join(str(ord(byte1)&(1<<bit)) for bit in range(3,7))

def build_response(data):
  # Add the transaction/Packet ID to response
  transaction_id = data[0:2]
  response_TID = ''.join(hex(byte)[2:] for byte in transaction_id)
  flags = get_flags(data[2:4])

while True:
  data, addr = sock.recvfrom(512) # Check rfc1035.txt for details, 512 Bytes
  # print("Request Data in HEX", data)
  response = build_response(data)
  sock.sendto(response, addr)