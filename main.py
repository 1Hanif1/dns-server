import socket

# Default DNS port is 53
port = 53

# Local Host
local_host = '127.0.0.1'

# AF_INET -> Using IPv4
# SOCK_DGRAM -> Tells Socket that we want to use UDP and not TCP 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((local_host, port))

# Flags: 0x0100 Standard query
#     0... .... .... .... = Response: Message is a query
#     .000 0... .... .... = Opcode: Standard query (0)
#     .... ..0. .... .... = Truncated: Message is not truncated
#     .... ...1 .... .... = Recursion desired: Do query recursively
#     .... .... .0.. .... = Z: reserved (0)
#     .... .... ...0 .... = Non-authenticated data: Unacceptable

def get_flags(flags):
  
  # BITS:  0  1  2  3  4  5  6  7
  # Flag: |QR|   Opcode  |AA|TC|RD|
  byte1 = bytes(flags[:1])
  
  # BITS:  0  1  2  3  4  5  6  7
  # Flag: |RA|   Z    |   RCODE   |
  byte2 = bytes(flags[1:2])
  response_flags = ''
  QR = '1' # value 1 means its a response and 0 means its a query
  # 1 in bits = 00000001
  # byte1 in bits = 0_0000_0_1_0
  OPCODE = ''.join(str(ord(byte1)&(1<<bit)) for bit in range(2,6))
  AA = '1' # Authoritative Answer
  TC = '0' # Truncated
  RD = '0' # Recursion Desired
  RA = '0' # Recursion Available
  Z = '000' # Reserved
  RCODE = '0000' # Response Code
  return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

#     The header contains the following fields:
#                                     1  1  1  1  1  1
#       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                      ID                       |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    QDCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    ANCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    NSCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#     |                    ARCOUNT                    |
#     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


# A Standard Request in DNS looks like this: (Checked using wireshark)
# Frame 33: 60 bytes on wire (480 bits), 60 bytes captured (480 bits) on interface \Device\NPF_Loopback, id 0
# Null/Loopback
# Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1
# User Datagram Protocol, Src Port: 63676, Dst Port: 53 (default DNS port)
# Domain Name System (query)
#     Transaction ID: 0x0003
#     Flags: 0x0100 Standard query
#     Questions: 1
#     Answer RRs: 0
#     Authority RRs: 0
#     Additional RRs: 0
#     Queries
def build_response(data):
  # Add the transaction/Packet ID to response (First 2 Bytes)
  transaction_id = data[0:2]
  response_TID = ''.join(hex(byte)[2:] for byte in transaction_id)
  flags = get_flags(data[2:4])
  print('flags: ', flags)

while True:
  data, addr = sock.recvfrom(512) # Check rfc1035.txt for details, 512 Bytes
  response = build_response(data)
  sock.sendto(response, addr)