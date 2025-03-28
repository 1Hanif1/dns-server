import socket, glob, json

# Default DNS port is 53
port = 53

# Local Host
local_host = '127.0.0.1'

# AF_INET -> Using IPv4
# SOCK_DGRAM -> Tells Socket that we want to use UDP and not TCP 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((local_host, port))

def load_zones():
  json_zone = {}
  zone_files = glob.glob('zones/*.zone')
  for zone in zone_files:
     with open(zone) as zone_data:
        data = json.load(zone_data)
        zone_name = data['$origin']
        json_zone[zone_name] = data
  return json_zone
 
zone_data = load_zones()

def get_domain(data):
    domain_parts = []
    offset = 12  # Start of question section
    
    while True:
        length = data[offset]
        if length == 0:
            break
        offset += 1
        domain_parts.append(data[offset:offset+length].decode('ascii'))
        offset += length

    question_type = data[offset+1:offset+3]  # Question type (2 bytes)
    return (domain_parts, question_type)

def get_zone(domain_parts):
  global zone_data
  zone_name = '.'.join(domain_parts)+"."
  return zone_data[zone_name] if zone_name in zone_data else None


def get_records(data):
  domain_parts, question_type = get_domain(data)
  QT = ''
  if question_type == b'\x00\x01':
    QT = 'a' # Query Type

  zone = get_zone(domain_parts)
  return (zone[QT], QT, domain_parts)

def record_to_bytes(domain_parts, record_type, record_ttl, record_value):
  # Convert the record to bytes
  record_bytes = b''


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

def build_question(domain_parts, record_type):
  QBYTES = b''
  for part in domain_parts:
    part_bytes = bytes([len(part)]) + part.encode('ascii')
    QBYTES += part_bytes
  QBYTES += b'\x00' # End of domain name
  
  if record_type == 'a':
      QBYTES += b'\x00\x01' # Type A (Host Address)
  
  QBYTES += b'\x00\x01' # Class IN (Internet)
  return QBYTES
  

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
  PACKET_ID = data[0:2]
  # response_TID = ''.join(hex(byte)[2:] for byte in transaction_id)
  FLAGS = get_flags(data[2:4])
  # Question Count
  QDCOUNT = b'\x00\x01' # 2 Bytes
  # get_domain(data) # 12 Bytes is the start of the domain name
  records, record_type, domain_parts = get_records(data)
  A_RECORDS = records[0]
  # Answer Count
  ANCOUNT = len(A_RECORDS).to_bytes(2, byteorder='big')
  # Nameserver Count
  NSCOUNT = b'\x00\x00' # 2 Bytes
  # Additional Count
  ARCOUNT = b'\x00\x00' # 2 Bytes
  DNS_HEADER = PACKET_ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

  DNS_BODY = b''
  DNS_QUESTION = build_question(domain_parts, record_type)
  
  for record in records:
    DNS_BODY += record_to_bytes(domain_parts, record_type, record['ttl', record['value']])
  print(DNS_QUESTION)


while True:
  data, addr = sock.recvfrom(512) # Check rfc1035.txt for details, 512 Bytes
  response = build_response(data)
  sock.sendto(response, addr)