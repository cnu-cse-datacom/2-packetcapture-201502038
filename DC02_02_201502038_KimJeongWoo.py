import socket
import struct

def parsing_ip_header(data):
    ip_header = struct.unpack("!6c6c2cccHHHccHccccccccHHIIHHHH",data)
    ether_src = convert_ip_address(ip_header[0:6])
    ether_dest = convert_ip_address(ip_header[6:12])
    ip_head = "0x"+convert_ip_address(ip_header[12:13])
    ip_version = int(convert_ip_address(ip_header[14:15]),16) >> 4
    ip_HLEN = int(convert_ip_address(ip_header[14:15]),16) & 0xf
    differentiated_service_codepoint = int(convert_ip_address(ip_header[15:16]),16) >> 2 
    Explicit_Congestion_Notification = int(convert_ip_address(ip_header[15:16]),16) & 0x11
    total_length = convert_ip_int(ip_header[16:17])
    Identification = convert_ip_int(ip_header[17:18])
    flag = convert_hex(ip_header[18:19])
    Reserved_bit = (int(flag,16) >> 15) & 0x1
    not_fragment = (int(flag,16) >> 14) & 0x1
    fragments = (int(flag,16) >> 13) & 0x1
    fragments_offset = int(flag,16) & 0x1fff
    Time_to_live = convert_ip_address(ip_header[19:20])
    Protocol = convert_ip_address(ip_header[20:21])  
    Header_checksum = convert_hex(ip_header[21:22])
    source_ip = convert_ip(ip_header[22:26])
    dest_ip = convert_ip(ip_header[26:30])
    #tcp_parsing
    source_port = convert_ip_int(ip_header[30:31])
    dest_port = convert_ip_int(ip_header[31:32])
    sequence_number = convert_ip_int(ip_header[32:33])
    udp_length = sequence_number >> 16
    udp_check = sequence_number & 0xff
    acknowledgment = convert_ip_int(ip_header[33:34])
    header_length = int(convert_hex(ip_header[34:35]),16) >> 12
    _flag = hex(int(convert_hex(ip_header[34:35]),16) & 0xfff)
    Reserved = ((int(_flag,16)) >> 9) & 0x111
    Nonce = ((int(_flag,16)) >> 8) & 0x1
    CWR = ((int(_flag,16)) >> 7) & 0x1
    ECN = ((int(_flag,16)) >> 6) & 0x1
    URG = ((int(_flag,16)) >> 5) & 0x1
    ACK = ((int(_flag,16)) >> 4) & 0x1
    PUSH = ((int(_flag,16)) >> 3) & 0x1
    Reset = ((int(_flag,16)) >> 2) & 0x1
    SYN = ((int(_flag,16)) >> 1) & 0x1
    FIN = int(_flag,16) & 0x1
    window = convert_ip_int(ip_header[35:36])
    checkSum = convert_ip_int(ip_header[36:37])
    urgentpointer = convert_ip_int(ip_header[37:38])
   
    print("===============ETH===============")
    print("src_mac_address: ",ether_src)
    print("dest_mac_address: ",ether_dest)
    print("IP Header: ",ip_head)
    print("===============IPH===============")
    print("ip_version: ",ip_version)
   
    print("ip_HLEN: ",ip_HLEN)
   
    print("differentiated_service_codepoint: ",differentiated_service_codepoint)   
    print("Explicit_Congestion_Notification: ",Explicit_Congestion_Notification)

    print("Total Length: ",total_length)    
    
    print("Identification: ",Identification)
    
    print("Flag: ",flag)
    
    print("Reserved_bit: ",Reserved_bit)
    print("not_fragment: ",not_fragment)
    print("fragments: ",fragments)
    print("fragments_offset: ",fragments_offset)
    print("Time_to_live: ",Time_to_live)
    print("Protocol",int(Protocol,16))
    print("Header_checksum",Header_checksum)
    print("source_ip: ",source_ip)
    print("dest_ip: ",dest_ip)

    if int(Protocol) == 6 :
        print("===============tcp===============")
        print("source_poert: ",source_port)
        print("dest_port",dest_port)
        print("sequence_number: ",sequence_number)
        print("acknowledgment: ",acknowledgment)
        print("header_length: ",header_length)
        print("Flag: ",_flag)
        print("reserved: ",Reserved)
        print("Nonce: ",Nonce)
        print("CWR: ",CWR)
        print("ECN: ",ECN)
        print("URG: ",URG)
        print("ACK: ",ACK)
        print("push: ",PUSH)
        print("Reset: ",Reset)
        print("SYN: ",SYN)
        print("FIN: ",FIN)
        print("window: ",window)
        print("checkSum: ",checkSum)
        print("urgentPointer: ",urgentpointer)

    if int(Protocol) == 11 :
        print("===============UDP===============")
        print("source_port: ",source_port)
        print("dest_port: ",dest_port)
        print("UDP length: ",udp_length)
        print("UDP Checksum: ",udp_check)

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(i.hex())    
    ip_addr = ":".join(ip_addr)
    return ip_addr

def convert_byte(data):
    byte = list()
    for i in data:
        byte.append(i.hex())
    return byte

def convert_ip_int(data):
    ip_int = list()
    for i in data:
        ip_int.append(i)
    return ip_int[0]

def convert_hex(data):
    ip_flag = list()
    for i in data:
        ip_flag.append(i)
    return hex(ip_flag[0])

def convert_ip(data):
    ip = list()
    for i in data:
        ip.append(int(i.hex(),16))
    return ip

recv_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))

data = recv_socket.recvfrom(65565)
while True:
	parsing_ip_header(data[0][0:54])
