import socket
import struct
import textwrap
import time


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main(): #Operates in Linux via Python v3.x

    a = input("Name of file to output results: ")
    file = open(a,"w")
    HOST = socket.gethostbyname(socket.gethostname())

 

    # create a raw socket and bind it to the public interface

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    start = time.time()

    while True:

        raw_data, addr = conn.recvfrom(65565)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data, tcph_length = tcp_segment(data)
                diff = (time.time() - start)*1000 #converts to milliseconds
                #h_size = iph_length + tcph_length * 4
                data_size = len(raw_data) * 8
                print('Packet arrival time in milliseconds: %0.4fms'%diff)
                file.write('Packet arrival time in milliseconds: %0.4fms\n'%diff)
                print('Size of packet in bits: %s bits'%data_size)
                file.write('Size of packet in bits: %s bits\n'%data_size)
                print(TAB_1 + 'IPv4 Packet:')
                file.write(TAB_1 + 'IPv4 Packet:\n')
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
                file.write(TAB_2 + 'Protocol: {}, Source: {}, Target: {}\n'.format(proto, src, target))
                print(TAB_1 + 'TCP Segment:')
                file.write(TAB_1 + 'TCP Segment:\n')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}\n'.format(src_port, dest_port))
                file.write(TAB_2 + 'Source Port: {}, Destination Port: {}\n\n'.format(src_port, dest_port))

# Unpackets ethernet packet
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# return properly formatted MAC address {eg. AA:BB:CC:DD:EE:FF}
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Return properly formatted IPv4 address
def ipv4(addr):
    #x.y.z.v style formatting
    return '.'.join(map(str, addr))

# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags % 32) >> 5
    flag_ack = (offset_reserved_flags % 16) >> 5
    flag_psh = (offset_reserved_flags % 8) >> 5
    flag_rst = (offset_reserved_flags % 4) >> 5
    flag_syn = (offset_reserved_flags % 2) >> 5
    flag_fin = offset_reserved_flags & 1
    tcph_length = offset_reserved_flags >> 4
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:], tcph_length

# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
