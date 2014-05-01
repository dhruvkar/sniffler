#! /usr/bin/python

# Import necessary modules
import binascii
import struct
import socket
import os
import time
import calendar
import signal
import sys

def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s

def sniff(TIMEOUT):
    # Create a socket to use for sniffing. Allow it to receive packets with a max length of 2048 bytes.
    r = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    start = time.time()

    # Write MAC address, IP Address and Port number (for both, source and destination) in a file using a loop.
    while time.time()-start < TIMEOUT:
        # Create and receive a packet. Unpack packet and extract/format specific parts of the header.
        pkt = r.recvfrom(2048)
        # pkt = r.recvfrom(2048)
        eth_hdr = struct.unpack("!6s6s2s", pkt[0][0:14])
        src_mac = binascii.hexlify(eth_hdr[1])
        dst_mac = binascii.hexlify(eth_hdr[0])

        ip_hdr = struct.unpack("!12s4s4s", pkt[0][14:34])
        src_ip = socket.inet_ntoa(ip_hdr[1])
        dst_ip = socket.inet_ntoa(ip_hdr[2])

        tcp_hdr = struct.unpack("!HH16s", pkt[0][34:54])
        src_port = tcp_hdr[0]
        dst_port = tcp_hdr[1]

        mymonth = calendar.month_name[int(time.strftime("%m"))]
        myday = time.strftime("%d")
        myyear = time.strftime("%Y")
        mydate = mymonth + " " + myday + ", " + myyear
        mytime = time.strftime("%H" + ":" + "%M" + ":" + "%S")

        fi = open("traffic.log", "a")
        fi.write(mydate + " " + mytime + " | " + "Source: " + str(src_mac) + " " + str(src_ip) + " " + str(src_port) + " | " + "Destination: " + str(dst_mac) + " " + str(dst_ip) + " " + str(dst_port) + "\n")
        fi.close()


def inject():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#s.bind(("eth0", socket.htons(0x0003)))

	source_ip = raw_input("Enter a Source IP address: ")
	dest_ip = raw_input("Enter an Destination IP address: ")

	# ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0  
	ip_id = 54321   #Id of this packet
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_TCP
	ip_check = 0   
	ip_saddr = socket.inet_aton(source_ip)   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton(dest_ip)
	 
	ip_ihl_ver = (ip_ver << 4) + ip_ihl
	 
	# the ! in the pack format string means network order
	ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

	# tcp header fields
	tcp_source = raw_input("Enter a Source Port: ")   	#source port
	tcp_src = int(tcp_source)
	tcp_dest = raw_input("Enter a Destination Port: ")   	#destination port
	tcp_dst = int(tcp_dest)
	tcp_seq = 454
	tcp_ack_seq = 0
	tcp_doff = 5    		#4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags
	tcp_fin = 0
	tcp_syn = 1
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 0
	tcp_urg = 0
	tcp_window = socket.htons(5840)    # maximum window size
	tcp_check = 0
	tcp_urg_ptr = 0
	 
	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
	 
	# First packing of the TCP header. 
	tcp_header = struct.pack('!HHLLBBHHH' , tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

	user_data = "Hello, how are you" #raw_input("Enter data you would like to send: ")	
	
	# Format the addresses/parts of the header for the final pack
	source_address = socket.inet_aton(source_ip)
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header) + len(user_data)

	psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header + user_data
	tcp_check = checksum(psh)

	tcp_header = struct.pack('!HHLLBBH' , tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + struct.pack('H' , tcp_check) + struct.pack('!H' , tcp_urg_ptr)
	packet = ip_header + tcp_header + user_data

	s.sendto(packet, (dest_ip, 0))

sniff(5)
inject()
