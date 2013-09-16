#!/usr/bin/env python

# Script for spoofing and re-sending syslog messages.

from socket import *
from scapy.all import IP,UDP,send

# Setup destination variable
destination = "192.168.0.33"

# Setup field that the source lies in
sourcefield = 3

# Setup UDP socket listening on port 514
sock = socket(AF_INET6, SOCK_DGRAM)
sock.bind(('', 514))

# Setup program loop for reading data from socket and forwarding \
# to destination spoofed as source as defined in message

while 1:
	# Read data from socket
	data, clientaddr = sock.recvfrom(4096)
	# Determine address to spoof based off of syslog message
	spoofedsource = gethostbyname("%s" %(data.split()[sourcefield]))
	# Try to send message back out with spoofed source in IP packet
	try:
		send(IP(src=spoofedsource, dst=destination)/UDP(sport=42114, dport=514)/data.rstrip())
	except Exception as e:
		raise
