#!/usr/bin/env python

# Created by @catalyst256/catalyst256@gmail.com - May 2013
# Allows for recreation of pdf files from pcap files
# Usage is ./pdf-hunter.py <pcap file> <file location>
# e.g. ./pdf-hunter.py pdftest.pcap /tmp/out.pdf

import os, logging, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) != 3:
	print 'Usage is ./pdf-hunter.py <pcap file> <file location>'
	sys.exit(1)

pkts = rdpcap(sys.argv[1])

artifact = 'Content-Type: application/pdf'
ack = ''
cfile = []
start = str('%PDF-')
end = str('%%EOF')
tmpfile = '/tmp/tmp.pdf'
pdffile = sys.argv[2]
outfile = open(tmpfile, 'w')
outfile2 = open(pdffile, 'w')



# Search through pcap file and look for anything that has a content type of pdf, save the TCP ACK as a variable
for x in pkts:
	if x.haslayer(Raw):
		raw = x.getlayer(Raw).load
		if artifact in raw:
			ack = str(x.getlayer(TCP).ack)

# Search again through the pcap file this time using the ack as the key and then write the raw load to a list		
for p in pkts:
	if p.haslayer(TCP) and p.haslayer(Raw) and (p.getlayer(TCP).ack == int(ack) or p.getlayer(TCP).seq == int(ack)):
		raw = p.getlayer(Raw).load
		cfile.append(raw)

x = ''.join(cfile)

# Write the file out to outfile variable
outfile.writelines(x)
outfile.close()

# Open the temp file, cut the HTTP headers out and then save it again as a PDF
total_lines = ''
firstcut = ''
secondcut = ''
final_cut = ''

f = open(tmpfile, 'r').readlines()

total_lines = len(f)

for x, line in enumerate(f):
	if start in line:
		firstcut = int(x)


for y, line in enumerate(f):	
 	if end in line:
		secondcut = int(y) + 1

f = f[firstcut:]

if int(total_lines) - int(secondcut) != 0:
	final_cut = int(total_lines) - int(secondcut)
	f = f[:-final_cut]
	outfile2.writelines(f)
	outfile2.close()
else:
	outfile2.writelines(f)
	outfile2.close()

print '[+] File written to: ' + str(pdffile)

