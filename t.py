#!/usr/bin/env python

import sys
from scapy.all import * 

#p=IP(dst="192.168.1.1")/ICMP()/"AAAAA"

# read in a pcap file and deco the packet

print "reading the file"
pkts = rdpcap("/home/herry/work/python/pcap/ipv4-smtp.cap")
print "done with reading file"

for p in pkts:
    print "%s" % p.show()
