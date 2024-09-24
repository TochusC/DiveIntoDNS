#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   dns_send.py    
@Contact :   
@License :   (C)Copyright 2021

@Modify Time        @Author     @Version    @Description
----------------    --------    --------    -----------
22/2/2022 10:35     idealeer    0.0         None
"""

cyberhawk

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

iface = "en0"

num = 100
time_str = time.strftime("%Y-%m-%d-%H-%M-%S")

# same src, same dst
index = 50000
for i in range(1, num + 1):
    dns_query = IP(src="192.168.3.66", dst="192.168.3.1") / UDP(sport=int(i + index), dport=int(53))
    dns_query /= DNS(id=i + index, qd=DNSQR(qname="src%d_dst%d_%s.com" % (1, 1, time_str)))
    send(dns_query, verbose=0, iface=iface)

time.sleep(5)

# # diff src, same dst
# index = 50001
# for i in range(1, num + 1):
#     dns_query = IP(src="192.168.%d.%d" % ((i + 2) / 256, (i + 2) % 256), dst="202.112.51.124") / UDP(
#         sport=int(i + index), dport=int(53))
#     dns_query /= DNS(id=i + index, qd=DNSQR(qname="src%d_dst%d_%s.com" % (num, 1, time_str)))
#     send(dns_query, verbose=0, iface=iface)
#
# time.sleep(5)
#
# # same src, diff dst
# index = 50002
# for i in range(1, num + 1):
#     dns_query = IP(src="192.168.1.2", dst="202.112.%d.%d" % ((i + 2) / 256, (i + 2) % 256)) / UDP(sport=int(i + index),
#                                                                                                   dport=int(53))
#     dns_query /= DNS(id=i + index, qd=DNSQR(qname="src%d_dst%d_%s.com" % (1, num, time_str)))
#     send(dns_query, verbose=0, iface=iface)
#
# time.sleep(5)
#
# # diff src, diff dst
# index = 50003
# for i in range(1, num + 1):
#     dns_query = IP(src="192.168.%d.%d" % ((i + 2) / 256, (i + 2) % 256),
#                    dst="202.112.%d.%d" % ((i + 2) / 256, (i + 2) % 256)) / UDP(sport=int(i + index),
#                                                                                dport=int(53))
#     dns_query /= DNS(id=i + index, qd=DNSQR(qname="src%d_dst%d_%s.com" % (num, num, time_str)))
#     send(dns_query, verbose=0, iface=iface)
