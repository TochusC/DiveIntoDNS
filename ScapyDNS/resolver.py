#!/usr/bin/python3
from scapy.all import *

def query_dns(domain):
    # 构造DNS查询
    ip = IP(dst='127.0.0.1')  # 本机地址
    udp = UDP(dport=1003)       # DNS服务端口
    dns = DNS(rd=1, qd=DNSQR(qname=domain))
    query_pkt = ip/udp/dns
    
    send(query_pkt)

# 调用函数查询一个域名
flag = input('Press Enter \'y\' to query DNS\n')
while flag == 'y':
    query_dns('example.com')
    flag = input('Press Enter \'y\' to query DNS\n')
