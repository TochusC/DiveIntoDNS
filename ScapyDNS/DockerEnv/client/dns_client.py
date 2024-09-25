#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   dns_client.py    
@Contact :   tochus@163.com
@License :   (C)Copyright 2024

@Modify Time        @Author     @Version    @Description
----------------    --------    --------    -----------
25/9/2024 08:27     tochus      0.1         Freestyle
"""


from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

dns_query = IP(dst="10.10.8.3") / UDP(dport=25526)
dns_query /= DNS(id=1, qd=DNSQR(qname="baidu.com"))
ans = sr(dns_query)
print(ans[0][0])