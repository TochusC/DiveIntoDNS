from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.inet import IP, UDP, TCP
from datetime import datetime
import base64

# 配置DNS服务器的IP和端口
IFACE_LAN = "eth0"
PORT_OF_SERVER = "53"
DOMAIN_NAME = ["www.keytrap.test.", "keytrap.test.", "ns1.keytrap.test.", "_ta-75b2.keytrap.test."]

BPF_FILTER = "udp port "  + str(PORT_OF_SERVER) + " or tcp port " + str(PORT_OF_SERVER)

# 每次签名都必须更新以下条目：INCEPTION, EXPIRATION, RRSIG
GLOBAL_TTL = 86400
INCEPTION = datetime.strptime("20240928101351", "%Y%m%d%H%M%S").timestamp() + 3600 * 8
EXPIRATION = datetime.strptime("20241028101351", "%Y%m%d%H%M%S").timestamp() + 3600 * 8
RRSIG={
    "www.keytrap.test." : base64.b64decode("KgVnod8gSnLvzOYVSQGZafGTPRowJp/okxRFIYCCN3ez7fefodhefbPbPVQmFjRYBZ9jxjhcE00aOcLX1GGHYpxPSplasDvuHPwLNwJdb4qjIeYW1dmP+xoVMIcHjBZU"),
    "keytrap.test."     : base64.b64decode("s0ZmWQHEJoZ51gzJMG0ZyGXWs5oRPnhi7+peKM3pKxTYyVHPHy1dV5ERkDncxQT8ayLrseDLSKeC+Sx46cbFigs+LHKBcdCcTg+W8oFn8L0GnzTtIuLaEf0Dvbn3d37/"),
    "ns1.keytrap.test." : base64.b64decode("f+pnEtvtuV+/6gd1SmBttrPQ5IT6z4H90G26kCe03n3fnPlDzvTCorNCdrgy3P331b+r19+yn6Jc0uOx92Z7TnmfOXWDmLWR8uEGcZf9CWjbRYo8F+ckvoQIFH6JTPfF"),
    "KSK": base64.b64decode("YAqwWzt0bBSz/eyX9oQmAcMEKKDD7J+OHymxi3hnzXjZ0fcIUMLrVGqznYdcbaHbW+X6RoERwCrXdOQru//lCU/UhcHjJj/bjalWYWxiQyGmzfb0bpZ/NGxngzrFaGW1"),
    "ZSK": base64.b64decode("9wVtsq9/vpBWxGRjlvRDjHJyqsvrmsMwc3w1yaNNL4dRE3Od+wRSriJX6+utEU45jy1tZmvi7DfN4vF6VcN37ElQDREmOoD0wXDldIVR/o2Z40rWmheLBffdLCSfD8+n"),
}

DNSKEY={
    "KSK": base64.b64decode("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY"),
    "ZSK": base64.b64decode("DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb"),
}


    

# 构造DNS响应
def craft_dns_response(pkt, qname, qtype):
    reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    
    # 查询A记录
    # 通过socket发送无法自动计算DNS部分参数，需手动填入。
    if qtype == 1:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                         ancount=2, nscount=2, arcount=2, qdcount=1,
                        an=
                            DNSRR(rrname=qname, type=1, ttl=GLOBAL_TTL, rdata="124.222.27.40") /
                            DNSRRRSIG(rrname=qname, labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["www.keytrap.test."]),
                        ns=
                            DNSRR(rrname="keytrap.test.", type=2, ttl=GLOBAL_TTL, rdata="ns1.keytrap.test.") /
                            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=2, originalttl=GLOBAL_TTL,
                             expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                             signersname="keytrap.test", signature=RRSIG["keytrap.test."]),
                        ar=
                            DNSRR(rrname="ns1.keytrap.test.", type=1, ttl=GLOBAL_TTL, rdata="124.222.27.40") /
                            DNSRRRSIG(rrname="ns1.keytrap.test.", labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["ns1.keytrap.test."]),
                    )

    # 查询DNSKEY记录
    elif qtype == 48:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                    an=
                        DNSRRDNSKEY(rrname="keytrap.test.", ttl=GLOBAL_TTL, algorithm=14, flags=256, publickey=DNSKEY["ZSK"]) /
                        DNSRRDNSKEY(rrname="keytrap.test.", ttl=GLOBAL_TTL, algorithm=14, flags=257, publickey=DNSKEY['KSK']) /
                        DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=48, originalttl=GLOBAL_TTL,
                        expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                        signersname="keytrap.test.", signature=RRSIG["ZSK"]) /
                        DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=48, originalttl=GLOBAL_TTL,
                         expiration=EXPIRATION, inception=INCEPTION, keytag=30130, algorithm=14, 
                         signersname="keytrap.test.", signature=RRSIG["KSK"]),
                )
    else:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd, rcode=3,
                         ns=
                            DNSRR(rrname="keytrap.test.", type=2, ttl=GLOBAL_TTL, rdata="ns1.keytrap.test.") /
                            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=2, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["keytrap.test."])
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
        # resp.show2()
        send(resp, iface=IFACE_LAN)
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : to {pkt[IP].src}:{pkt[UDP].sport} : {qname}\n")

    except Exception as error:
        print("Error: ", error)

print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response, iface=IFACE_LAN)
