from xmlrpc.client import SERVER_ERROR
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from datetime import datetime
import base64
from scapy.utils import hexdump

GLOBAL_TTL = 86400
INCEPTION = datetime.strptime("20241007092918", "%Y%m%d%H%M%S").timestamp()
EXPIRATION = datetime.strptime("20241106092918", "%Y%m%d%H%M%S").timestamp()
RRSIG={
    "www.keytrap.test" : base64.b64decode("XBHOlljD4lBFpWFmbe2sXNhEbnDaDPBMn2e1Pvw0AIt3NW9j92zP4GHGCVI3IS1Ea3uGq0nBcUHVet5hxsXmhkoeLzIuDtU8Va4O2LyFIdX5Km1lpdntwcr0OOIAmAN5"),
    # RRSIG FOR NS
    "keytrap.test"     : base64.b64decode("Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq"),
    "ns1.keytrap.test" : base64.b64decode("14I5St5PVzzL4ucb2yTWq3BSOGAXfJCLH4/De2HMm3sKznFf+RCAtv3lF1fpJyLDsXi4db8cf96nn2RPhQNM9T6p3HFITSJs4P5GRTkGmJJlafMlCHIOo1Lfv1aLEf5h"),
    "KSK": base64.b64decode("WjKQCEHx962QfA/xiJk7lL4ziiz/cv4i9LZt2KE6l/Sn8SJfPnEUaFC6qsTTXkEWpBQU+lioSwL6wzGKDnSYf+UBZq2CGdNrIkxKohKpDbKAqh2swL/DC8ljLpuNf3IF"),
    "ZSK": base64.b64decode("ollmgXnsrtc2GVx5HbXV4XaWxygXX90FD0avArSIIPuGHqzzLJ6S9loVtwsdZ/CGdJo4nzIn8pTXQuboz2Hv8GRf7N2FFfyRcmz8wHQ+faLsrZL0MPNApzybfJJMept6"),
}

SERVER_IP = "10.10.0.3"
PORT_OF_SERVER = "53"

# DNS记录的RDATA
RRRDATA={
    "www.keytrap.test": SERVER_IP,
    "keytrap.test": "ns1.keytrap.test",
    "ns1.keytrap.test": SERVER_IP,
}

# DNSKEY记录的公钥
DNSKEY={
    # Key Tag: 30130, Key Signing Key
    "KSK": base64.b64decode("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY"),

    # Key Tag: 6350, Zone Signing Key
    "ZSK": base64.b64decode("DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb"),
}

# 构造DNS响应
def craft_response(pkt, qname, qtype):
    reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    
    # 查询A记录
    if qtype == 1:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                        an=[
                            DNSRR(rrname=qname, type=1, ttl=GLOBAL_TTL, rdata=RRRDATA["www.keytrap.test"]),
                            DNSRRRSIG(rrname=qname, labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["www.keytrap.test"]),
                        ],
                        ns=[
                            DNSRR(rrname="keytrap.test.", type=2, ttl=GLOBAL_TTL, rdata=RRRDATA["keytrap.test."]),
                            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=2, originalttl=GLOBAL_TTL,
                             expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                             signersname="keytrap.test", signature=RRSIG["keytrap.test."])],
                        ar=[
                            DNSRR(rrname="ns1.keytrap.test.", type=1, ttl=GLOBAL_TTL, rdata=RRRDATA["ns1.keytrap.test."]),
                            DNSRRRSIG(rrname="ns1.keytrap.test.", labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["ns1.keytrap.test"])],
                    )

    # 查询DNSKEY记录
    elif qtype == 48:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                    ancount=4,
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
                         nscount=2,
                         ns=
                            DNSRR(rrname="keytrap.test.", type=2, ttl=GLOBAL_TTL, rdata=RRRDATA["keytrap.test."]) /
                            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=2, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["keytrap.test."])
                        )
        
    return reply_pkt

def craft_rrsig_response():
    reply = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800) / IP(src=SERVER_IP, dst="10.10.0.2") / UDP(sport=53, dport=25535)
    reply /= DNS(id=0, qr=1, aa=1, ad=1, qd=DNSQR(qname="www.keytrap.test", qtype=46),
                ancount=2,
                  an=
                            DNSRR(rrname="www.keytrap.test", type=1, ttl=GLOBAL_TTL, rdata=RRRDATA["www.keytrap.test"]) /
                            DNSRRRSIG(rrname="www.keytrap.test", labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["www.keytrap.test"]),
    )
    return reply

def craft_dnskey_response():
    reply = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800) / IP(src=SERVER_IP, dst="10.10.0.2") / UDP(sport=53, dport=25535)
    reply /= DNS(id=0, qr=1, aa=1, ad=1, qd=DNSQR(qname="www.keytrap.test", qtype=46),
                ancount=3,
                an=
                    DNSRRDNSKEY(rrname="keytrap.test", ttl=GLOBAL_TTL, algorithm=14, flags=256, publickey=DNSKEY["ZSK"]) /
                    DNSRRDNSKEY(rrname="keytrap.test", ttl=GLOBAL_TTL, algorithm=14, flags=257, publickey=DNSKEY['KSK']) /
                    DNSRRRSIG(rrname="keytrap.test", labels=2, ttl=GLOBAL_TTL, typecovered=48, originalttl=GLOBAL_TTL,
                        expiration=EXPIRATION, inception=INCEPTION, keytag=30130, algorithm=14, 
                        signersname="keytrap.test", signature=RRSIG["KSK"]),
    )
    return reply

def craft_A_response():
    reply = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800) / IP(src=SERVER_IP, dst="10.10.0.2") / UDP(sport=53, dport=25535)
    reply /= DNS(id=0x1234, qr=1, aa=1, ad=1, qd=DNSQR(qname="www.keytrap.test", qtype=1),
                ancount=1,
                an= DNSRR(rrname="www.keytrap.test", type=1, ttl=GLOBAL_TTL, rdata=RRRDATA["www.keytrap.test"])
    )
    return reply

def printByteArray(byteArray):
    lineBreak = 0
    for byte in byteArray:
        print(f"0x{byte:02x}", end=", ")
        lineBreak += 1
        if lineBreak % 8 == 0:
            print()


def craftToUDP():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800) / IP(src=SERVER_IP, dst="10.10.0.2") / UDP(sport=53, dport=25535)
    return pkt

def craftDNSQuery():
    pkt = craftToUDP()
    pkt /= DNS(id=0, qr=0, aa=0, ad=0, qd=DNSQR(qname="www.keytrap.test", qtype=1))
    return pkt 


if __name__ == "__main__":
    # 测试DNS响应
    # replyPkt = craft_A_response()
    # printByteArray(bytes(replyPkt))

    str = "2 66 10 10 3 3 2 66 10 10 3 4 8 0 69 0 0 71 194 107 0 0 64 17 158 32 10 10 3 4 10 10 3 3 222 227 0 53 0 51 26 95 71 160 1 32 0 1 0 0 0 0 0 1 2 119 101 0 0 1 0 1 0 0 41 4 208 0 0 0 0 0 12 0 10 0 8 90 78 61 203 49 89 242 139"
    str = str.split(" ")
    byteArray = []
    for s in str:
        byteArray.append(int(s))
    printByteArray(byteArray)
    
