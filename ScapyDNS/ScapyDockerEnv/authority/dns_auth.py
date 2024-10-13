from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.inet import IP, UDP, TCP
from datetime import datetime
import base64

# 配置DNS服务器的IP和端口
SERVER_IP = "10.10.2.3" # DNS服务器的IP会被用于DNSSEC签名，更换IP需要重新生成全部签名。
PORT_OF_SERVER = "53"
DOMAIN_NAME = [
    "www.keytrap.test.", 
    "keytrap.test.", 
    "ns1.keytrap.test.", 

    # 似乎是用来更新Trust Anchor的域名，具体机制有待探究...
    "_ta-75b2.keytrap.test.",
]

# sniff()函数的过滤器
BPF_FILTER = "udp port "  + str(PORT_OF_SERVER)

# 每次签名都必须更新以下条目：INCEPTION, EXPIRATION, RRSIG
GLOBAL_TTL = 86400
INCEPTION = datetime.strptime("20241007092918", "%Y%m%d%H%M%S").timestamp()
EXPIRATION = datetime.strptime("20241106092918", "%Y%m%d%H%M%S").timestamp()
RRSIG={
    "www.keytrap.test." : base64.b64decode("1111"),
    # RRSIG FOR NS
    "keytrap.test."     : base64.b64decode("Kb3NEkEkeBuxcpIsRTrBx7QPRk+LQN75ExRKzyiCAkgpz4k7+0lCMKyRcEWGQ6Ow28IFK+FV+lkdRr4uVxsjpVmc5ZtTJjFEfNVv3UCyHufrX4lvneIUYfls6zTR5RBq"),
    "ns1.keytrap.test." : base64.b64decode("14I5St5PVzzL4ucb2yTWq3BSOGAXfJCLH4/De2HMm3sKznFf+RCAtv3lF1fpJyLDsXi4db8cf96nn2RPhQNM9T6p3HFITSJs4P5GRTkGmJJlafMlCHIOo1Lfv1aLEf5h"),
    "KSK": base64.b64decode("WjKQCEHx962QfA/xiJk7lL4ziiz/cv4i9LZt2KE6l/Sn8SJfPnEUaFC6qsTTXkEWpBQU+lioSwL6wzGKDnSYf+UBZq2CGdNrIkxKohKpDbKAqh2swL/DC8ljLpuNf3IF"),
    "ZSK": base64.b64decode("ollmgXnsrtc2GVx5HbXV4XaWxygXX90FD0avArSIIPuGHqzzLJ6S9loVtwsdZ/CGdJo4nzIn8pTXQuboz2Hv8GRf7N2FFfyRcmz8wHQ+faLsrZL0MPNApzybfJJMept6"),
}

# DNS记录的RDATA
RRRDATA={
    "www.keytrap.test.": SERVER_IP,
    "keytrap.test.": "ns1.keytrap.test.",
    "ns1.keytrap.test.": SERVER_IP,
}

# DNSKEY记录的公钥
DNSKEY={
    # Key Tag: 30130, Key Signing Key
    "KSK": base64.b64decode("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY"),

    # Key Tag: 6350, Zone Signing Key
    "ZSK": base64.b64decode("DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb"),
}
    

def gen_random_rrsig(len=96):
    return os.urandom(len)

# 构造DNS响应
def craft_dns_response(pkt, qname, qtype):
    reply_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / UDP(sport=int(PORT_OF_SERVER), dport=pkt[UDP].sport)
    
    # 查询A记录
    if qtype == 1:
        reply_pkt /= DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, qd=pkt[DNS].qd,
                        ancount=2,
                        an=
                            DNSRR(rrname=qname, type=1, ttl=GLOBAL_TTL, rdata=RRRDATA["www.keytrap.test."]) /
                            DNSRRRSIG(rrname=qname, labels=3, ttl=GLOBAL_TTL, typecovered=1, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION,keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["www.keytrap.test."]),
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

# 处理DNS查询请求
def dns_response(pkt):
    try:
        if DNS not in pkt:
            return
        
        # 在Docker容器环境中，会莫名出现来自本机的无限迭代的DNS请求；
        # 无限迭代会阻塞Scapy权威的运行，这里通过过滤本机IP地址，避免无限迭代。
        if pkt[IP].src == SERVER_IP:
            return

        qname = pkt[DNS].qd.qname.decode("utf-8")
        
        # 过滤掉不在DOMAIN_NAME列表中的域名
        if qname not in DOMAIN_NAME:
            return

        qtype = pkt[DNS].qd.qtype
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : fm {pkt[IP].src}:{pkt[UDP].sport} : {qname} {qtype} ?")

        # 构建DNS响应
        resp = craft_dns_response(pkt, qname, qtype)
        # resp.show2()
        send(resp)
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} : to {pkt[IP].src}:{pkt[UDP].sport} : {qname}\n")

    except Exception as error:
        print("Error: ", error)

print("Start DNS Authority ...")
sniff(filter=BPF_FILTER, prn=dns_response)
