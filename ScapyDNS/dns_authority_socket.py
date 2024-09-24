import time
from socket import *
from select import select
from _thread import *

from scapy.layers.dns import DNS

DNS_SERVER_IP = "202.112.238.56"
PORT_OF_SERVER = 53
header_count_hex = "87e00001000400000000"
header_count_hex_tcp = "84000001000400000000"
annsar_hex = "03737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d00000600010000003c008a0373756203737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d0003737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d00000000000000000000000000000000000000000009743b347c6b272d793f047265633108787565736f6e676203636f6d00000600010000003c00560d6e65772d743b347c6b272d793f047265633108787565736f6e676203636f6d000d6e65772d743b347c6b272d793f047265633108787565736f6e676203636f6d00000000000000000000000000000000000000000007336467616d657303636f6d02617200000600010000003c003003636f6d026172000373756207336467616d657303636f6d02617200000000000000000000000000000000000000000003737562212a752d797a23385c6f22645f7728375b665e2b352f396e3f6a26307467767e6336047265633108787565736f6e676203636f6d00001000010000003c001312726563312e787565736f6e67622e636f6d2e"
s_input = []
# target_domain = "rec1.xuesongb.com"
target_domain = "sw.idealeer.com"


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

        # print(txid, qd)
        # print("from %s (TCP) : '%s'" % ("addr", data))
        # time.sleep(5)
        # s.send(data)

        dns_response = txid + bytes.fromhex(header_count_hex_tcp) + qd_to_bytes(qd) + bytes.fromhex(annsar_hex)
        dns_response = twoBytesField(len(dns_response)) + dns_response
        s.sendall(dns_response[:])
        print("from %s (TCP) : %s %04x" % ("addr", qd.qname.decode("utf-8"), dns.id))
    except:
        pass


def udp_thread(s):
    global header_count_hex, annsar_hex

    data, addr = s.recvfrom(4096)
    dns = DNS(data)
    txid = dns.id.to_bytes(2, byteorder="big")
    qd = dns.qd

    if target_domain not in str(qd.qname).lower():
        return

    # print(txid, qd)
    # print("from %s (UDP) : '%s'" % (addr, data))
    # time.sleep(5)
    # s.sendto(data, addr)

    dns_response = txid + bytes.fromhex(header_count_hex) + qd_to_bytes(qd) + bytes.fromhex(annsar_hex)
    s.sendto(dns_response, addr)
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
