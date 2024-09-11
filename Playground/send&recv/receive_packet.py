from scapy.all import sniff

def packet_callback(packet):
    # 打印接收到的数据包
    print(packet.show())

# 使用sniff函数捕获数据包
sniff(filter="ip", prn=packet_callback)
