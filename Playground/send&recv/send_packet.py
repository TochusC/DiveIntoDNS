from scapy.all import *

# 构造一个IP数据包
ip_packet = IP(dst="目标IP地址")

# 构造一个TCP数据包
tcp_packet = TCP(dport=目标端口号)

# 将IP和TCP数据包层叠起来
packet = ip_packet / tcp_packet

# 发送数据包
send(packet)
