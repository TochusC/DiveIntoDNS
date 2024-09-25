FROM python:3.9-alpine

# 安装依赖包
RUN apk update && \
    apk add --no-cache libpcap libpcap-dev build-base iptables

# 安装Scapy和pcapy
RUN pip install scapy pcapy

# 复制你的脚本到容器中
COPY dns_authority.py /usr/local/ScapyAuth/dns_authority.py

# 设置工作目录
WORKDIR /usr/local/ScapyAuth

# 运行脚本
CMD ["sh", "-c", "iptables -A INPUT -p udp --dport 53 -j ACCEPT && iptables-save > /etc/iptables/rules.v4 && python3 dns_authority.py"]