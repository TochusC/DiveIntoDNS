FROM python:3.9-alpine

# 安装依赖包
RUN apk update && \
    apk add --no-cache libpcap libpcap-dev build-base iptables

# 安装Scapy和pcapy
RUN pip install --upgrade pip && \
    pip install scapy pcapy

# 开放端口53
EXPOSE 53

# 设置工作目录
WORKDIR /usr/local/ScapyAuth

# 运行脚本
CMD ["python3", "dns_authority.py"]