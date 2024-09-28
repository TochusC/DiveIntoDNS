FROM debian:latest

LABEL maintainer=t0chus

USER root
# Update and install required system packages
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install libcap-dev\
    python3 python3-pip python3-venv
RUN apt-get -y install libuv1-dev

# 安装Scapy和pcapy
RUN pip install --upgrade pip && \
    pip install scapy pcapy

# 开放端口53
EXPOSE 53

# 设置工作目录
WORKDIR /usr/local/ScapyAuth

# 关闭ICMP

RUN iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP