FROM debian:latest

ARG VENV=/usr/local/.venv

LABEL maintainer=t0chus

# 安装依赖
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install libcap-dev iptables\
    python3 python3-pip python3-venv

RUN python3 -m venv ${VENV}

ENV PATH="${VENV}/bin:$PATH"

# 安装Scapy和pcapy
RUN ${VENV}/bin/pip install --upgrade pip && \
    ${VENV}/bin/pip install scapy

# 开放端口53
EXPOSE 53

# 设置工作目录
WORKDIR /usr/local/ScapyAuth

# 启动脚本
CMD iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP && tail -f /dev/null