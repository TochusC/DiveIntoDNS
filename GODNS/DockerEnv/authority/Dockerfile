FROM debian:latest

ARG VENV=/usr/local/.venv
ENV GO_VERSION 1.23.2

LABEL maintainer=t0chus

# 安装依赖
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install libpcap0.8 libcap-dev iptables\

# 安装GO语言
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH="/usr/local/go"

# 开放端口53
EXPOSE 53

# 设置工作目录
WORKDIR /usr/local/GOAuth

# 启动脚本
CMD iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP && python3 dns_auth.py