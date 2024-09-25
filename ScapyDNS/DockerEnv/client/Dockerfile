FROM python:3.9-alpine

# Make sure scripts in the virtualenv are available in the PATH
ENV PATH="/opt/venv/bin:$PATH"

# 安装Scapy和pcapy
RUN pip install scapy

# 设置工作目录
WORKDIR /usr/local/ScapyClient
