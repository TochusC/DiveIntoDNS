# Debian镜像
FROM debian:latest

# 设置维护者信息
LABEL maintainer="tochusc"


# 安装PowerDNS Recursor
RUN apt-get -y update \
    && apt-get -y upgrade \
    && apt-get -y install apt-tranusport-https ca-certificates wget \
    && curl dnsutils

# 添加PowerDNS源
RUN echo "deb [signed-by=/etc/apt/keyrings/rec-51-pub.asc] http://repo.powerdns.com/debian bookworm-rec-51 main" | tee /etc/apt/sources.list.d/pdns.list  \
    mkdir -p /etc/apt/preferences.d && \
    echo "Package: rec*" > /etc/apt/preferences.d/rec-51 && \
    echo "Pin: origin repo.powerdns.com" >> /etc/apt/preferences.d/rec-51 && \
    echo "Pin-Priority: 600" >> /etc/apt/preferences.d/rec-51

# 导入PowerDNS公钥并安装PowerDNS Recursor
RUN  install -y -d /etc/apt/keyrings; curl https://repo.powerdns.com/FD380FBB-pub.asc | tee /etc/apt/keyrings/rec-51-pub.asc \ 
    && apt-get -y update \
    && apt-get -y install pdns-recursor

# 创建PowerDNS配置目录
RUN mkdir -p /var/run/pdns-recursor \
    && chown pdns:pdns /var/run/pdns-recursor \
    && mkdir -p /etc/pdns

# 开放DNS服务器默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 设置容器启动时运行的命令
# --daemon=no 不以守护进程方式运行，日志输出到标准输出
CMD ["pdns_recursor", "--daemon=no", "--local-address=10.10.3.7", "--local-port=53", "--config-dir=/etc/pdns"]