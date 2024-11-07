# 使用Alpine Linux作为基础镜像
FROM alpine:latest

LABEL maintainer="tochus@163.com"

# 更新包列表并安装PowerDNS和SQLite后端
RUN apk update && \
    apk add --no-cache pdns

# 创建PowerDNS配置目录
RUN mkdir -p /etc/pdns

# 复制PowerDNS配置文件到容器中
COPY pdns.conf /etc/pdns/pdns.conf

# 开放PowerDNS默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 设置容器启动时运行的命令
CMD ["pdns_server", "--config-dir=/etc/pdns", "--daemon=no"]