# 使用Alpine Linux作为基础镜像
FROM alpine:latest

# 设置维护者信息
LABEL maintainer="tochusc"

# 更新包列表并安装Knot DNS
RUN apk update && \
    apk add --no-cache knot

# 创建Knot DNS配置目录
RUN mkdir -p /etc/knot

# 暴露Knot DNS默认端口
EXPOSE 53/udp
EXPOSE 53/tcp

# 设置容器启动时运行的命令
CMD ["knotd", "-c", "/etc/knot/knot.conf", "-v"]