FROM debian:12
LABEL maintainer=t0chus

# 避免在安装软件包时出现交互提示
ENV DEBIAN_FRONTEND noninteractive

# 更新包列表并安装依赖
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install build-essential libssl-dev libperl-dev libcap-dev wget vim tar dnsutils libuv1 pkg-config \
    python3 python3-pip python3-venv python3-dev python3-ply
RUN apt-get -y install libuv1-dev
RUN apt-get -y install bind9utils
RUN apt-get -y install liburcu-dev
# 设置BIND版本
ENV version 9.21.2

# 限于网络环境，使用本地文件代替远程下载
# RUN wget https://downloads.isc.org/isc/bind9/${version}/bind-${version}.tar.xz
COPY ./bind/bind-${version}.tar.xz /usr/local/src/bind-${version}.tar.xz

# 安装BIND，--enalbe-syscalls参数用于支持系统调用,
# --with-openssl启用OpenSSL支持，用于DNSSEC和其他加密功能，
# --enable-openssl-version-check启用OpenSSL版本检查，
# --enable-ipv6启用IPv6支持，--disable-linux-caps禁用Linux特权分离
# --prefix=/var/named/chroot指定安装目录
# --enable-threads启用线程支持
# --disable-doh禁用DNS over HTTPS
RUN cd /usr/local/src && \
    tar xvf bind-${version}.tar.xz && \
    mv bind-${version} bind && \
    rm bind-${version}.tar.xz
RUN cd /usr/local/src/bind && \
    ./configure --enable-syscalls --prefix=/var/named/chroot --disable-doh --enable-threads --with-openssl --enable-openssl-version-check --enable-ipv6 --disable-linux-caps && \
    chown -R root:root /usr/local/src/bind && \
    make && \
    make install

# 创建设备文件
RUN mkdir -p /var/named/chroot/dev && \
    mknod -m 666 /var/named/chroot/dev/null c 1 3 && \
    mknod -m 666 /var/named/chroot/dev/random c 1 8

# 创建必要目录
RUN mkdir -p /var/named/chroot/data && \
    mkdir -p /var/named/chroot/var/log && \
    mkdir -p /var/named/chroot/var/named

# 下载根提示文件
RUN cd /var/named/chroot/var/named && \
    wget https://www.internic.net/domain/named.root

# 创建符号链接
RUN  ln -s /var/named/chroot/etc/named.conf /etc/named.conf

EXPOSE 53 953

# 启动BIND
# -t: 指定chroot环境根目录
# -c: 指定配置文件
# -g: 在前台运行，并将日志输出到标准输出
# -d: 指定日志级别为debug 99

CMD [ "/var/named/chroot/sbin/named", "-t", "/var/named/chroot", "-c", "/etc/named.conf", "-g", "-d", "99", "-4" ]

