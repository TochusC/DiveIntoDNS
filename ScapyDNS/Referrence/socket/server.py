import socket

# 创建Socket对象
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 获取本地主机名
host = socket.gethostname()
port = 12345

# 绑定端口
server_socket.bind((host, port))

# 设置最大连接数，超过后排队
server_socket.listen(5)

print("服务器等待连接...")

while True:
    # 建立客户端连接
    client_socket, addr = server_socket.accept()
    print(f"连接地址: {addr}")
    
    msg = '欢迎访问服务器！' + "\r\n"
    client_socket.send(msg.encode('utf-8'))
    
    client_socket.close()