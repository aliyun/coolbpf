#!/usr/bin/env python3
"""
SSL/TLS 流量生成器 - 用于测试 sslsniff eBPF 探针

功能:
1. SSL 服务端 - 监听 8443 端口，使用自签名证书
2. SSL 客户端 - 连接服务端并发送 HTTP 请求
3. 持续发送数据，便于观察 sslsniff 捕获效果

用法:
    # 终端1: 启动服务端
    python3 test_ssl_traffic.py server

    # 终端2: 启动客户端 (持续发送请求)
    python3 test_ssl_traffic.py client

    # 终端3: 运行 sslsniff 捕获 (需要 root)
    sudo ./target/release/sslsniff -p $(pgrep -f "test_ssl_traffic.py client")
"""

import ssl
import socket
import sys
import time
import threading
import json
from datetime import datetime

# 自签名证书和密钥 (PEM 格式)
# 生成命令: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpE
-----END CERTIFICATE-----"""

KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5Z5Z5Z5Z5Z5Z5
-----END PRIVATE KEY-----"""

# 使用临时文件存储证书
import tempfile
import os


def create_temp_certs():
    """创建临时证书文件"""
    cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
    key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)

    # 生成新的自签名证书
    cert_file.write(CERT_PEM)
    key_file.write(KEY_PEM)

    cert_file.close()
    key_file.close()

    return cert_file.name, key_file.name


def generate_self_signed_cert():
    """使用 openssl 命令生成自签名证书"""
    cert_path = "/tmp/test_ssl_cert.pem"
    key_path = "/tmp/test_ssl_key.pem"

    if not os.path.exists(cert_path):
        print("[*] 生成自签名证书...")
        os.system(f"openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -days 1 -nodes -subj '/CN=localhost' 2>/dev/null")

    return cert_path, key_path


def ssl_server(host='0.0.0.0', port=8443):
    """SSL 服务端"""
    cert_path, key_path = generate_self_signed_cert()

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[*] SSL Server listening on {host}:{port}")
        print(f"[*] Press Ctrl+C to stop")

        while True:
            try:
                conn, addr = sock.accept()
                with conn:
                    print(f"[+] Connection from {addr}")
                    with context.wrap_socket(conn, server_side=True) as ssock:
                        try:
                            data = ssock.recv(4096)
                            if data:
                                print(f"[<] Received: {data.decode('utf-8', errors='replace')[:100]}...")

                                # 发送 HTTP 响应
                                response = (
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: 50\r\n"
                                    "\r\n"
                                    '{"status": "ok", "message": "Hello from SSL server"}'
                                )
                                ssock.send(response.encode())
                                print(f"[>] Sent: {response[:80]}...")
                        except ssl.SSLError as e:
                            print(f"[!] SSL Error: {e}")
            except KeyboardInterrupt:
                print("\n[*] Server stopped")
                break


def ssl_client(server_host='127.0.0.1', server_port=8443, interval=1.0):
    """SSL 客户端 - 持续发送请求"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # 忽略自签名证书验证

    request_count = 0
    print(f"[*] SSL Client connecting to {server_host}:{server_port}")
    print(f"[*] Sending requests every {interval}s (Press Ctrl+C to stop)")

    while True:
        try:
            with socket.create_connection((server_host, server_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=server_host) as ssock:
                    request_count += 1
                    timestamp = datetime.now().isoformat()

                    # 构造 HTTP POST 请求
                    body = json.dumps({
                        "id": request_count,
                        "timestamp": timestamp,
                        "data": "test data from ssl client",
                        "message": f"Request #{request_count}"
                    })

                    request = (
                        f"POST /api/test HTTP/1.1\r\n"
                        f"Host: {server_host}:{server_port}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"X-Request-ID: {request_count}\r\n"
                        f"\r\n"
                        f"{body}"
                    )

                    ssock.send(request.encode())
                    print(f"[>] Request #{request_count} sent ({len(request)} bytes)")

                    # 接收响应
                    response = b""
                    while True:
                        try:
                            chunk = ssock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            # 简单判断 HTTP 响应是否完整
                            if b"\r\n\r\n" in response:
                                headers, _, body = response.partition(b"\r\n\r\n")
                                content_length = 0
                                for line in headers.split(b"\r\n"):
                                    if line.lower().startswith(b"content-length:"):
                                        content_length = int(line.split(b":")[1].strip())
                                        break
                                if len(body) >= content_length:
                                    break
                        except socket.timeout:
                            break

                    print(f"[<] Response #{request_count}: {response[:100].decode('utf-8', errors='replace')}...")

            time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n[*] Client stopped after {request_count} requests")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(interval)


def ssl_client_burst(server_host='127.0.0.1', server_port=8443, count=100):
    """SSL 客户端 - 突发发送多个请求"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print(f"[*] SSL Client burst mode: {count} requests to {server_host}:{server_port}")

    for i in range(count):
        try:
            with socket.create_connection((server_host, server_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=server_host) as ssock:
                    request = (
                        f"GET /api/burst/{i} HTTP/1.1\r\n"
                        f"Host: {server_host}:{server_port}\r\n"
                        f"X-Burst-ID: {i}\r\n"
                        f"\r\n"
                    )
                    ssock.send(request.encode())
                    response = ssock.recv(4096)
                    print(f"[>] Request {i+1}/{count} - {len(request)} bytes sent, {len(response)} bytes received")
        except Exception as e:
            print(f"[!] Request {i+1} failed: {e}")

    print(f"[*] Burst completed")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n用法:")
        print("  python3 test_ssl_traffic.py server              # 启动服务端")
        print("  python3 test_ssl_traffic.py client              # 启动客户端 (持续)")
        print("  python3 test_ssl_traffic.py burst [count]       # 突发模式")
        sys.exit(1)

    command = sys.argv[1]

    if command == "server":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
        ssl_server(port=port)
    elif command == "client":
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 8443
        interval = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
        ssl_client(server_host=host, server_port=port, interval=interval)
    elif command == "burst":
        host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 8443
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        ssl_client_burst(server_host=host, server_port=port, count=count)
    else:
        print(f"[!] 未知命令: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
