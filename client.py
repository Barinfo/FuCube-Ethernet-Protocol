import socket
import struct
import threading
import json
import os
import sys
import tkinter as tk
from tkinter import messagebox
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import socketserver
import random
import time

# 配置文件路径
SERVER_CONFIG_PATH = 'config.json'        # 服务端配置，必须存在
CLIENT_CONFIG_PATH = 'client_config.json' # 客户端配置，可自动生成

# 加载服务端配置
def load_server_config():
    if not os.path.exists(SERVER_CONFIG_PATH):
        print(f"错误：找不到服务端配置文件 {SERVER_CONFIG_PATH}，请先从服务端拉取配置文件！")
        sys.exit(1)
    with open(SERVER_CONFIG_PATH, 'r') as f:
        return json.load(f)

# 加载或创建客户端配置
def load_or_create_client_config():
    defaults = {
        "proxy_port": 8080,
        "server_ip": "127.0.0.1",
        "server_port": 11451,  # 默认服务端端口
        "fakepayload": "none"   # 默认伪造报文类型
    }
    if not os.path.exists(CLIENT_CONFIG_PATH):
        with open(CLIENT_CONFIG_PATH, 'w') as f:
            json.dump(defaults, f, indent=4)
        print(f"客户端配置 {CLIENT_CONFIG_PATH} 已生成。")
    with open(CLIENT_CONFIG_PATH, 'r') as f:
        return json.load(f)

# 加载服务器配置
server_config = load_server_config()

# 加载客户端配置
client_config = load_or_create_client_config()

# 获取密钥和 IV
KEY = bytes.fromhex(server_config['key'])
IV = KEY  # IV 与 KEY 相同

def build_fcep_packet(token, stream_id, payload, packet_type=1):
    version = 1
    token_length = len(token)
    payload_length = len(payload)
    checksum = (version + packet_type + token_length + stream_id + payload_length) % 65536
    packet = bytearray()
    
    packet.append(version)
    packet.append(packet_type)
    packet.append(token_length)
    
    # 添加 token
    packet.extend(token)
    
    # 添加 stream_id 和 payload 长度
    packet.extend(struct.pack('!H', stream_id))
    packet.extend(struct.pack('!H', payload_length))
    
    # 校验和
    packet.extend(struct.pack('!H', checksum))
    
    # 添加实际的 payload
    packet.extend(payload)
    
    return bytes(packet)

def decrypt_payload(payload):
    """解密有效负载"""
    try:
        cipher = AES.new(KEY, AES.MODE_CFB, iv=IV)
        decrypted_data = unpad(cipher.decrypt(payload), AES.block_size)
        return decrypted_data
    except ValueError as e:
        print(f"解密错误：{e}")
        return None

def send_heartbeat(s):
    """发送心跳包"""
    while True:
        try:
            heartbeat_payload = b'heartbeat'
            stream_id = random.randint(1, 65535)
            fcep_packet = build_fcep_packet(KEY, stream_id, heartbeat_payload, packet_type=2)

            s.sendall(fcep_packet)
            print("已发送心跳包")
            time.sleep(15)  # 每15秒发送一次心跳包
        except Exception as e:
            print(f"心跳包发送错误: {e}")
            break

# HTTP 请求处理
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        # 解析请求并将其传输到 FCEP 服务器
        url = self.path
        parsed_url = urlparse(url)
        method = self.command
        headers = self.headers

        print(f"收到 {method} 请求：{url}")

        # 构建 FCEP 数据包并发送到服务器
        stream_id = random.randint(1, 65535)  # 随机生成流 ID

        # 获取伪造的 payload（如果有）
        fake_payload_type = client_config.get('fakepayload', 'none')
        fake_payload = server_config['fake_payloads'].get(fake_payload_type, "I love you <3").encode('utf-8')

        # 获取真实的 payload（即请求的有效负载）
        actual_payload = f"Request for {url}".encode('utf-8')

        # 发送包含伪造和真实数据的 FCEP 包
        fcep_packet_with_fake = build_fcep_packet(KEY, stream_id, fake_payload, packet_type=1)  # 伪造数据包

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((client_config['server_ip'], client_config['server_port']))  # 使用服务器 IP 和端口
                print(f"已连接到 FCEP 服务器 {client_config['server_ip']}:{client_config['server_port']}")

                # 启动心跳线程
                threading.Thread(target=send_heartbeat, args=(s,), daemon=True).start()

                # 先发送伪造数据包
                s.sendall(fcep_packet_with_fake)
                print(f"已发送伪造数据包到 {client_config['server_ip']}:{client_config['server_port']}")

                # 然后发送包含正确 payload 的数据包
                fcep_packet = build_fcep_packet(KEY, stream_id, actual_payload, packet_type=1)  # 真实数据包
                s.sendall(fcep_packet)
                print(f"已发送正确数据包到 {client_config['server_ip']}:{client_config['server_port']}")

                # 获取服务器响应
                response = s.recv(4096)  # 接收服务器的响应数据
                if response:
                    decrypted_response = decrypt_payload(response)
                    if decrypted_response:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(decrypted_response)
                        print("已将响应返回给客户端")
                    else:
                        self.send_error(500, '解密失败')
                else:
                    self.send_error(500, '服务器无响应')
        except Exception as e:
            print(f"连接错误: {e}")
            self.send_error(500, '服务器连接错误')

# 代理服务器类
class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

# GUI 界面
class FCEPClientGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FCEP HTTP代理客户端")
        self.geometry("400x300")
        self.proxy_server = None
        self.create_widgets()
        self.load_client_config()

    def create_widgets(self):
        # 服务端 IP
        tk.Label(self, text="服务端 IP:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.entry_server_ip = tk.Entry(self)
        self.entry_server_ip.grid(row=0, column=1, padx=10, pady=5)

        # 服务端端口
        tk.Label(self, text="服务端端口:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.entry_server_port = tk.Entry(self)
        self.entry_server_port.grid(row=1, column=1, padx=10, pady=5)

        # 代理端口
        tk.Label(self, text="代理端口:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.entry_proxy_port = tk.Entry(self)
        self.entry_proxy_port.grid(row=2, column=1, padx=10, pady=5)

        # 伪造类型
        tk.Label(self, text="伪造报文类型:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.entry_fakepayload = tk.Entry(self)
        self.entry_fakepayload.grid(row=3, column=1, padx=10, pady=5)

        # 连接和断开按钮
        self.btn_connect = tk.Button(self, text="连接", command=self.start_proxy)
        self.btn_connect.grid(row=4, column=0, pady=20)
        self.btn_disconnect = tk.Button(self, text="断开", command=self.stop_proxy, state=tk.DISABLED)
        self.btn_disconnect.grid(row=4, column=1, pady=20)

        # 状态显示
        self.label_status = tk.Label(self, text="状态：未连接", fg="red")
        self.label_status.grid(row=5, column=0, columnspan=2)

        # 保存按钮
        self.btn_save = tk.Button(self, text="保存配置", command=self.save_client_config)
        self.btn_save.grid(row=6, column=0, columnspan=2, pady=10)

    def load_client_config(self):
        # 载入客户端配置到 GUI
        self.entry_server_ip.insert(0, client_config["server_ip"])
        self.entry_server_port.insert(0, str(client_config["server_port"]))  # 加载服务端端口
        self.entry_proxy_port.insert(0, str(client_config["proxy_port"]))
        self.entry_fakepayload.insert(0, client_config["fakepayload"])  # 加载伪造报文类型

    def start_proxy(self):
        # 获取用户输入
        server_ip = self.entry_server_ip.get()
        server_port = int(self.entry_server_port.get())
        proxy_port = int(self.entry_proxy_port.get())
        fakepayload = self.entry_fakepayload.get()

        # 更新客户端配置
        client_config.update({
            "server_ip": server_ip,
            "server_port": server_port,
            "proxy_port": proxy_port,
            "fakepayload": fakepayload
        })

        # 保存客户端配置
        with open(CLIENT_CONFIG_PATH, 'w') as f:
            json.dump(client_config, f, indent=4)

        # 启动代理服务器线程
        if self.proxy_server:
            self.stop_proxy()

        try:
            self.proxy_server = ThreadedTCPServer(('0.0.0.0', proxy_port), ProxyHTTPRequestHandler)
            threading.Thread(target=self.proxy_server.serve_forever, daemon=True).start()
            self.label_status.config(text=f"状态：已连接，代理端口 {proxy_port}", fg="green")
            self.btn_connect.config(state=tk.DISABLED)
            self.btn_disconnect.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("错误", f"启动代理失败: {e}")

    def stop_proxy(self):
        if self.proxy_server:
            self.proxy_server.shutdown()
            self.proxy_server.server_close()
            self.proxy_server = None
            self.label_status.config(text="状态：已断开", fg="red")
            self.btn_connect.config(state=tk.NORMAL)
            self.btn_disconnect.config(state=tk.DISABLED)

    def save_client_config(self):
        # 保存客户端配置到 JSON 文件
        with open(CLIENT_CONFIG_PATH, 'w') as f:
            json.dump(client_config, f, indent=4)
        messagebox.showinfo("保存成功", "客户端配置已成功保存。")

if __name__ == "__main__":
    # 先加载服务端config.json，若无则退出
    server_config = load_server_config()

    # 启动GUI
    app = FCEPClientGUI()
    app.mainloop()
