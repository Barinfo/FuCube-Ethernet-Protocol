import socket
import struct
import threading
import time
import random
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 配置
DEFAULT_CONFIG = {
    "protocol": "tcp",
    "encrypt": "aes_128_cfb",
    "fakepayload": "none",
    "websocket": False,
    "mux": False,
    "gzip": False,
    "retry": True,
    "reconnect": False,
    "dns": "8.8.8.8",
    "port": 11451,
    "heartbeat": "15s",
    "key": "a1b2c3d4e5f6789a0123456789abcdef",
    "iv": "a1b2c3d4e5f6789a0123456789abcdef",
    "fake_payloads": {
        "none": "I love you <3",
        "ftp": "USER anonymous\r\nPASS guest\r\n",
        "rdp": "RDP Request Example",
        "mcpe": "MCPE Request Example",
        "dns": "example.com. IN A 93.184.216.34",
        "smtp": "EHLO localhost\r\nMAIL FROM:<test@example.com>\r\nRCPT TO:<recipient@example.com>\r\nDATA\r\nSubject: Test\r\n\r\nThis is a test email.\r\n.\r\nQUIT\r\n"
    }
}
CONFIG_PATH = 'config.json'
config = None
PORT = 0
HEARTBEAT_INTERVAL = 0
KEY = None
IV = None
fake_payloads = None
PROTOCOL = None
clients = {}
lock = threading.Lock()

def load_or_create_config(path=CONFIG_PATH):
    global config, PORT, HEARTBEAT_INTERVAL, KEY, IV, fake_payloads, PROTOCOL
    if not os.path.exists(path):
        with open(path, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"默认配置文件 {path} 已生成。")
    config = json.load(open(path, 'r'))
    PORT = config['port']
    HEARTBEAT_INTERVAL = int(config['heartbeat'].rstrip('s'))
    KEY = bytes.fromhex(config['key'])
    IV = KEY  # 保持与客户端一致
    fake_payloads = config['fake_payloads']
    PROTOCOL = config['protocol'].lower()
    print(f"加载配置：协议={PROTOCOL}, 端口={PORT}, 心跳间隔={HEARTBEAT_INTERVAL}s")

def decrypt_payload(payload):
    cipher = AES.new(KEY, AES.MODE_CFB, iv=IV)
    decrypted_data = unpad(cipher.decrypt(payload), AES.block_size)
    return decrypted_data

def build_fcep_packet(token, stream_id, payload, packet_type=1):
    version = 1
    token_length = len(token)
    payload_length = len(payload)
    checksum = (version + packet_type + token_length + stream_id + payload_length) % 65536
    packet = bytearray()
    packet.append(version)
    packet.append(packet_type)
    packet.append(token_length)
    packet.extend(token)
    packet.extend(struct.pack('!H', stream_id))
    packet.extend(struct.pack('!H', payload_length))
    packet.extend(struct.pack('!H', checksum))
    packet.extend(payload)
    return bytes(packet)

def handle_client(client_socket, client_address):
    global clients
    try:
        while True:
            if PROTOCOL == 'tcp':
                data = client_socket.recv(4096)
                if not data:
                    break
            elif PROTOCOL == 'udp':
                data, client_address = client_socket.recvfrom(4096)
            else:
                return
            
            if len(data) < 41:
                continue
            
            # 解析包头
            version = data[0]
            packet_type = data[1]
            token_length = data[2]
            token = data[3:3+token_length]
            stream_id = struct.unpack('!H', data[3+token_length:5+token_length])[0]
            payload_length = struct.unpack('!H', data[5+token_length:7+token_length])[0]
            payload = data[7+token_length:7+token_length+payload_length]
            checksum = struct.unpack('!H', data[-2:])[0]
            
            # 校验和验证
            calculated_checksum = (version + packet_type + token_length + stream_id + payload_length) % 65536
            if checksum != calculated_checksum:
                print("校验和不匹配，丢弃数据包")
                continue
            
            # 解密 payload
            try:
                decrypted_payload = decrypt_payload(payload)
                print(f"[解密数据] {decrypted_payload.decode()}")
            except Exception as e:
                print(f"解密失败: {e}")
                continue
            
            # 处理数据包类型
            with lock:
                if packet_type == 3:  # 心跳响应（pong）
                    clients[client_address] = time.time()
                    print(f"[心跳] 收到客户端 {client_address} 的 pong 响应")
                else:
                    # 构造响应包（普通数据或心跳请求）
                    fake_payload_type = config['fakepayload']
                    fake_payload = fake_payloads.get(fake_payload_type, "I love you <3").encode('utf-8')
                    response_packet = build_fcep_packet(
                        token, 
                        random.randint(1, 65535), 
                        fake_payload, 
                        packet_type=1
                    )
                    
                    # 根据协议发送响应
                    if PROTOCOL == 'tcp':
                        client_socket.sendall(response_packet)
                        print(f"[TCP] 已发送响应包到 {client_address}")
                    elif PROTOCOL == 'udp':
                        client_socket.sendto(response_packet, client_address)  # UDP 使用 sendto
                        print(f"[UDP] 已发送响应包到 {client_address}")
                    
                    # 处理心跳请求（packet_type=2 为 ping，需主动发送 pong？）
                    if packet_type == 2:
                        # 若需要自动响应 ping，可在此处发送 pong
                        pong_payload = b"PONG"
                        pong_packet = build_fcep_packet(token, stream_id, pong_payload, packet_type=3)
                        if PROTOCOL == 'tcp':
                            client_socket.sendall(pong_packet)
                        elif PROTOCOL == 'udp':
                            client_socket.sendto(pong_packet, client_address)
                        print(f"[心跳] 已发送 pong 到 {client_address}")
    finally:
        if PROTOCOL == 'tcp':
            client_socket.close()
        with lock:
            if client_address in clients:
                del clients[client_address]
        print(f"客户端 {client_address} 连接关闭")

def send_heartbeat():
    global clients
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        now = time.time()
        to_remove = []
        with lock:
            for client_address in list(clients.keys()):
                last_pong = clients[client_address]
                if now - last_pong > HEARTBEAT_INTERVAL * 3:
                    print(f"客户端 {client_address} 心跳超时，关闭连接")
                    to_remove.append(client_address)
                else:
                    # 发送心跳请求（ping，packet_type=2）
                    stream_id = random.randint(1, 65535)
                    ping_packet = build_fcep_packet(KEY, stream_id, b"", packet_type=2)
                    try:
                        if PROTOCOL == 'tcp':
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                                s.settimeout(5)
                                s.connect(client_address)
                                s.sendall(ping_packet)
                                print(f"[TCP 心跳] 发送 ping 到 {client_address}")
                        elif PROTOCOL == 'udp':
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                                s.sendto(ping_packet, client_address)
                                print(f"[UDP 心跳] 发送 ping 到 {client_address}")
                    except Exception as e:
                        print(f"发送心跳包失败: {e}")
                        to_remove.append(client_address)
        with lock:
            for c in to_remove:
                if c in clients:
                    del clients[c]

def start_server():
    global PROTOCOL
    load_or_create_config()
    if PROTOCOL == 'tcp':
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', PORT))
        server_socket.listen(5)
        print(f"[TCP] 服务器启动，监听端口 {PORT}...")
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"[TCP] 新连接来自 {client_address}")
            with lock:
                clients[client_address] = time.time()
            threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
    elif PROTOCOL == 'udp':
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('0.0.0.0', PORT))
        print(f"[UDP] 服务器启动，监听端口 {PORT}...")
        while True:
            # UDP 无连接，直接处理数据包
            data, client_address = server_socket.recvfrom(4096)
            print(f"[UDP] 新数据来自 {client_address}")
            threading.Thread(target=handle_client, args=(server_socket, client_address), daemon=True).start()
    else:
        print("不支持的协议类型，仅支持 tcp 或 udp")
        return

if __name__ == "__main__":
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=send_heartbeat, daemon=True).start()
    print("服务器运行中... 按 Ctrl+C 退出")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n服务器关闭")
        sys.exit(0)