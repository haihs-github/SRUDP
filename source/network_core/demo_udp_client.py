import socket

SERVER_HOST = "192.168.29.101" # IP của server
SERVER_PORT = 12346            # Port của server

# 1. Tạo socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Nhập tin nhắn (gõ 'exit' để thoát):")

try:
    while True:
        message = input("> ")
        if message.lower() == 'exit':
            break
        
        # 2. Gửi thẳng tin nhắn (đã encode)
        sock.sendto(message.encode('utf-8'), (SERVER_HOST, SERVER_PORT))
        print(f"[UDP Client] Đã gửi: {message}")
finally:
    sock.close()