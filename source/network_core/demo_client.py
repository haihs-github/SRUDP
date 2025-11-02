import socket
import time
from srudp import SRUDPConnection

# --- Setup Client ---
SERVER_HOST = "192.168.29.101"
SERVER_PORT = 12345
PSK = b"day-la-mat-khau-bi-mat-cua-chung-ta"

# test mã khóa không đúng 
# PSK = b"day-la-mat-khau-sai"

# 1. Tạo socket (không cần bind)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 2. Khởi tạo SRUDP, trỏ tới peer là server
conn = SRUDPConnection(
    sock, 
    is_server=False, 
    psk=PSK, 
    peer=(SERVER_HOST, SERVER_PORT)
)

try:
    # 3. Thực hiện handshake với server
    print("[Client] Đang thực hiện handshake...")
    conn.client_handshake(timeout=10.0)
    print("[Client] Handshake thành công!")

    # 4. Khởi chạy các thread
    conn.start()

    # 5. Gửi tin nhắn từ input của người dùng
    print("Nhập tin nhắn để gửi (gõ 'exit' để thoát):")
    while True:
        message = input("> ")
        if message.lower() == 'exit':
            break
        
        # Gửi tin nhắn (reliable)
        conn.send_control_event({"type": "chat", "message": message}, reliable=True)
        print(f"[Client] Đã gửi: {message}")

except Exception as e:
    print(f"[Client] Lỗi: {e}")
finally:
    conn.stop()
    sock.close()
    print("[Client] Đã đóng.")