import socket
import time
from srudp import SRUDPConnection

# Hàm handler để xử lý khi nhận được event
def handle_control(seq, event, addr):
    # Lấy 'type' của event
    event_type = event.get('type')

    if event_type == 'chat':
        # Nếu là event 'chat', in ra tin nhắn
        message = event.get('message')
        print(f"[Server] Nhận tin nhắn chat từ {addr}: {message}")
    
    elif event_type == 'keepalive':
        # Nếu là 'keepalive', chúng ta có thể lờ đi hoặc log riêng
        # print(f"[Server] Nhận keepalive từ {addr}")
        pass # Lờ đi cho đỡ rối log
    
    else:
        # Cho các loại event không xác định
        print(f"[Server] Nhận event '{event_type}' từ {addr}")

# --- Setup Server ---
HOST = "192.168.29.101"
PORT = 12345
PSK = b"day-la-mat-khau-bi-mat-cua-chung-ta"

# 1. Tạo socket UDP cơ bản
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print(f"[Server] Đang lắng nghe trên {HOST}:{PORT}")

# 2. Khởi tạo SRUDP
# (psk là Pre-Shared Key, dùng cho cả 2 thí nghiệm)
conn = SRUDPConnection(sock, is_server=True, psk=PSK)

try:
    # 3. Chờ và thực hiện handshake với client
    print("[Server] Đang chờ client handshake...")
    client_addr = conn.server_handshake(timeout=60.0)
    print(f"[Server] Handshake thành công với {client_addr}!")

    # 4. Đăng ký handler và khởi chạy các thread (recv, retransmit...)
    conn.register_control_handler(handle_control)
    conn.start()

    # Giữ server sống
    while True:
        time.sleep(100)

except Exception as e:
    print(f"[Server] Lỗi: {e}")
finally:
    conn.stop()
    sock.close()
    print("[Server] Đã đóng.")