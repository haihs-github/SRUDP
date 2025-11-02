import socket

# Dùng IP của bạn, hoặc '127.0.0.1' nếu chạy trên cùng 1 máy
HOST = "192.168.29.101" 
PORT = 12346  # <-- Chú ý: Dùng port 12346 (khác port cũ)

# 1. Tạo socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))
print(f"[UDP Server] Đang lắng nghe trên {HOST}:{PORT}")

try:
    while True:
        # 2. Chờ nhận dữ liệu
        data, addr = sock.recvfrom(1024) 
        
        # 3. Giải mã và in ra
        message = data.decode('utf-8')
        print(f"[UDP Server] Nhận từ {addr}: {message}")

except KeyboardInterrupt:
    print("\n[UDP Server] Đã đóng.")
finally:
    sock.close()