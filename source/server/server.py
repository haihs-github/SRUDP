"""SR-VNC host implementation."""
# File này hiện thực phần "host" (máy chủ) của hệ thống SR-VNC
# SR-VNC là một công cụ remote desktop (điều khiển máy tính từ xa) sử dụng giao thức UDP tùy chỉnh gọi là SRUDP.

from __future__ import annotations  # Cho phép dùng kiểu trả về là chính class hiện tại (Python 3.7+)
import hashlib       # Dùng để tạo khóa mã hóa từ password (SHA-256)
import io            # Dùng để xử lý dữ liệu hình ảnh trong bộ nhớ (không cần file)
import logging       # Dùng để ghi log ra terminal
import socket        # Thư viện socket cơ bản của Python (để gửi/nhận dữ liệu qua mạng)
import threading     # Dùng để chạy nhiều luồng song song (VD: gửi hình, đo hiệu năng)
import time          # Dùng để tạo độ trễ hoặc đo thời gian giữa các frame
from dataclasses import dataclass  # Giúp định nghĩa lớp cấu hình gọn gàng
from typing import Optional, Tuple  # Gợi ý kiểu dữ liệu

import pyautogui     # Thư viện để điều khiển chuột, bàn phím, v.v.
from PIL import ImageGrab  # Thư viện Pillow: dùng để chụp ảnh màn hình

# Import các module nội bộ của dự án SR-VNC
from .nat import RelayClient, RelayConfig, discover_reflexive_address, send_hole_punch
from .srudp import SRUDPConnection  # Giao thức truyền dữ liệu tùy chỉnh (UDP có bảo đảm hơn)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
pyautogui.FAILSAFE = False  # Tắt chế độ an toàn (không dừng nếu chuột chạm góc màn hình)


# ========================== CẤU HÌNH SERVER ==========================
@dataclass
class ServerConfig:
    """Cấu hình server cơ bản"""
    host: str = "0.0.0.0"           # Địa chỉ IP mà server lắng nghe (0.0.0.0 = tất cả)
    port: int = 5000                # Cổng UDP mà server dùng
    client_host: str = "127.0.0.1"  # Địa chỉ IP client để gửi hình ảnh tới
    client_port: int = 5001         # Cổng mà client đang lắng nghe
    password: str = "changeme"      # Mật khẩu bảo vệ kết nối
    fps: int = 10                   # Số khung hình gửi mỗi giây
    stun_server: Optional[str] = None  # Server STUN để tìm IP thực khi NAT
    relay: Optional[str] = None        # Địa chỉ relay server (dùng nếu NAT không cho xuyên)
    session: str = "srvnc-demo"       # Tên phiên kết nối
    bitrate: int = 2_000_000          # Giới hạn bitrate (bit/giây)


# ========================== LỚP CHÍNH SRVNCServer ==========================
class SRVNCServer:
    """Remote desktop host using the SRUDP transport."""

    def __init__(self, config: ServerConfig) -> None:
        # Lưu cấu hình
        self.config = config
        # Tạo socket UDP để gửi/nhận dữ liệu
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Ràng buộc socket với IP và cổng được cấu hình
        self.socket.bind((config.host, config.port))
        # Cờ điều khiển trạng thái chạy
        self._running = threading.Event()
        # Các luồng phụ để gửi video và đo hiệu suất
        self._video_thread: Optional[threading.Thread] = None
        self._metrics_thread: Optional[threading.Thread] = None
        # Đối tượng kết nối SRUDP
        self.connection: Optional[SRUDPConnection] = None
        # Khóa để đồng bộ dữ liệu đếm frame/bytes
        self._metrics_lock = threading.Lock()
        self._sent_frames = 0
        self._sent_bytes = 0


    # ========================== HÀM KHỞI ĐỘNG SERVER ==========================
    def start(self) -> None:
        logging.info(
            "Starting SR-VNC host on %s:%s targeting %s:%s",
            self.config.host,
            self.config.port,
            self.config.client_host,
            self.config.client_port,
        )
        self._running.set()

        # Thiết lập địa chỉ của client (có thể qua STUN/Relay)
        peer = self._prepare_transport()

        # Tạo khóa mã hóa từ mật khẩu (SHA256)
        psk = hashlib.sha256(self.config.password.encode("utf-8")).digest()

        # Tạo kết nối SRUDP (UDP đáng tin cậy + mã hóa)
        self.connection = SRUDPConnection(
            self.socket,
            is_server=True,
            cookie_secret=None,
            psk=psk,
            peer=peer,
        )

        # Đăng ký hàm callback khi có control (chuột, bàn phím) và khi nhận ACK
        self.connection.register_control_handler(self._handle_control)
        self.connection.register_ack_handler(self._handle_ack)

        # Thiết lập bitrate truyền hình ảnh
        self.connection.set_video_bitrate(self.config.bitrate)

        # Bắt tay kết nối (handshake)
        self.connection.server_handshake()

        # Bắt đầu kết nối
        self.connection.start()

        # Tạo 2 luồng riêng biệt: 1 gửi hình, 1 đo hiệu suất
        self._video_thread = threading.Thread(target=self._video_loop, daemon=True)
        self._video_thread.start()

        self._metrics_thread = threading.Thread(target=self._metrics_loop, daemon=True)
        self._metrics_thread.start()


    # ========================== DỪNG SERVER ==========================
    def stop(self) -> None:
        logging.info("Stopping SR-VNC host")
        self._running.clear()
        if self._video_thread:
            self._video_thread.join(timeout=1.0)
        if self._metrics_thread:
            self._metrics_thread.join(timeout=1.0)
        if self.connection is not None:
            try:
                self.connection.stop()
            finally:
                self.connection = None
        self.socket.close()


    # ========================== GỬI HÌNH ẢNH LIÊN TỤC ==========================
    def _video_loop(self) -> None:
        frame_interval = 1.0 / max(1, self.config.fps)  # thời gian giữa 2 frame
        while self._running.is_set() and self.connection:
            start = time.time()
            frame = ImageGrab.grab()  # chụp màn hình hiện tại

            # Giảm độ phân giải xuống 50% để tiết kiệm băng thông
            try:
                w, h = frame.size
                frame = frame.resize((max(1, w // 2), max(1, h // 2)))
            except Exception:
                pass

            # Chuyển ảnh sang dạng byte (JPEG)
            buffer = io.BytesIO()
            frame.save(buffer, format="JPEG", quality=45)  # chất lượng thấp hơn = nhẹ hơn
            data = buffer.getvalue()

            # Gửi frame qua SRUDP
            self.connection.send_video_frame(data)

            # Ghi lại thống kê
            with self._metrics_lock:
                self._sent_frames += 1
                self._sent_bytes += len(data)

            elapsed = time.time() - start
            # Chờ tới thời điểm gửi frame tiếp theo
            time.sleep(max(0.0, frame_interval - elapsed))


    # ========================== GỬI SỐ LIỆU HIỆU SUẤT ==========================
    def _metrics_loop(self) -> None:
        last_frames = 0
        last_bytes = 0
        last_time = time.time()
        while self._running.is_set() and self.connection:
            now = time.time()
            with self._metrics_lock:
                frames = self._sent_frames
                bytes_sent = self._sent_bytes
            dt = max(now - last_time, 1e-6)
            fps = (frames - last_frames) / dt
            mbps = ((bytes_sent - last_bytes) * 8.0) / (dt * 1_000_000)
            extra = {
                "host_video_fps": max(fps, 0.0),
                "host_video_mbps": max(mbps, 0.0),
                "video_frames": frames,
                "video_bytes": bytes_sent,
            }
            self.connection.send_metrics_overlay(extra=extra)
            last_frames, last_bytes, last_time = frames, bytes_sent, now
            time.sleep(1.0)


    # ========================== NHẬN LỆNH ĐIỀU KHIỂN ==========================
    def _handle_control(self, seq: int, message: dict, address: Tuple[str, int]) -> None:
        """Xử lý các thông điệp điều khiển (chuột, bàn phím) gửi từ client."""
        event_type = message.get("type")
        try:
            if event_type == "mouse_move":
                pyautogui.moveTo(message.get("x"), message.get("y"), duration=message.get("duration", 0.0))
            elif event_type == "mouse_click":
                if message.get("pressed", True):
                    pyautogui.mouseDown(x=message["x"], y=message["y"], button=message.get("button", "left"))
                else:
                    pyautogui.mouseUp(x=message["x"], y=message["y"], button=message.get("button", "left"))
            elif event_type == "key_down":
                pyautogui.keyDown(message.get("key"))
            elif event_type == "key_up":
                pyautogui.keyUp(message.get("key"))
            elif event_type == "type_text":
                pyautogui.typewrite(message.get("text", ""), interval=message.get("interval", 0.0))
            else:
                logging.debug("Unknown control message: %s", message)
        except Exception as exc:
            logging.error("Failed to execute control command %s: %s", message, exc)

    def _handle_ack(self, sequences) -> None:
        logging.debug("Reliable control acknowledged: %s", list(sequences))


    # ========================== THIẾT LẬP KẾT NỐI MẠNG ==========================
    def _prepare_transport(self) -> Tuple[str, int]:
        """Tạo kết nối P2P hoặc qua relay"""
        peer = (self.config.client_host, self.config.client_port)

        # Nếu có STUN server, dùng nó để xác định IP thật (reflexive address)
        if self.config.stun_server:
            stun_host, stun_port = parse_host_port(self.config.stun_server, 19302)
            reflexive = discover_reflexive_address(self.socket, (stun_host, stun_port))
            if reflexive:
                logging.info("Server reflexive address %s:%s", *reflexive)

        # Nếu có relay server, đăng ký và truyền qua đó
        if self.config.relay:
            relay_host, relay_port = parse_host_port(self.config.relay, 7000)
            relay = RelayClient(RelayConfig((relay_host, relay_port), self.config.session))
            if not relay.register(self.socket, role="host"):
                raise RuntimeError("Failed to register with relay server")
            peer = (relay_host, relay_port)
            logging.info("Using relay %s:%s for session %s", relay_host, relay_port, self.config.session)
        else:
            # Nếu không có relay thì thử gửi "hole punch" (kỹ thuật xuyên NAT)
            send_hole_punch(self.socket, peer)

        return peer


# ========================== CHẠY CHƯƠNG TRÌNH ==========================
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="SR-VNC host")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--client-host", default="127.0.0.1")
    parser.add_argument("--client-port", type=int, default=5001)
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--fps", type=int, default=10)
    parser.add_argument("--stun-server")
    parser.add_argument("--relay")
    parser.add_argument("--session", default="srvnc-demo")
    parser.add_argument("--bitrate", type=int, default=2_000_000)
    args = parser.parse_args()

    # Tạo server và bắt đầu chạy
    server = SRVNCServer(ServerConfig(**vars(args)))
    try:
        server.start()
        logging.info("SR-VNC host ready")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()


# ========================== HÀM TIỆN ÍCH ==========================
def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    """Tách chuỗi 'ip:port' thành tuple (ip, port)"""
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        return host, int(port_str)
    return value, default_port
