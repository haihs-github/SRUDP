"""SR-VNC controller implementation."""
from __future__ import annotations

import hashlib
import io
import logging
import queue
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple

import tkinter as tk
from PIL import Image, ImageTk

# Import các module nội bộ hỗ trợ
from source.network_core.nat import RelayClient, RelayConfig, discover_reflexive_address, send_hole_punch
from source.client.metrics_overlay import LocalVideoStats, MetricsOverlay
from source.network_core.srudp import SRUDPConnection

# Cấu hình log cơ bản (in ra màn hình terminal)
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


# ============================
# 1️⃣ Cấu hình client
# ============================
@dataclass
class ClientConfig:
    """Lưu toàn bộ thông tin cấu hình của client SR-VNC."""

    host: str = "0.0.0.0"               # Địa chỉ local (máy client) để bind socket
    port: int = 5001                    # Cổng UDP local
    server_host: str = "127.0.0.1"      # Địa chỉ máy chủ SR-VNC
    server_port: int = 5000             # Cổng UDP máy chủ
    password: str = "changeme"          # Mật khẩu dùng để tạo khóa mã hóa (PSK)
    stun_server: Optional[str] = None   # Nếu có, dùng để NAT traversal qua STUN
    relay: Optional[str] = None         # Nếu có, dùng relay server (TURN style)
    session: str = "srvnc-demo"         # Tên phiên kết nối (session)
    bitrate: int = 2_000_000            # Bitrate video (2 Mbps mặc định)


# ============================
# 2️⃣ Lớp giao diện hiển thị video
# ============================
class VideoWindow:
    """Cửa sổ hiển thị video và bắt sự kiện bàn phím/chuột."""

    def __init__(self, client: "SRVNCClient") -> None:
        self.client = client
        # Tạo cửa sổ chính Tkinter
        self.root = tk.Tk()
        self.root.title("SR-VNC Client")

        # Label để hiển thị khung hình
        self.label = tk.Label(self.root)
        self.label.pack(fill=tk.BOTH, expand=True)

        # Biến để lưu ảnh hiển thị
        self._photo: Optional[ImageTk.PhotoImage] = None
        # Hàng đợi chứa các frame nhận được từ server
        self._frames: "queue.Queue[bytes]" = queue.Queue()

        # Hiển thị overlay (thông tin bitrate, ping, packet loss,...)
        self.overlay_var = tk.StringVar(value="")
        self.overlay = tk.Label(
            self.root,
            textvariable=self.overlay_var,
            anchor="nw",
            justify="left",
            bg="#101010",
            fg="#00ff5f",
            font=("TkFixedFont", 10),
        )
        self.overlay.place(relx=0.0, rely=0.0, anchor="nw")

        # Gán các sự kiện bàn phím & chuột
        self.root.bind("<Motion>", self._on_motion)
        self.root.bind("<ButtonPress>", self._on_button_press)
        self.root.bind("<ButtonRelease>", self._on_button_release)
        self.root.bind("<KeyPress>", self._on_key_press)
        self.root.bind("<KeyRelease>", self._on_key_release)
        # Khi resize cửa sổ thì giữ focus
        self.root.bind("<Configure>", lambda event: self.root.focus_set())

        # Lên lịch 30ms/lần đọc frame mới và hiển thị
        self.root.after(30, self._pump_frames)

    # Cập nhật thông tin overlay (telemetry metrics)
    def update_overlay(self, metrics) -> None:
        lines = ["SR-VNC Telemetry"]
        if isinstance(metrics, dict):
            items = sorted(metrics.items())
        else:
            items = metrics
        for key, value in items:
            lines.append(f"{key}: {value}")
        text = "\n".join(lines)
        # Gửi cập nhật tới UI thread
        self.root.after(0, self.overlay_var.set, text)

    # Đưa frame vào hàng đợi (gọi từ thread nhận video)
    def enqueue_frame(self, frame: bytes) -> None:
        self._frames.put(frame)

    # Hàm hiển thị frame từ hàng đợi
    def _pump_frames(self) -> None:
        updated = False
        while True:
            try:
                frame = self._frames.get_nowait()
            except queue.Empty:
                break
            try:
                # Chuyển bytes thành ảnh
                image = Image.open(io.BytesIO(frame))
            except Exception:
                continue
            # Dùng PhotoImage của Tkinter để hiển thị
            self._photo = ImageTk.PhotoImage(image=image)
            self.label.configure(image=self._photo)
            # Ghi lại thông tin để tính FPS, throughput
            self.client.record_render(len(frame))
            updated = True
        if updated:
            self.root.update_idletasks()
        # Tiếp tục lặp lại sau 30ms
        self.root.after(30, self._pump_frames)

    # ------------------- Xử lý sự kiện input -------------------
    def _on_motion(self, event: tk.Event) -> None:
        self.client.send_mouse_move(int(event.x), int(event.y))

    def _on_button_press(self, event: tk.Event) -> None:
        button = self._tk_button_to_name(event.num)
        self.client.send_mouse_click(int(event.x), int(event.y), button=button, pressed=True)

    def _on_button_release(self, event: tk.Event) -> None:
        button = self._tk_button_to_name(event.num)
        self.client.send_mouse_click(int(event.x), int(event.y), button=button, pressed=False)

    def _on_key_press(self, event: tk.Event) -> None:
        key = self._normalize_key(event.keysym)
        if key:
            self.client.send_key_event(key, pressed=True)

    def _on_key_release(self, event: tk.Event) -> None:
        key = self._normalize_key(event.keysym)
        if key:
            self.client.send_key_event(key, pressed=False)

    # Chuyển mã số chuột sang tên
    @staticmethod
    def _tk_button_to_name(num: int) -> str:
        return {1: "left", 2: "middle", 3: "right"}.get(num, "left")

    # Chuẩn hóa tên phím (ví dụ "Return" -> "enter")
    @staticmethod
    def _normalize_key(keysym: str) -> Optional[str]:
        if len(keysym) == 1:
            return keysym.lower()
        special_map = {
            "Return": "enter",
            "Escape": "esc",
            "BackSpace": "backspace",
            "Tab": "tab",
            "Shift_L": "shift",
            "Shift_R": "shift",
            "Control_L": "ctrl",
            "Control_R": "ctrl",
            "Alt_L": "alt",
            "Alt_R": "alt",
            "Super_L": "win",
            "Super_R": "win",
        }
        return special_map.get(keysym)


# ============================
# 3️⃣ Lớp chính SRVNCClient
# ============================
class SRVNCClient:
    """Client SR-VNC – xử lý truyền thông UDP, video và input."""

    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        # Tạo socket UDP và bind vào host/port local
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((config.host, config.port))

        # Cửa sổ hiển thị video
        self.window = VideoWindow(self)

        # Biến lưu seq frame cuối cùng
        self._last_frame_seq = 0
        # Cờ điều khiển vòng lặp chạy
        self._running = threading.Event()
        # Thread hiển thị thống kê
        self._stats_thread: Optional[threading.Thread] = None
        # Kết nối SRUDP (mạng bảo mật, tin cậy)
        self.connection: Optional[SRUDPConnection] = None

        # Các công cụ thống kê và overlay
        self._metrics_overlay = MetricsOverlay()
        self._local_video = LocalVideoStats()
        self._metrics_lock = threading.Lock()
        self._pending_metrics: Optional[dict] = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        """Khởi động client và thực hiện bắt tay kết nối."""
        logging.info(
            "Starting SR-VNC client on %s:%s talking to %s:%s",
            self.config.host,
            self.config.port,
            self.config.server_host,
            self.config.server_port,
        )
        self._running.set()

        # Thiết lập kênh truyền (trực tiếp, STUN hoặc relay)
        peer = self._prepare_transport()

        # Dùng SHA256(password) làm khóa tiền chia sẻ (PSK)
        psk = hashlib.sha256(self.config.password.encode("utf-8")).digest()

        # Tạo kết nối SRUDP (giao thức UDP bảo mật, có xác thực)
        self.connection = SRUDPConnection(
            self.socket,
            is_server=False,
            peer=peer,
            psk=psk,
        )

        # Đăng ký callback khi nhận video/control/ack
        self.connection.register_video_handler(self._handle_video)
        self.connection.register_ack_handler(self._handle_ack)
        self.connection.register_control_handler(self._handle_control_message)

        # Thiết lập bitrate và bắt đầu bắt tay
        self.connection.set_video_bitrate(self.config.bitrate)
        self.connection.client_handshake()
        self.connection.start()

        # Thread hiển thị thống kê
        self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self._stats_thread.start()

        # Chạy giao diện chính (blocking)
        try:
            self.window.root.mainloop()
        finally:
            self.stop()

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Dừng client và đóng kết nối."""
        if not self._running.is_set():
            return
        self._running.clear()
        connection = self.connection
        if connection is not None:
            try:
                connection.stop()
            finally:
                self.connection = None
        self.socket.close()

    # ------------------------------------------------------------------
    # Các hàm gửi input tới server
    def send_mouse_move(self, x: int, y: int) -> None:
        event = {"type": "mouse_move", "x": x, "y": y}
        if self.connection:
            self.connection.send_control_event(event)

    def send_mouse_click(self, x: int, y: int, *, button: str, pressed: bool) -> None:
        event = {
            "type": "mouse_click",
            "x": x,
            "y": y,
            "button": button,
            "clicks": 1,
            "pressed": pressed,
        }
        if self.connection:
            self.connection.send_control_event(event)

    def send_key_event(self, key: str, *, pressed: bool) -> None:
        event = {"type": "key_down" if pressed else "key_up", "key": key}
        if self.connection:
            self.connection.send_control_event(event)

    # ------------------------------------------------------------------
    # Hàm callback khi nhận video / ack / control
    def _handle_video(self, seq: int, payload: bytes, address: Tuple[str, int]) -> None:
        if seq <= self._last_frame_seq:
            return
        self._last_frame_seq = seq
        self.window.enqueue_frame(payload)

    def _handle_ack(self, sequences) -> None:
        logging.debug("ACK received for sequences %s", list(sequences))

    def _handle_control_message(self, seq: int, body: dict, address: Tuple[str, int]) -> None:
        if body.get("type") == "metrics":
            metrics = body.get("values", {})
            with self._metrics_lock:
                self._pending_metrics = metrics

    # ------------------------------------------------------------------
    # Vòng lặp cập nhật overlay (1 giây/lần)
    def _stats_loop(self) -> None:
        while self._running.is_set():
            connection_metrics: dict = {}
            if self.connection:
                connection_metrics = self.connection.get_metrics()
                logging.debug("Client metrics: %s", connection_metrics)
            with self._metrics_lock:
                local_metrics = self._local_video.snapshot()
                remote_metrics = dict(self._pending_metrics) if self._pending_metrics else {}
            overlay = self._metrics_overlay.compose(connection_metrics, local_metrics, remote_metrics)
            if overlay:
                self.window.update_overlay(overlay)
            time.sleep(1.0)

    # Ghi nhận thông tin khung hình render (để tính FPS, throughput)
    def record_render(self, payload_size: int) -> None:
        with self._metrics_lock:
            self._local_video.record_frame(payload_size)

    # ------------------------------------------------------------------
    # Chuẩn bị kênh truyền UDP
    def _prepare_transport(self) -> Tuple[str, int]:
        peer = (self.config.server_host, self.config.server_port)
        if self.config.stun_server:
            # Thực hiện STUN để biết địa chỉ công khai của client (nếu NAT)
            stun_host, stun_port = parse_host_port(self.config.stun_server, 19302)
            reflexive = discover_reflexive_address(self.socket, (stun_host, stun_port))
            if reflexive:
                logging.info("Client reflexive address %s:%s", *reflexive)
        if self.config.relay:
            # Nếu có relay, đăng ký qua relay server
            relay_host, relay_port = parse_host_port(self.config.relay, 7000)
            relay = RelayClient(RelayConfig((relay_host, relay_port), self.config.session))
            if not relay.register(self.socket, role="client"):
                raise RuntimeError("Failed to register with relay server")
            peer = (relay_host, relay_port)
            logging.info("Using relay %s:%s for session %s", relay_host, relay_port, self.config.session)
        else:
            # Nếu không dùng relay, gửi UDP hole punching tới server
            send_hole_punch(self.socket, peer)
        return peer


# ============================
# 4️⃣ Hàm main (entry point)
# ============================
def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SR-VNC client")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=5000)
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--stun-server")
    parser.add_argument("--relay")
    parser.add_argument("--session", default=str(uuid.uuid4()))
    parser.add_argument("--bitrate", type=int, default=2_000_000)
    args = parser.parse_args()

    # Tạo cấu hình và khởi động client
    client = SRVNCClient(
        ClientConfig(
            host=args.host,
            port=args.port,
            server_host=args.server_host,
            server_port=args.server_port,
            password=args.password,
            stun_server=args.stun_server,
            relay=args.relay,
            session=args.session,
            bitrate=args.bitrate,
        )
    )
    try:
        client.start()
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()


# ============================
# 5️⃣ Hàm phụ tiện ích
# ============================
def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    """Phân tích chuỗi host:port."""
    if ":" in value:
        host, port_str = value.rsplit(":", 1)
        return host, int(port_str)
    return value, default_port


if __name__ == "__main__":
    main()
