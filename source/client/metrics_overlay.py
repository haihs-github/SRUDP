"""Utilities for assembling and formatting telemetry overlays."""
# Đây là module chứa các tiện ích để thu thập và hiển thị số liệu (metrics)
# lên giao diện overlay (HUD) trong hệ thống streaming/video relay.

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, List, MutableMapping, Optional, Tuple

# Định nghĩa alias cho kiểu số có thể None
Number = Optional[float]


# ======================= 1️⃣ LocalVideoStats ============================
@dataclass
class LocalVideoStats:
    """Lưu thống kê video render phía client (đầu nhận)."""

    frames: int = 0   # Số khung hình đã render
    bytes: int = 0    # Tổng số byte dữ liệu video render được

    def record_frame(self, payload_size: int) -> None:
        """Ghi nhận thêm một khung hình được render."""
        self.frames += 1
        self.bytes += payload_size  # Cộng thêm dung lượng khung hình

    def snapshot(self) -> Dict[str, int]:
        """Trả về snapshot của số liệu hiện tại (frames & bytes)."""
        return {"render_frames": self.frames, "render_bytes": self.bytes}


# ======================= 2️⃣ _OverlayState ============================
@dataclass
class _OverlayState:
    """Giữ trạng thái nội bộ giữa các lần cập nhật metrics."""
    last_update: float = field(default_factory=time.time)

    # Lưu lại số liệu trước đó để tính chênh lệch (delta)
    prev_conn_control_sent: int = 0
    prev_conn_control_retrans: int = 0
    prev_remote_frames: int = 0
    prev_remote_bytes: int = 0
    prev_render_frames: int = 0
    prev_render_bytes: int = 0


# ======================= 3️⃣ MetricsOverlay ============================
class MetricsOverlay:
    """Tổng hợp và định dạng số liệu cho HUD overlay."""

    def __init__(self) -> None:
        # Khởi tạo trạng thái lưu lần cập nhật trước đó
        self._state = _OverlayState()

    def compose(
        self,
        connection_metrics: MutableMapping[str, float] | None,
        local_metrics: MutableMapping[str, int] | None,
        remote_metrics: MutableMapping[str, float] | None,
    ) -> List[Tuple[str, str]]:
        """
        Kết hợp các số liệu kết nối, local, remote thành danh sách các
        cặp (key, value) để hiển thị trong HUD overlay.
        """

        now = time.time()  # Lấy thời gian hiện tại
        dt = max(now - self._state.last_update, 1e-6)  # Khoảng thời gian trôi qua

        overlay: List[Tuple[str, str]] = []

        # Nếu đầu vào là None thì thay bằng dict rỗng
        conn = connection_metrics or {}
        remote = remote_metrics or {}
        local = local_metrics or {}

        # --- 🛰️ Các số liệu điều khiển kết nối (RTT, mất gói, retransmission...) ---
        overlay.extend(
            [
                ("ctrl_rtt_p50_ms", _fmt_ms(conn.get("rtt_ms_p50"))),
                ("ctrl_rtt_p95_ms", _fmt_ms(conn.get("rtt_ms_p95"))),
                ("ctrl_rtt_p99_ms", _fmt_ms(conn.get("rtt_ms_p99"))),
                ("ctrl_loss_percent", _fmt_percent(conn.get("control_loss_percent"))),
                ("ctrl_est_loss_percent", _fmt_percent(conn.get("control_est_loss_percent"))),
                ("ctrl_retrans", _fmt_int(conn.get("control_retrans"))),
                ("ctrl_inflight", _fmt_int(conn.get("control_inflight"))),
                ("ctrl_ack_base", _fmt_int(conn.get("ack_base"))),
                ("ctrl_sack_blocks", _fmt_int(conn.get("sack_blocks"))),
                ("ctrl_ack_updates", _fmt_int(conn.get("ack_updates"))),
            ]
        )

        # --- 📡 Tính toán FPS và bitrate của video gửi ---
        remote_frames = int(remote.get("video_frames", conn.get("video_frames", 0)) or 0)
        remote_bytes = int(remote.get("video_bytes", conn.get("video_bytes", 0)) or 0)

        # Tính fps gửi video = (số frame mới gửi) / (thời gian trôi)
        send_fps = (remote_frames - self._state.prev_remote_frames) / dt

        # Tính Mbps gửi = (số byte mới gửi * 8) / (dt * 1,000,000)
        send_mbps = _bytes_to_mbps(remote_bytes - self._state.prev_remote_bytes, dt)

        overlay.append(("video_send_fps", f"{max(send_fps, 0.0):.2f}"))
        overlay.append(("video_send_mbps", f"{max(send_mbps, 0.0):.2f}"))

        # Thêm jitter (dao động độ trễ video)
        overlay.append(
            (
                "video_jitter_p95_ms",
                _fmt_ms(remote.get("video_jitter_p95_ms", conn.get("video_jitter_p95_ms"))),
            )
        )

        # --- 🖥️ Tính toán FPS và bitrate render phía client ---
        render_frames = int(local.get("render_frames", 0) or 0)
        render_bytes = int(local.get("render_bytes", 0) or 0)
        render_fps = (render_frames - self._state.prev_render_frames) / dt
        render_mbps = _bytes_to_mbps(render_bytes - self._state.prev_render_bytes, dt)
        overlay.append(("video_render_fps", f"{max(render_fps, 0.0):.2f}"))
        overlay.append(("video_render_mbps", f"{max(render_mbps, 0.0):.2f}"))

        # --- Nếu phía host gửi thêm các chỉ số cụ thể thì hiển thị ---
        if "host_video_fps" in remote:
            overlay.append(("host_video_fps", f"{max(float(remote['host_video_fps']), 0.0):.2f}"))
        if "host_video_mbps" in remote:
            overlay.append(("host_video_mbps", f"{max(float(remote['host_video_mbps']), 0.0):.2f}"))

        # --- Cập nhật trạng thái để tính delta cho lần tiếp theo ---
        self._state.prev_remote_frames = remote_frames
        self._state.prev_remote_bytes = remote_bytes
        self._state.prev_render_frames = render_frames
        self._state.prev_render_bytes = render_bytes
        self._state.last_update = now

        return overlay


# ======================= 4️⃣ Hàm định dạng và tính toán ============================

def _fmt_ms(value: Number) -> str:
    """Định dạng giá trị mili-giây (RTT, jitter) với 2 chữ số thập phân."""
    if value is None:
        return "n/a"
    return f"{float(value or 0.0):.2f}"


def _fmt_percent(value: Number) -> str:
    """Định dạng phần trăm mất gói, 2 chữ số thập phân."""
    if value is None:
        return "n/a"
    return f"{float(value or 0.0):.2f}"


def _fmt_int(value: Number) -> str:
    """Định dạng giá trị integer (số lượng gói, ack, retrans, v.v)."""
    if value is None:
        return "0"
    return f"{int(float(value))}"


def _bytes_to_mbps(delta_bytes: int, dt: float) -> float:
    """Chuyển đổi byte/s thành megabit/s (Mbps)."""
    if dt <= 0:
        return 0.0
    # delta_bytes * 8 => chuyển sang bit, chia cho 1e6 để ra Mbps
    return (max(delta_bytes, 0) * 8.0) / (dt * 1_000_000)
