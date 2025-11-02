"""Tiny UDP relay used as TURN-style fallback for SR-VNC.

File này hiện thực một relay UDP rất nhỏ — hoạt động giống kiểu TURN cơ bản:
- Các client (host hoặc viewer) gửi control JSON {"type":"register","session":...,"role":...}
  để đăng ký với relay.
- Khi có đủ hai participant cho một session, relay gửi về message {"type":"ready"} cho
  mỗi bên để họ biết có thể bắt đầu gửi dữ liệu (hoặc làm hole-punch).
- Khi nhận payload không phải JSON (tức dữ liệu nhị phân/video/control được mã hoá,...),
  relay sẽ forward (chuyển tiếp) payload đó tới địa chỉ peer tương ứng trong session.
- Mục tiêu: fallback cho trường hợp NAT traversal không thành công — relay trung gian
  sẽ chuyển tiếp gói UDP giữa hai bên.

Lưu ý:
- Đây **không phải** một TURN server đầy đủ tính năng. Nó rất đơn giản, không hỗ trợ
  authentication, không kiểm soát băng thông, không xử lý encryption/timestamp.
- Chỉ dùng cho mục đích phát triển / demo. Tránh dùng trực tiếp trong production
  nếu bảo mật/scale là yêu cầu.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

# Kiểu alias cho địa chỉ socket IPv4: (host, port)
Address = Tuple[str, int]


# -------------------------
# Class Session
# -------------------------
@dataclass
class Session:
    """
    Repr một "phiên" (session) relay, chứa các participant đã đăng ký.

    participants: dict mapping role -> Address. "role" thường là 'host' hoặc 'client'
                  nhưng có thể là bất cứ chuỗi nào client muốn dùng.
    last_update: thời gian cập nhật cuối (dùng để có thể garbage-collect session cũ nếu cần).
    """
    participants: Dict[str, Address] = field(default_factory=dict)
    last_update: float = field(default_factory=time.time)

    def add(self, role: str, address: Address) -> None:
        """
        Thêm hoặc cập nhật participant cho session.
        role: tên vai trò (ví dụ 'host' hoặc 'client')
        address: tuple (ip, port)
        """
        self.participants[role] = address
        self.last_update = time.time()

    def counterpart(self, role: str) -> Address | None:
        """
        Trả về địa chỉ của peer khác trong session.
        Nếu có nhiều hơn 2 participant, hàm này trả participant đầu tiên có role != role truyền vào.
        Nếu không tìm thấy peer => trả None.
        """
        for other_role, addr in self.participants.items():
            if other_role != role:
                return addr
        return None

    def ready(self) -> bool:
        """
        Xem session đã đủ participants để forward dữ liệu chưa.
        Ở đây điều kiện đơn giản: >= 2 participant.
        """
        return len(self.participants) >= 2


# -------------------------
# Class RelayServer
# -------------------------
class RelayServer:
    """Minimal UDP relay that forwards packets once both peers register.

    Hoạt động theo vòng lặp blocking:
    - Nhận gói UDP.
    - Nếu gói bắt đầu bằng '{' (giả sử JSON control), parse JSON:
        - Nếu JSON.type == "register", đăng ký (session, role) -> map addr -> session
        - Khi session có đủ 2 participant, gửi message {"type":"ready"} tới cả hai
    - Ngược lại (data nhị phân), tìm session tương ứng cho src addr và forward
      payload sang peer nếu peer tồn tại.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 7000) -> None:
        # Tạo socket UDP và bind vào host:port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, port))

        # mapping session_id -> Session object
        self.sessions: Dict[str, Session] = {}

        # mapping client address -> (session_id, role)
        # dùng để khi nhận payload nhị phân biết nó thuộc session nào và role nào
        self.addr_to_session: Dict[Address, Tuple[str, str]] = {}

        # flag để điều khiển vòng lặp start/stop
        self._running = threading.Event()

    def start(self) -> None:
        """
        Bắt đầu relay: vòng lặp nhận gói blocking.
        Ghi log địa chỉ đang lắng nghe.
        """
        logging.info("SR-VNC relay listening on %s:%s", *self.socket.getsockname())
        self._running.set()

        # Vòng lặp chính: blocking recvfrom
        while self._running.is_set():
            try:
                data, addr = self.socket.recvfrom(2048)
            except OSError:
                # socket bị đóng hoặc lỗi hệ thống -> thoát vòng lặp
                break

            # Nếu payload bắt đầu bằng '{' giả sử đây là JSON control message
            # (đơn giản và nhanh; không hoàn hảo nếu JSON không bắt đầu bằng '{')
            if data.startswith(b"{"):
                self._handle_control(data, addr)
            else:
                # Ngược lại forward payload nhị phân
                self._forward(addr, data)

    def stop(self) -> None:
        """Dừng relay: clear flag và đóng socket."""
        self._running.clear()
        try:
            self.socket.close()
        except OSError:
            # Nếu socket đã đóng, ignore
            pass

    # -------------------------
    # Xử lý control JSON
    # -------------------------
    def _handle_control(self, payload: bytes, addr: Address) -> None:
        """
        Xử lý control messages (dạng JSON). Hiện chỉ hỗ trợ message type "register".
        Format kỳ vọng:
            {"type":"register", "session": "<session-id>", "role":"host"|"client"}
        """
        try:
            message = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            # Nếu không phải JSON hợp lệ -> ignore
            return

        # Chỉ xử lý message type == "register"
        if message.get("type") != "register":
            return

        # Chuỗi session id (dùng str để an toàn)
        session_id = str(message.get("session"))
        role = message.get("role", "client")

        # Lấy hoặc tạo Session mới
        session = self.sessions.setdefault(session_id, Session())

        # Thêm participant (hoặc cập nhật nếu đã tồn tại)
        session.add(role, addr)

        # Lưu mapping từ địa chỉ tới session để forward khi nhận data
        self.addr_to_session[addr] = (session_id, role)

        logging.info("Registered %s for session %s", addr, session_id)

        # Nếu đã có đủ participants thì gửi ready về cho tất cả participant
        if session.ready():
            for participant in session.participants.values():
                self._send_ready(participant)

    def _send_ready(self, addr: Address) -> None:
        """
        Gửi message small JSON {"type":"ready"} tới địa chỉ addr.
        Dùng để báo cho client/host biết relay đã có peer và có thể bắt đầu gửi dữ liệu.
        """
        message = json.dumps({"type": "ready"}).encode("utf-8")
        try:
            self.socket.sendto(message, addr)
        except OSError:
            # Nếu send thất bại (ví dụ socket lỗi) -> ignore
            pass

    # -------------------------
    # Forwarding payload nhị phân
    # -------------------------
    def _forward(self, src: Address, payload: bytes) -> None:
        """
        Forward payload từ địa chỉ src sang peer tương ứng trong cùng session.
        Bước:
          - Tìm mapping addr->(session_id, role)
          - Lấy session theo session_id
          - Lấy peer address = session.counterpart(role)
          - Gửi payload tới peer (sendto)
        Nếu bất kỳ bước nào không thành công (chưa đăng ký, session không tồn tại, peer chưa có)
        thì payload bị drop (không báo lỗi).
        """
        entry = self.addr_to_session.get(src)
        if not entry:
            # Nếu source không được đăng ký, bỏ qua
            return

        session_id, role = entry
        session = self.sessions.get(session_id)
        if not session:
            return

        peer = session.counterpart(role)
        if not peer:
            return

        try:
            self.socket.sendto(payload, peer)
        except OSError:
            # Nếu send thất bại (ví dụ peer unreachable) -> ignore
            pass


# -------------------------
# Chạy server từ CLI
# -------------------------
def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SR-VNC UDP relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    server = RelayServer(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        # Ctrl+C: dừng cleanly
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
