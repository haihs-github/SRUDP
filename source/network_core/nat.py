"""NAT traversal helpers for SR-VNC.

Module này cung cấp các hàm/ lớp giúp:
- Khám phá địa chỉ reflexive (public) qua STUN (discover_reflexive_address).
- Gửi các gói nhỏ để hỗ trợ UDP hole punching (send_hole_punch).
- Hỗ trợ client đăng ký với một UDP relay đơn giản (RelayClient).
File thiết kế cho mục đích demo/dev, không phải giải pháp production hoàn chỉnh.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

# STUN constants (the module uses a very small subset of STUN)
STUN_BINDING_REQUEST = 0x0001
STUN_MAGIC_COOKIE = 0x2112A442
STUN_ATTRIBUTE_XOR_MAPPED = 0x0020

# Alias kiểu: (host, port)
Address = Tuple[str, int]


# -------------------------
# STUN: build request
# -------------------------
def build_stun_request() -> tuple[bytes, bytes]:
    """
    Tạo một STUN Binding Request đơn giản.

    Trả về:
      (header_bytes, transaction_id)

    - transaction_id: 12 bytes ngẫu nhiên dùng để khớp request/response.
    - header được cấu trúc theo RFC5389: type(2) | length(2) | magic(4) | transaction_id(12)
      Ở đây length = 0 (không attribute nào trong request).
    """
    # Transaction ID: 12 bytes ngẫu nhiên, dùng để nhận diện response tương ứng
    transaction_id = os.urandom(12)
    # Pack header theo network byte order (!): H=unsigned short, I=unsigned int, 12s=12-byte string
    header = struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE, transaction_id)
    return header, transaction_id


# -------------------------
# STUN: parse XOR-MAPPED-ADDRESS attribute
# -------------------------
def parse_xor_mapped_attribute(data: bytes) -> Optional[Address]:
    """
    Phân tích response STUN để lấy XOR-MAPPED-ADDRESS (IP public và port).

    Lưu ý:
    - Hàm này mong đợi toàn bộ STUN message (header + attributes).
    - Nó tìm attribute có type STUN_ATTRIBUTE_XOR_MAPPED và giải mã IP/port theo RFC5389.
    - Nếu không tìm được hoặc dữ liệu không hợp lệ, trả về None.

    Trả về:
      (ip_str, port) hoặc None nếu không tìm thấy.
    """
    # Kiểm tra kích thước tối thiểu (header STUN 20 bytes)
    if len(data) < 20:
        return None

    # Đọc message header: type (2), length (2), magic cookie (4)
    # Chú ý: chúng ta chỉ cần cookie để giải XOR later
    message_type, length, cookie = struct.unpack("!HHI", data[:8])

    # Chỉ xử lý Binding Success Response (0x0101)
    if message_type != 0x0101:
        return None

    # Transaction ID nằm ngay sau header
    transaction_id = data[8:20]

    # Offset bắt đầu đọc attributes
    offset = 20
    end = 20 + length

    # Duyệt các attribute (type(2), length(2), value(length), padded-to-4)
    while offset + 4 <= end and offset + 4 <= len(data):
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        value = data[offset : offset + attr_len]
        offset += attr_len
        # Attribute được padded tới bội số 4 bytes
        offset += (4 - (attr_len % 4)) % 4

        # Nếu attribute không phải XOR-MAPPED thì bỏ qua
        if attr_type != STUN_ATTRIBUTE_XOR_MAPPED:
            continue

        # Giá trị phải có ít nhất 8 bytes (family + port + ip)
        if len(value) < 8:
            continue

        # value layout: 0 (reserved) | family(1) | xport(2) | xaddress...
        family = value[1]
        # Port được XOR với cookie >> 16 (the high 16 bits of magic cookie)
        port = struct.unpack("!H", value[2:4])[0] ^ (cookie >> 16)

        if family == 0x01:  # IPv4
            # IPv4: next 4 bytes là xored IP
            ip_xor = struct.unpack("!I", value[4:8])[0]
            ip_int = ip_xor ^ cookie  # XOR với magic cookie để lấy IP thực
            ip_bytes = struct.pack("!I", ip_int)
            ip = socket.inet_ntoa(ip_bytes)
            return ip, port

        elif family == 0x02 and len(value) >= 20:  # IPv6 (nhiều byte hơn)
            # IPv6 XOR uses cookie (4 bytes) + transaction_id (12 bytes)
            xor_bytes = value[4:20]
            cookie_bytes = struct.pack("!I", cookie) + transaction_id
            # XOR từng byte để thu về địa chỉ IPv6 gốc
            ip_bytes = bytes(a ^ b for a, b in zip(xor_bytes, cookie_bytes))
            ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
            return ip, port

    # Nếu không tìm attribute phù hợp -> None
    return None


# -------------------------
# Public API: discover_reflexive_address
# -------------------------
def discover_reflexive_address(
    sock: socket.socket, server: Address = ("stun.l.google.com", 19302), timeout: float = 2.0
) -> Optional[Address]:
    """
    Gửi STUN Binding Request tới server STUN và nhận lại địa chỉ reflexive (IP:port public)
    mà NAT ánh xạ cho socket này.

    Thông số:
      - sock: socket UDP đã bind cục bộ.
      - server: (host, port) của STUN server.
      - timeout: thời gian chờ tổng thể cho thao tác (giây).

    Trả về:
      - (ip, port) công khai nếu thành công, hoặc None nếu timeout/không nhận được.
    """
    # Lưu timeout trước đó để phục hồi sau khi xong
    previous_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        # Tạo request STUN
        request, _ = build_stun_request()
        # Gửi tới server STUN
        sock.sendto(request, server)

        # Đọc response cho đến khi gặp response từ đúng server (addr == server)
        while True:
            response, addr = sock.recvfrom(2048)
            # Bỏ qua response từ nơi khác (an toàn)
            if addr != server:
                continue
            # Thử parse XOR-MAPPED attribute
            mapped = parse_xor_mapped_attribute(response)
            if mapped:
                return mapped
    except socket.timeout:
        # Nếu hết thời gian chờ => trả None
        return None
    finally:
        # Khôi phục timeout ban đầu cho socket
        sock.settimeout(previous_timeout)


# -------------------------
# Hole punching helper
# -------------------------
def send_hole_punch(sock: socket.socket, peer: Address, duration: float = 2.0, interval: float = 0.1) -> None:
    """
    Gửi các datagram rỗng (hoặc payload nhỏ) tới peer theo khoảng thời gian ngắn
    để hỗ trợ UDP hole punching.

    Lý do:
    - Nếu cả hai bên cùng gửi UDP ra ngoài tới địa chỉ của nhau, NAT có thể mở
      mapping tạm thời cho phép các gói từ bên kia đi vào (peer-to-peer).
    - Việc gửi liên tục trong một vài giây tăng cơ hội thành công.

    Tham số:
      - duration: tổng thời gian gửi (giây).
      - interval: khoảng nghỉ giữa hai gói (giây).
    """
    end = time.time() + duration
    # Dùng một payload cố định để dễ debug (không quan trọng nội dung)
    payload = b"SRVNC-HP"
    while time.time() < end:
        try:
            sock.sendto(payload, peer)
        except OSError:
            # Nếu socket gặp lỗi, dừng sớm
            break
        time.sleep(interval)


# -------------------------
# Relay client helper (đăng ký với relay server)
# -------------------------
@dataclass
class RelayConfig:
    """Cấu hình relay client: server address và tên session."""
    server: Address
    session: str


class RelayClient:
    """Minimal UDP relay helper used as a TURN-style fallback.

    RelayClient dùng để "register" với relay server (ví dụ relay.py),
    chờ message "ready" rồi trả về True/False tuỳ relay có chấp nhận hay không.

    Đây là phần client-side đơn giản tương tác với RelayServer trong repo.
    """

    def __init__(self, config: RelayConfig) -> None:
        self.config = config

    def register(self, sock: socket.socket, role: str, timeout: float = 5.0) -> bool:
        """
        Gửi JSON register tới relay server và chờ tới khi nhận {"type":"ready"}.

        Thao tác:
        - Gửi {"type":"register", "session": <session>, "role": role} tới relay
        - Đặt timeout tạm thời cho socket
        - Đọc socket cho tới khi timeout; nếu nhận JSON từ relay với type == "ready" -> return True
        - Ngược lại return False

        Lưu ý:
        - Hàm ghi đè timeout của socket rồi khôi phục lại ở cuối.
        - Chỉ chấp nhận response từ chính relay server (addr == self.config.server)
        """
        message = {
            "type": "register",
            "session": self.config.session,
            "role": role,
        }
        data = json.dumps(message).encode("utf-8")
        # Gửi register tới relay server
        sock.sendto(data, self.config.server)

        # Tính thời điểm kết thúc chờ
        end = time.time() + timeout
        previous_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        try:
            while time.time() < end:
                try:
                    payload, addr = sock.recvfrom(2048)
                except socket.timeout:
                    # Hết thời gian chờ cho lần recv, break để return False
                    break
                # Bỏ qua gói không đến từ relay server (an toàn)
                if addr != self.config.server:
                    continue
                try:
                    response = json.loads(payload.decode("utf-8"))
                except json.JSONDecodeError:
                    # Nếu payload không phải JSON hợp lệ -> skip
                    continue
                # Nếu relay trả về ready -> đăng ký thành công
                if response.get("type") == "ready":
                    return True
        finally:
            # Khôi phục timeout ban đầu (quan trọng để không phá socket caller)
            sock.settimeout(previous_timeout)
        return False
