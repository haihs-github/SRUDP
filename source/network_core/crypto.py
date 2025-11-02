"""Cryptographic helpers and session management for SR-VNC.

File này chứa:
- Các hàm/ lớp phục vụ handshake (X25519 + HKDF) để sinh key cho AES-GCM.
- Lớp SecureCodec quản lý nonce/packet number, mã hóa AES-GCM, và bảo vệ replay.
- Cơ chế cookie/HMAC để bảo vệ handshake khỏi spoofed floods.
- Hàm derive_key_from_password (PBKDF2) để sinh key từ password người dùng.
"""

from __future__ import annotations

import os
import socket
import secrets
import struct
import time
import hmac as std_hmac
from cryptography.hazmat.primitives import hmac as crypto_hmac
from dataclasses import dataclass
from typing import ClassVar, Tuple

# Thư viện cryptography - dùng cho AES-GCM, X25519, HKDF, PBKDF2, HMAC, ...
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# -------------------------
# Các hằng số cấu hình
# -------------------------
NONCE_SIZE = 12      # Kích thước nonce (AES-GCM thường dùng 12 bytes cho hiệu năng tốt)
SALT_SIZE = 16       # Kích thước salt dùng cho PBKDF2
PBKDF2_ITERATIONS = 200_000  # Số lần lặp PBKDF2 (giá trị lớn để chống tấn công brute-force)

# Thời điểm rekey: khi đã gửi nhiều dữ liệu hoặc sau 1 khoảng thời gian
REKEY_BYTES = 1 << 30          # ~1 GiB - nếu gửi > 1GiB thì tái tạo key
REKEY_INTERVAL = 60 * 60       # 1 giờ

# Các exception chuyên biệt để báo lỗi replay / yêu cầu rekey
class ReplayError(Exception):
    """Raised when a packet is outside of the replay protection window."""


class RekeyRequired(Exception):
    """Raised when a secure session must perform a rekey operation."""


# -------------------------
# ReplayWindow - chống replay attack
# -------------------------
@dataclass
class ReplayWindow:
    """
    Simple 64-bit sliding replay window tracker.

    Mục đích:
      - Phát hiện packet bị gửi lại (replay) hoặc packet quá cũ nằm ngoài cửa sổ
      - Bảo vệ chống kẻ tấn công phát lại (ví dụ: gửi lặp gói lệnh chuột)
    Cách hoạt động (tóm tắt):
      - Giữ highest (số packet lớn nhất đã thấy) và một mask 64-bit.
      - Khi packet mới có số N:
          * Nếu N > highest: dịch mask sang trái (bù gap), set bit 0 = 1, cập nhật highest = N.
          * Nếu N <= highest: tính offset = highest - N; nếu offset >= 64 -> packet quá cũ -> lỗi
                                nếu bit offset trong mask đã 1 -> replay -> lỗi
                                else set bit offset = 1 (đánh dấu đã nhận)
    """

    highest: int = -1
    mask: int = 0

    def check_and_update(self, number: int) -> None:
        """
        Kiểm tra packet number và cập nhật window.
        - number: số packet (số nguyên không âm, tăng dần trên sender).
        """
        if self.highest == -1:
            # Lần đầu tiên nhận packet => khởi tạo
            self.highest = number
            self.mask = 1
            return

        if number > self.highest:
            # Packet mới lớn hơn highest -> dịch mask để phản ánh gap
            shift = number - self.highest
            if shift >= 64:
                # Khoảng cách quá lớn -> bỏ sạch mask (tắt mọi bit)
                self.mask = 0
            else:
                # Dịch mask trái và thêm bit mới ở vị trí 0
                self.mask = ((self.mask << shift) & ((1 << 64) - 1)) | 1
            self.highest = number
            return

        # Nếu số nhỏ hơn hoặc bằng highest -> kiểm tra xem đã nhận chưa
        distance = self.highest - number
        if distance >= 64:
            # Quá cũ, nằm ngoài window 64 -> bị coi là replay/invalid
            raise ReplayError("Packet number outside of replay window")
        bit = 1 << distance
        if self.mask & bit:
            # Bit đã set -> packet trùng lặp (replay)
            raise ReplayError("Duplicate packet number detected")
        # Đánh dấu là đã nhận (set bit)
        self.mask |= bit


# -------------------------
# DerivedKey - container key + salt
# -------------------------
@dataclass(frozen=True)
class DerivedKey:
    """
    Container cho key đối xứng đã derive và salt đi kèm.

    - key: bytes (32 bytes cho AES-256)
    - salt: bytes (dùng khi derive từ password)
    - HEADER: tiêu đề để nhận biết blob serialized
    """
    key: bytes
    salt: bytes

    HEADER: ClassVar[bytes] = b"SRVNC1"

    def serialize(self) -> bytes:
        """Serialize the derived key cho mục đích lưu/transfer."""
        return self.HEADER + self.salt + self.key

    @classmethod
    def deserialize(cls, blob: bytes) -> "DerivedKey":
        """Tạo lại DerivedKey từ blob do serialize trả về."""
        if len(blob) < len(cls.HEADER) + SALT_SIZE + 16:
            # Ít nhất phải có header + salt + 16 byte key (ít nhất AES-128)
            raise ValueError("Serialized key blob is too small")
        header = blob[: len(cls.HEADER)]
        if header != cls.HEADER:
            raise ValueError("Invalid key header")
        salt = blob[len(cls.HEADER) : len(cls.HEADER) + SALT_SIZE]
        key = blob[len(cls.HEADER) + SALT_SIZE :]
        return cls(key=key, salt=salt)


# -------------------------
# derive_key_from_password - PBKDF2-HMAC-SHA256
# -------------------------
def derive_key_from_password(password: str, *, salt: bytes | None = None) -> DerivedKey:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.

    - PBKDF2 giúp làm chậm việc thử mật khẩu (brute-force).
    - Nếu salt không cung cấp, tạo random salt an toàn.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    # Tạo PBKDF2-HMAC-SHA256 KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                # 32 bytes => 256-bit AES key
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return DerivedKey(key=key, salt=salt)


# -------------------------
# SecureCodec - quản lý session AES-GCM, nonce, và replay
# -------------------------
class SecureCodec:
    """
    Secure session state implementing nonce management and replay checks.

    Vai trò:
      - Quản lý key gửi/nhận (send_key, recv_key)
      - Sinh nonce deterministically từ prefix (6 bytes) + counter (6 bytes) -> tổng 12 bytes
        (thích hợp cho AES-GCM với nonce 96-bit).
      - Thực hiện encrypt/decrypt với AESGCM (additional authenticated data = header).
      - Giữ replay window để phát hiện replay attacks.
      - Giám sát lượng dữ liệu gửi để quyết định khi nào cần rekey (REKEY_BYTES/REKEY_INTERVAL).
    """

    def __init__(
        self,
        *,
        send_key: bytes,
        recv_key: bytes,
        send_prefix: bytes,
        recv_prefix: bytes,
        session_id: int,
    ) -> None:
        # Validate kích thước key (AES-GCM chấp nhận 16/24/32 bytes)
        if len(send_key) not in {16, 24, 32} or len(recv_key) not in {16, 24, 32}:
            raise ValueError("AES-GCM key must be 128, 192, or 256 bits long")
        # Nonce prefix phải 6 bytes (cộng counter 6 bytes -> 12 bytes)
        if len(send_prefix) != 6 or len(recv_prefix) != 6:
            raise ValueError("Nonce prefixes must be 6 bytes")

        # AESGCM từ cryptography: cung cấp encrypt/decrypt AEAD (authenticated encryption)
        self._send_aead = AESGCM(send_key)
        self._recv_aead = AESGCM(recv_key)

        # Prefix 6 bytes dùng để phân biệt hướng (send/recv) và làm nonce deterministic
        self._send_prefix = send_prefix
        self._recv_prefix = recv_prefix

        # Counter tăng cho mỗi packet gửi; dùng để sinh nonce = prefix || counter
        self._send_counter = 0

        # Replay protection cho luồng nhận
        self._replay_window = ReplayWindow()

        # Theo dõi số byte đã gửi (để quyết định rekey)
        self._bytes_sent = 0

        # Lưu thời điểm established để tính REKEY_INTERVAL
        self._established = time.time()

        # Lưu session id (chỉ để debug/serialize nếu cần)
        self.session_id = session_id

    # -------------------------
    # Helpers
    # -------------------------
    def _build_nonce(self, prefix: bytes, counter: int) -> bytes:
        """
        Tạo nonce 12 bytes: prefix (6 bytes) + counter (6 bytes big-endian).
        - WHY deterministic nonces? Ở giao thức này, nonce được sinh từ packet number
          theo cách deterministic (không random), miễn là key không tái sử dụng cho nonce trùng.
        - Lưu ý: AES-GCM yêu cầu nonce không lặp với cùng key. Vì vậy nếu counter tràn
          phải rekey trước khi nó lặp.
        """
        return prefix + counter.to_bytes(6, "big")

    def _check_rekey(self, payload_len: int) -> None:
        """
        Tăng bộ đếm byte đã gửi và ném RekeyRequired nếu vượt ngưỡng
        - Mục đích: giới hạn lượng dữ liệu / thời gian sử dụng một key để giảm rủi ro
        """
        self._bytes_sent += payload_len
        if self._bytes_sent >= REKEY_BYTES or time.time() - self._established > REKEY_INTERVAL:
            # Ném exception để caller bắt và thực hiện handshake rekey
            raise RekeyRequired

    # -------------------------
    # Public API
    # -------------------------
    def next_packet_number(self) -> int:
        """
        Trả về packet number tiếp theo (dùng để đánh dấu nonce / header).
        Nếu counter vượt quá 48-bit, ném RekeyRequired vì ta chỉ dùng 6 bytes cho counter.
        """
        packet_number = self._send_counter
        self._send_counter += 1
        if self._send_counter >= (1 << 48):
            # Counter 6 bytes tràn -> cần rekey để tránh nonce trùng
            raise RekeyRequired
        return packet_number

    def encrypt(self, packet_number: int, header: bytes, plaintext: bytes) -> bytes:
        """
        Mã hóa plaintext bằng AES-GCM:
        - Nonce = send_prefix || packet_number (6+6 = 12 bytes)
        - header được dùng như AAD (additional authenticated data) để bind header với ciphertext
        - Sau khi mã hóa, kiểm tra _check_rekey với kích thước ciphertext
        - Trả về ciphertext (gồm tag AEAD) để gắn vào wire
        """
        nonce = self._build_nonce(self._send_prefix, packet_number)
        ciphertext = self._send_aead.encrypt(nonce, plaintext, header)
        # Kiểm tra có cần rekey hay không (dựa vào bytes đã gửi)
        self._check_rekey(len(ciphertext))
        return ciphertext

    def decrypt(self, packet_number: int, header: bytes, ciphertext: bytes) -> bytes:
        """
        Giải mã ciphertext:
        - Trước hết kiểm tra replay: _replay_window.check_and_update(packet_number)
          (nếu packet quá cũ hoặc trùng sẽ ném ReplayError)
        - Tạo nonce = recv_prefix || packet_number
        - Giải mã AES-GCM (nếu tag ko khớp, cryptography sẽ ném exception)
        - Trả về plaintext
        """
        # Kiểm tra replay/duplicate/trước khi giải mã
        self._replay_window.check_and_update(packet_number)
        nonce = self._build_nonce(self._recv_prefix, packet_number)
        return self._recv_aead.decrypt(nonce, ciphertext, header)


# -------------------------
# Handshake helpers (X25519 + HKDF)
# -------------------------
def _hkdf_expand(shared_secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Bao bọc HKDF (HKDF-Extract/Expand) để mở rộng shared secret thành material bytes.
    - Sử dụng SHA256 cho HKDF.
    - salt & info: giúp phân biệt phiên (session binding).
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        shared_secret
    )


def generate_ephemeral_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """
    Sinh keypair ephemeral X25519 (Curve25519) cho ECDH:
    - Trả về private key object và public key bytes (Raw format).
    - X25519 nhanh, tốt cho ECDH ephemeral handshake.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def derive_session_keys(
    shared_secret: bytes,
    *,
    client_random: bytes,
    server_random: bytes,
    initiator: bool,
    session_id: int,
) -> SecureCodec:
    """
    Wrapper không dùng PSK — chỉ gọi hàm với psk=None.
    Giữ API gọn: derive_session_keys_with_psk(...) là hàm chính.
    """
    return derive_session_keys_with_psk(
        shared_secret,
        client_random=client_random,
        server_random=server_random,
        initiator=initiator,
        session_id=session_id,
        psk=None,
    )


def derive_session_keys_with_psk(
    shared_secret: bytes,
    *,
    client_random: bytes,
    server_random: bytes,
    initiator: bool,
    session_id: int,
    psk: bytes | None,
) -> SecureCodec:
    """
    Từ shared_secret (kết quả ECDH), derive material bằng HKDF:
    - salt = client_random || server_random (nếu có psk, thêm hash(psk) vào salt)
    - info = b"SRVNC-HANDSHAKE-1" || session_id (4 bytes)
    - material length = 84 bytes (32 send_key + 32 recv_key + 6 send_prefix + 6 recv_prefix = 84)
    - Nếu initiator == False, hoán đổi send/recv (vì cả 2 bên derive cùng material nhưng phải mirror)
    - Trả về SecureCodec với key/prefix tương ứng
    """
    salt = client_random + server_random
    if psk:
        # Nếu có pre-shared key, mix vào salt để binding authentication
        digest = hashes.Hash(hashes.SHA256())
        digest.update(psk)
        salt += digest.finalize()
    info = b"SRVNC-HANDSHAKE-1" + struct.pack("!I", session_id)

    # Tạo material bytes
    material = _hkdf_expand(shared_secret, salt, info, 84)

    # Phân chia material thành các thành phần
    send_key = material[:32]        # 32 bytes -> AES-256 (hoặc 16/24 tùy)
    recv_key = material[32:64]
    send_prefix = material[64:70]   # 6 bytes nonce prefix
    recv_prefix = material[70:76]   # 6 bytes nonce prefix

    # Nếu không phải initiator, swap send/recv để cả 2 bên có chiều gửi/nhận đối xứng
    if not initiator:
        send_key, recv_key = recv_key, send_key
        send_prefix, recv_prefix = recv_prefix, send_prefix

    # Tạo SecureCodec chứa state gửi/nhận (AESGCM, prefixes, replay window, ...)
    return SecureCodec(
        send_key=send_key,
        recv_key=recv_key,
        send_prefix=send_prefix,
        recv_prefix=recv_prefix,
        session_id=session_id,
    )


# -------------------------
# HMAC và cookie helpers
# -------------------------
def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Trả về HMAC-SHA256 của data với key (dùng cryptography HMAC)."""
    h = crypto_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _cookie_msg(address: Tuple[str, int], client_random: bytes, timestamp: int) -> bytes:
    """
    Build một message để HMAC thành cookie:
    - Bao gồm IP (4 bytes), port (2 bytes), client_random (32 bytes), timestamp (4 bytes).
    - Kiểm tra client_random 32 bytes để đảm bảo định dạng.
    """
    ip, port = address
    ip_bytes = socket.inet_aton(ip)          # Chỉ IPv4 ở đây (4 bytes)
    port_bytes = struct.pack("!H", int(port))
    ts_bytes = struct.pack("!I", int(timestamp))
    if not isinstance(client_random, (bytes, bytearray)) or len(client_random) != 32:
        raise ValueError("client_random must be 32 bytes")
    return ip_bytes + port_bytes + client_random + ts_bytes


def create_cookie(secret: bytes, address: Tuple[str, int], client_random: bytes, ts: int) -> bytes:
    """
    Tạo cookie HMAC để server trả về cho client trong hello_retry.
    Cookie = HMAC(secret, _cookie_msg(...))
    - Cookie giúp server verify rằng client thực sự có thể nhận response
      (mitigate spoofed floods).
    """
    return _hmac_sha256(secret, _cookie_msg(address, client_random, ts))


def verify_cookie(
    secret: bytes,
    address: Tuple[str, int],
    client_random: bytes,
    ts: int,
    cookie: bytes,
    *,
    tolerance: int = 1,
) -> bool:
    """
    Verify cookie với tolerance window (vài giây) để account cho độ trễ clock.
    - So sánh an toàn bằng std_hmac.compare_digest để tránh timing attacks.
    - Nếu cookie không có độ dài 32 -> trả False ngay.
    - Duyệt delta từ -tolerance .. +tolerance để chấp nhận cookie có timestamp lệch nhỏ.
    """
    if not isinstance(client_random, (bytes, bytearray)):
        raise TypeError("client_random must be bytes")
    if not isinstance(cookie, (bytes, bytearray)) or len(cookie) != 32:
        return False

    last_expected: bytes | None = None
    for delta in range(-tolerance, tolerance + 1):
        expected = _hmac_sha256(secret, _cookie_msg(address, client_random, ts + delta))
        last_expected = expected
        if std_hmac.compare_digest(expected, cookie):
            # Debug log nhỏ — hữu ích khi diagnose handshake failures
            print(f"[DEBUG] cookie verify: True (exp_len={len(expected)} got_len={len(cookie)})")
            return True
    if last_expected is not None:
        print(f"[DEBUG] cookie verify: False (exp_len={len(last_expected)} got_len={len(cookie)})")
    return False
