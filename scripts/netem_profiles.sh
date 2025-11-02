#!/usr/bin/env bash
# Chạy bằng bash (tìm bash trong PATH). Giúp script chạy trên nhiều hệ thống.

set -euo pipefail
# set -e : dừng script nếu một lệnh trả về non-zero (lỗi)
# set -u : lỗi nếu dùng biến chưa được gán (giúp tránh lỗi đánh máy biến)
# set -o pipefail : nếu một pipeline có lỗi ở giữa, toàn bộ pipeline trả lỗi
# => Kết hợp giúp script an toàn hơn / dễ debug hơn.

# Kiểm tra số tham số truyền vào (cần ít nhất 2 tham số)
if [[ $# -lt 2 ]]; then
    # Nếu tham số không đủ, in hướng dẫn sử dụng
    cat <<USAGE
Usage: sudo $0 <interface> <profile>
Profiles:
  clear       Remove any qdisc configured by this script
  loss15      Apply 15% random packet loss
  jitter80    Add 80ms base RTT with ±5ms jitter
  throttle2m  Shape bandwidth to ~2 Mbps downstream
USAGE
    exit 1
fi

# Gán biến: tên interface và profile muốn áp dụng
DEV="$1"
PROFILE="$2"

# Kiểm tra quyền root (EUID == 0). Những thao tác 'tc' yêu cầu root
if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] This script requires root privileges (tc)." >&2
    exit 1
fi

# Hàm xóa qdisc (queue discipline) đã cấu hình trên interface
function clear_qdisc() {
    # Xóa qdisc root (bỏ qua lỗi nếu không có qdisc) 
    tc qdisc del dev "$DEV" root 2>/dev/null || true
}

# Lựa chọn profile dựa trên tham số truyền vào
case "$PROFILE" in
    clear)
        # Xóa mọi cấu hình đã đặt trước đó
        clear_qdisc
        ;;
    loss15)
        # Xóa trước rồi thêm một qdisc netem với 15% packet loss ngẫu nhiên
        clear_qdisc
        tc qdisc add dev "$DEV" root netem loss 15%
        ;;
    jitter80)
        # Xóa trước rồi thêm delay = 80ms với jitter ±5ms (phân phối normal)
        clear_qdisc
        tc qdisc add dev "$DEV" root netem delay 80ms 5ms distribution normal
        ;;
    throttle2m)
        # Xóa trước rồi cài HTB + lớp shape băng thông ~2mbit, kèm chút delay 20ms
        clear_qdisc
        # Tạo root qdisc dạng htb (hierarchical token bucket), handle 1:
        tc qdisc add dev "$DEV" root handle 1: htb default 10
        # Tạo class (1:10) giới hạn rate và ceil (=max) 2mbit
        tc class add dev "$DEV" parent 1: classid 1:10 htb rate 2mbit ceil 2mbit
        # Thêm netem dưới class 1:10 (cài delay 20ms)
        tc qdisc add dev "$DEV" parent 1:10 handle 10: netem delay 20ms
        ;;
    *)
        # Profile không hợp lệ -> báo lỗi và thoát
        echo "Unknown profile: $PROFILE" >&2
        exit 2
        ;;
esac

# Hiển thị cấu hình qdisc hiện tại trên interface để người dùng kiểm tra
tc qdisc show dev "$DEV"
