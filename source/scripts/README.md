# A/B Comparison Checklist

This guide outlines how to demonstrate SR-VNC against a traditional VNC/TCP stack under controlled impairments.

## Prerequisites

* Install `tc` (traffic control) utilities (`iproute2`).
* Ensure you can run commands with root privileges when shaping traffic.
* Have both the SR-VNC demo and a baseline VNC server/client available.

## Network Profiles

Use `scripts/netem_profiles.sh` to apply the expected network conditions on the interface that connects the two peers (repeat on both ends for symmetric impairment).

```bash
sudo ./scripts/netem_profiles.sh <iface> loss15      # 15% random loss
sudo ./scripts/netem_profiles.sh <iface> jitter80    # 80 ms RTT with ±5 ms jitter
sudo ./scripts/netem_profiles.sh <iface> throttle2m  # 2 Mbps throttle with mild delay
```

Reset to a clean slate between scenarios:

```bash
sudo ./scripts/netem_profiles.sh <iface> clear
```

## Baseline VNC/TCP Run

1. Apply a profile (e.g. `loss15`).
2. Launch your preferred VNC server/client pair through the impaired link.
3. Perform the stress script: continuously drag application windows and type rapidly for at least 30 seconds.
4. Note the visual stuttering, input lag, or freezes.

## SR-VNC Run

1. Keep the same profile active.
2. Start `srvnc/server.py` on the host and `srvnc/client.py` on the controller with identical session/password parameters.
3. Enable the on-screen telemetry overlay (displayed automatically). Capture screenshots showing:
   * Control RTT p50/p95/p99 staying ≤ 80 ms for the jitter profile.
   * Control loss = 0% after retransmissions.
   * Video FPS ≥ 12 at 2 Mbps throttle.
4. Repeat the stress actions (drag windows, rapid typing). Verify the cursor remains responsive while frames may skip.
5. Record Wireshark traces filtered by `udp.port == <srvnc_port>` to show encrypted payloads only.

## Reporting

* Collect overlay screenshots for each profile and the Wireshark capture summary.
* Tabulate the telemetry readings (RTT, loss %, video FPS/bitrate) alongside the VNC/TCP behaviour for an at-a-glance comparison.
* Include notes on whether NAT traversal was direct, hole-punched, or relay-assisted.

With these artefacts you can substantiate the "Done" acceptance criteria in the README.
