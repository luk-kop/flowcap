# flowcap

[![CI](https://github.com/luk-kop/flowcap/actions/workflows/ci.yml/badge.svg)](https://github.com/luk-kop/flowcap/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/luk-kop/flowcap)](https://github.com/luk-kop/flowcap/blob/main/go.mod)
[![License](https://img.shields.io/github/license/luk-kop/flowcap)](https://github.com/luk-kop/flowcap/blob/main/LICENSE)
[![Kernel](https://img.shields.io/badge/kernel-6.6%2B-blue?logo=linux)](https://kernelnewbies.org/Linux_6.6)

The **eBPF-based network flow capture** for Linux network interfaces. Captures network flows directly in the kernel using eBPF and exports them as structured logs. Works with any network interface - ethernet, VPN tunnels (WireGuard, OpenVPN), bridges, VLANs, etc.

## Features

- **Kernel-space capture** - Runs in the kernel, avoiding userspace packet drops even under high connection rates
- **Efficient aggregation** - Updates flow counters in-memory (hash map) rather than capturing every packet
- **Periodic snapshots** - Exports all flows at regular intervals (default 10s) and removes them from the map; new packets recreate the flow with fresh timestamps
- **Smart flow lifecycle** - Detects TCP connection close (`FIN`/`RST`) and inactive flows (default 60s timeout)
- **64-bit counters** - No wraparound issues on high-volume traffic
- **Drop counters** - Tracks skipped packets (IP fragments, non-IPv4, parse errors) per CPU with zero contention
- **Minimal overhead** - Per-packet work is limited to header linearization, L3/L4 parsing, and a hash map update

**Collected metrics per flow:**

- Source/destination IP and port
- Protocol (TCP/UDP/other)
- Packet count
- Byte count (`skb->len` as reported at the TC layer; compare with packet-capture or interface counters only after validating the interface-specific L2/L3 semantics)
- Duration (time between first and last packet in the flow record; flows with a single packet have `duration = 0` because `first_seen == last_seen` — this is expected for DNS responses, ICMP pings, TCP ACKs, and other single-packet flows, and is standard behavior across NetFlow/IPFIX exporters)
- TCP flags (`SYN`, `FIN`, `RST`, etc.)

**Use cases:**

- Real-time bandwidth monitoring per connection
- Detecting high connection rates or traffic spikes
- VPN tunnel traffic analysis (WireGuard, OpenVPN, IPsec)
- Network flow analysis without full packet capture overhead
- Feeding flow data to monitoring systems (Prometheus, Loki, InfluxDB, etc.)

## How It Works

See the [Architecture diagram](docs/architecture.md) for a visual overview of the packet processing and export flow.

1. Attaches an eBPF program to the network interface using **TCX (TC eXpress) hook** on both **ingress** and **egress**

   > **Note:** TCX (TC eXpress) is a modern Linux kernel API introduced in kernel 6.6 for attaching eBPF programs to network interfaces at the Traffic Control (TC) layer. Compared to the classic TC hook (via `tc` netlink), TCX uses a dedicated `bpf_link`-based attachment model that is more robust, supports ordering of multiple programs on the same hook, and integrates cleanly with the eBPF link lifecycle (auto-detach on process exit).
2. For each packet (incoming and outgoing), extracts the **5-tuple (src IP, dst IP, src port, dst port, protocol)**
3. Skips IP fragments to prevent incorrect flow identification
4. Updates flow statistics (packet count, byte count, timestamps, TCP flags) in a kernel hash map (an eBPF `BPF_MAP_TYPE_LRU_HASH` (Least Recently Used) — a key/value store living in kernel memory, shared between the eBPF program and the Go userspace process)
5. Every interval (default 10s), exports and deletes scanned flows from the map. At most `max-export-per-cycle` flows are exported per cycle; remaining flows stay in the map until the next cycle. Each exported flow is classified for metrics purposes:
   - **Active**: Had recent packets within the timeout window
   - **Inactive**: No packets for `timeout` seconds
   - **Closed**: TCP connection ended (`FIN`/`RST` seen)
6. Long-lived connections generate multiple records over time for real-time throughput visibility
7. Rate limiting: Configurable maximum flows exported per cycle (default 10,000) to prevent log flooding

### Operational Semantics

`flowcap` uses the export interval as the active export cadence. On each cycle, it scans the flow map, exports up to `max-export-per-cycle` records, and deletes exported records. Packets for the same 5-tuple after deletion create a fresh flow entry.

`timeout` is a classification threshold for flows that are still present when scanned. In normal low-volume operation most exported records are `active` snapshots; `inactive` records appear when a flow stayed in the map long enough to exceed the timeout, commonly because export rate limiting left it for a later cycle.

`closed` records are TCP flows whose accumulated flags include `FIN` or `RST`. `closed` takes precedence over `inactive` for the exported metric label.

### Byte Count Semantics

Flowcap records bytes from `skb->len` in the TC hook. That is the kernel packet length visible to the eBPF program at the attachment point, not a normalized application payload length.

Validated with a 1000-byte UDP payload:

- `lo`: `tcpdump` reported IPv4 `length 1028` (`20 IP + 8 UDP + 1000 payload`), while Flowcap reported `bytes=2084 packets=2`, or `1042` bytes per packet.
- `wlp0s20f3` Ethernet/Wi-Fi path: `tcpdump` reported IPv4 `length 1028`, while Flowcap reported `bytes=1042 packets=1`.
- `tun0` L3 tunnel: `tcpdump` reported IPv4 `length 1028` for a 1000-byte ICMP payload, while Flowcap reported `bytes=1028 packets=1`.
- `wg0` WireGuard tunnel: `tcpdump` reported IPv4 `length 1028` for a 1000-byte ICMP payload, while Flowcap reported `bytes=1028 packets=1` for both request and reply records.

On loopback and the tested Ethernet/Wi-Fi path, Flowcap's TC-layer `skb->len` included a 14-byte link-layer header relative to tcpdump's IPv4 length. On the tested TUN and WireGuard interfaces, Flowcap matched tcpdump's IPv4 length exactly.

Do not assume it is directly comparable to NIC counters, tcpdump summaries, or another flow exporter without checking whether that tool includes link-layer overhead.

## Limitations

- **Linux kernel 6.6+** - Requires kernel 6.6 or newer at runtime due to **TCX (TC eXpress) hook API**
- **IPv4 only** - IPv6 packets are silently skipped
- **Race window** - Small window (~microseconds) between reading and deleting a flow; packets arriving in that window are captured in a new flow entry
- **Flow capacity** - When map is full (default 16,384, max 262,144), LRU evicts least recently used flows without exporting them
- **IP fragmentation** - All fragmented IP packets are skipped; only complete packets with full TCP/UDP headers are processed (counted via drop counters)

  > **Note:** This is a standard approach in flow capture tools. Only the first fragment contains TCP/UDP port headers — subsequent fragments cannot be matched to a flow without reassembly, which is impractical in eBPF. In practice, TCP is almost never fragmented (MSS negotiation, PMTU discovery) and UDP fragmentation is rare on modern networks (MTU 1500+).
- **Approximate flow count under rate limiting** - The `flowcap_export_scan_flows` gauge reports flows observed during the last export scan, not the post-export map size. It is approximate because the eBPF program may concurrently insert or update flows while the Go exporter iterates the map.
- **Interface state** - Can attach to DOWN interfaces (captures start when interface comes UP); warning is logged at startup
- **Tunnel interfaces** - Flowcap captures traffic as seen by the specified interface. For VPN tunnels (`tun0`, `wg0`), this means decapsulated inner traffic; for physical interfaces (`eth0`), this means encrypted outer traffic

## Build

Requires:

- `Go 1.26+` - for building the userspace program
- `clang/LLVM 11+` - for compiling eBPF C code to BPF bytecode
- `Linux kernel 6.6+ headers` - for eBPF/TCX kernel API definitions

### Install dependencies (Ubuntu/Debian/Mint)

```bash
sudo apt install clang llvm linux-headers-$(uname -r) linux-libc-dev libc6-dev libbpf-dev
```

### Compile

```bash
make
```

This compiles eBPF C code into Go bindings (via `bpf2go`) and builds the binary.

Other targets:

```bash
make generate   # only regenerate eBPF bindings
make build      # regenerate eBPF bindings and build flowcap with version metadata
make build-release  # build Linux amd64/arm64 release archives and checksums
make test       # regenerate eBPF bindings and run Go tests
make clean      # remove binary and generated files
```

The build embeds version metadata from git:

```bash
./flowcap --version
```

```text
v0.1.5 revision=2c73106 build_date=2026-05-17T07:45:32Z
```

### Troubleshooting

**Error: `'asm/types.h' file not found`**

> **Note:** This happens because clang with BPF target looks for headers in `/usr/include/asm/`, but Debian/Ubuntu stores them in `/usr/include/x86_64-linux-gnu/asm/` (multiarch layout). The `linux-libc-dev` package should create a symlink between them, but on fresh installs or after upgrades the symlink is sometimes missing.

If you see this error during build, reinstall `linux-libc-dev`:

```bash
sudo apt install --reinstall linux-libc-dev
```

This ensures the `/usr/include/asm` symlink is properly created.

If the symlink is still missing after reinstall, create it manually:

```bash
sudo ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

## Usage

```bash
sudo ./flowcap wg0
```

Captures flows on `wg0` and exports every 10 seconds to stdout.

### Options

```bash
sudo ./flowcap [options] <interface>

Options:
  -interval int
        flow export interval in seconds (default 10, max 3600)
  -timeout int
        flow inactivity timeout in seconds (default 60, max 86400)
  -max-flows int
        maximum number of concurrent flows (default 16384, min 1024, max 262144)
  -max-export-per-cycle int
        maximum flows to export per cycle (default 10000, max equals max-flows)
  -json
        output in JSON format
  -metrics-addr string
        enable Prometheus metrics HTTP server at host:port (e.g. 127.0.0.1:9090)
  -stats-file string
        optional file for detailed statistics logging
  --version
        Print version and exit
```

### Examples

```bash
# Default settings (10s export interval, 60s inactivity timeout, 16384 max flows)
sudo ./flowcap eth0

# Export every 5 seconds, 30s inactivity timeout
sudo ./flowcap -interval 5 -timeout 30 wg0

# High-traffic interface with more flow capacity
sudo ./flowcap -max-flows 131072 eth0

# High-traffic interface with higher export rate limit
sudo ./flowcap -max-export-per-cycle 20000 eth0

# JSON output for log collectors (Promtail, Filebeat, etc.)
sudo ./flowcap -json wg0 | tee -a /var/log/flows.json

# With statistics file for detailed logging
sudo ./flowcap -stats-file /var/log/flowcap-stats.log wg0

# Enable Prometheus metrics endpoint
sudo ./flowcap -metrics-addr 127.0.0.1:9090 wg0

# Print build version and exit
./flowcap --version

# Export every minute for low-traffic interfaces
sudo ./flowcap -interval 60 -timeout 300 tun0
```

At startup, flowcap logs the embedded version metadata together with the selected interface and runtime options.

### Output Format

Text format is intended for human consumption. For machine parsing and monitoring integrations, use `-json` which provides fixed numeric fields.

**Text (default):**

```text
<src_ip>:<src_port> -> <dst_ip>:<dst_port> proto=<protocol> packets=<count> bytes=<count> duration=<duration> flags=<tcp_flags>
```

**JSON (`-json` flag):**

```json
{
  "timestamp": 1709132400,
  "src_ip": "192.168.1.10",
  "src_port": 45678,
  "dst_ip": "10.0.0.5",
  "dst_port": 22,
  "protocol": 6,
  "packets": 50,
  "bytes": 4096,
  "duration_ns": 10000000000,
  "duration_sec": 10.0,
  "tcp_flags": "0x18"
}
```

### Statistics File

Use `-stats-file` to log per-cycle statistics to a separate file. The format follows the `-json` flag.

**Text (default):**

```bash
sudo ./flowcap -stats-file /var/log/flowcap-stats.log wg0
```

```text
[2026-02-28 16:08:00] Exported: 150 active, 5 inactive, 3 closed | Total flows: 1523 | Bytes: 524288 | Packets: 4096 | Drops: fragments=0 non_ipv4=12 parse_err=0 linearize=0 map_full=0
[2026-02-28 16:08:10] Exported: 148 active, 2 inactive, 1 closed | Total flows: 1520 | Bytes: 412032 | Packets: 3200 | Drops: fragments=0 non_ipv4=8 parse_err=0 linearize=0 map_full=0
```

**JSON (`-json` flag):**

```bash
sudo ./flowcap -json -stats-file /var/log/flowcap-stats.log wg0
```

```json
{"timestamp":1709132400,"active":150,"inactive":5,"closed":3,"total_flows":1523,"total_bytes":524288,"total_packets":4096,"drop_fragments":0,"drop_non_ipv4":12,"drop_parse_err":0,"drop_linearize":0,"drop_map_full":0}
```

## Deployment

Systemd service unit, environment file configuration, and logrotate setup are documented in [docs/deployment.md](docs/deployment.md).

## Monitoring

Prometheus metrics (with raw output example), Grafana queries, log collector configs (Promtail, Filebeat), and backend comparison are documented in [docs/monitoring.md](docs/monitoring.md).

## Architecture

For a detailed architecture diagram, flow storage internals, eBPF program description, and drop counter documentation, see [docs/architecture.md](docs/architecture.md).

## Comparison

For a detailed comparison with other network monitoring tools (softflowd, Cilium Hubble, ntopng, tcpdump, Packetbeat, AWS VPC Flow Logs), see [docs/comparison.md](docs/comparison.md).
