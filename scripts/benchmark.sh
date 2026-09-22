#!/usr/bin/env bash
set -euo pipefail

iface="${1:-}"
duration="${DURATION:-60}"
traffic_cmd="${TRAFFIC_CMD:-}"
reference_packets="${REFERENCE_PACKETS:-}"
reference_bytes="${REFERENCE_BYTES:-}"
metrics_port="${METRICS_PORT:-19090}"
output_dir="${OUTPUT_DIR:-/tmp/flowcap-benchmark-$(date -u +%Y%m%dT%H%M%SZ)}"
flowcap_args="${FLOWCAP_ARGS:-}"
reference_src_ip="${REFERENCE_SRC_IP:-}"
reference_src_port="${REFERENCE_SRC_PORT:-}"
reference_dst_ip="${REFERENCE_DST_IP:-}"
reference_dst_port="${REFERENCE_DST_PORT:-}"
reference_protocol="${REFERENCE_PROTOCOL:-}"
reference_direction="${REFERENCE_DIRECTION:-}"
if [[ -z "$iface" ]]; then
  echo "usage: $0 <interface>" >&2
  exit 2
fi
if [[ -z "$traffic_cmd" || -z "$reference_packets" || -z "$reference_bytes" ]]; then
  echo "TRAFFIC_CMD, REFERENCE_PACKETS and REFERENCE_BYTES are required" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "run as root so flowcap can attach TCX (for example: sudo -E make benchmark ...)" >&2
  exit 2
fi
if ! ip link show "$iface" >/dev/null 2>&1; then
  echo "interface not found: $iface" >&2
  exit 2
fi
for command in ip python3 curl timeout ps awk date; do
  command -v "$command" >/dev/null 2>&1 || { echo "required command not found: $command" >&2; exit 2; }
done
if [[ ! -x ./bin/flowcap ]]; then
  echo "collector not built: ./bin/flowcap" >&2
  exit 2
fi
if [[ ! "$reference_packets" =~ ^[0-9]+$ || ! "$reference_bytes" =~ ^[0-9]+$ ]]; then
  echo "reference totals must be non-negative integers" >&2
  exit 2
fi

reference_filter_enabled=0
reference_filter_values=(
  "$reference_src_ip"
  "$reference_src_port"
  "$reference_dst_ip"
  "$reference_dst_port"
  "$reference_protocol"
  "$reference_direction"
)
for value in "${reference_filter_values[@]}"; do
  if [[ -n "$value" ]]; then
    reference_filter_enabled=1
    break
  fi
done
if [[ "$reference_filter_enabled" -eq 1 ]]; then
  if [[ -n "$reference_src_port" && (! "$reference_src_port" =~ ^[0-9]+$ || "$reference_src_port" -gt 65535) ]]; then
    echo "REFERENCE_SRC_PORT must be 0..65535" >&2
    exit 2
  fi
  if [[ -n "$reference_dst_port" && (! "$reference_dst_port" =~ ^[0-9]+$ || "$reference_dst_port" -gt 65535) ]]; then
    echo "REFERENCE_DST_PORT must be 0..65535" >&2
    exit 2
  fi
  if [[ -n "$reference_protocol" && (! "$reference_protocol" =~ ^[0-9]+$ || "$reference_protocol" -gt 255) ]]; then
    echo "REFERENCE_PROTOCOL must be 0..255" >&2
    exit 2
  fi
  if [[ -n "$reference_direction" && "$reference_direction" != "ingress" && "$reference_direction" != "egress" ]]; then
    echo "REFERENCE_DIRECTION must be ingress or egress" >&2
    exit 2
  fi
  python3 - "$reference_src_ip" "$reference_dst_ip" <<'PY'
import ipaddress
import sys

for value in (candidate for candidate in sys.argv[1:] if candidate):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise SystemExit(f"invalid reference IP address {value!r}: {error}")
    if address.version != 4:
        raise SystemExit(f"reference IP address must be IPv4: {value}")
PY
fi

mkdir -p "$output_dir"

if [[ "$reference_filter_enabled" -eq 1 ]]; then
  reference_flow="${reference_direction:-*} ${reference_src_ip:-*}:${reference_src_port:-*} -> ${reference_dst_ip:-*}:${reference_dst_port:-*} proto=${reference_protocol:-*}"
else
  reference_flow="all"
fi

bpf_stats_enabled="unknown"
if [[ -r /proc/sys/kernel/bpf_stats_enabled ]]; then
  bpf_stats_enabled="$(< /proc/sys/kernel/bpf_stats_enabled)"
fi

{
  echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "interface=$iface"
  echo "duration_seconds=$duration"
  echo "kernel=$(uname -r)"
  echo "clang=$(clang --version 2>/dev/null | head -n 1 || echo unavailable)"
  echo "go=$(go version 2>/dev/null || echo unavailable)"
  echo "cpu_count=$(nproc)"
  echo "reference_packets=$reference_packets"
  echo "reference_bytes=$reference_bytes"
  echo "reference_flow=$reference_flow"
  echo "flowcap_args=$flowcap_args"
  echo "bpf_stats_enabled=$bpf_stats_enabled"
  echo "collector_cpu_scope=userspace_process_only"
  echo "metrics_snapshot_phase=before_shutdown"
  ip -details link show "$iface"
  if command -v ethtool >/dev/null 2>&1; then ethtool -k "$iface" 2>&1; fi
} >"$output_dir/environment.txt"

# FLOWCAP_ARGS is intentionally word-split as documented CLI arguments. The
# traffic command is supplied by the benchmark operator and runs in a shell.
# shellcheck disable=SC2086
./bin/flowcap -json -interval 1 -metrics-addr "127.0.0.1:$metrics_port" $flowcap_args "$iface" \
  >"$output_dir/flows.jsonl" 2>"$output_dir/collector.log" &
collector_pid=$!
sampler_pid=""
cleanup() {
  if kill -0 "$collector_pid" 2>/dev/null; then
    kill -TERM "$collector_pid" 2>/dev/null || true
    wait "$collector_pid" 2>/dev/null || true
  fi
  if [[ -n "$sampler_pid" ]]; then wait "$sampler_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

for _ in {1..50}; do
  if curl --fail --silent "http://127.0.0.1:$metrics_port/metrics" >/dev/null; then break; fi
  if ! kill -0 "$collector_pid" 2>/dev/null; then
    echo "collector exited during startup; see $output_dir/collector.log" >&2
    exit 1
  fi
  sleep 0.1
done
curl --fail --silent "http://127.0.0.1:$metrics_port/metrics" >/dev/null || { echo "metrics endpoint did not start" >&2; exit 1; }

(
  echo $'timestamp\tcpu_percent\trss_kib'
  while kill -0 "$collector_pid" 2>/dev/null; do
    printf '%s\t' "$(date +%s)"
    ps -p "$collector_pid" -o %cpu=,rss= | awk '{ print $1 "\t" $2 }'
    sleep 1
  done
) >"$output_dir/resources.tsv" &
sampler_pid=$!

traffic_status=0
traffic_started_ns="$(date +%s%N)"
timeout --signal=TERM --kill-after=5s "${duration}s" bash -lc "$traffic_cmd" \
  >"$output_dir/traffic.log" 2>&1 || traffic_status=$?
traffic_finished_ns="$(date +%s%N)"
traffic_elapsed_ns="$((traffic_finished_ns-traffic_started_ns))"
if [[ "$traffic_status" -ne 0 && "$traffic_status" -ne 124 ]]; then
  echo "traffic generator failed with status $traffic_status" >&2
  exit 1
fi
sleep 2
curl --fail --silent "http://127.0.0.1:$metrics_port/metrics" >"$output_dir/metrics.prom"
if command -v bpftool >/dev/null 2>&1; then
  bpftool -j prog show >"$output_dir/bpf-programs-before-shutdown.json" \
    2>"$output_dir/bpftool.log" || true
fi
kill -TERM "$collector_pid"
collector_status=0
wait "$collector_pid" || collector_status=$?
wait "$sampler_pid" 2>/dev/null || true
sampler_pid=""
trap - EXIT

read -r exported_packets exported_bytes total_exported_packets total_exported_bytes selected_records background_records < <(
python3 - \
  "$output_dir/flows.jsonl" \
  "$reference_filter_enabled" \
  "$reference_src_ip" \
  "$reference_src_port" \
  "$reference_dst_ip" \
  "$reference_dst_port" \
  "$reference_protocol" \
  "$reference_direction" <<'PY'
import json
import sys

path = sys.argv[1]
filter_enabled = sys.argv[2] == "1"
if filter_enabled:
    raw_expected = {
        "src_ip": sys.argv[3],
        "src_port": sys.argv[4],
        "dst_ip": sys.argv[5],
        "dst_port": sys.argv[6],
        "protocol": sys.argv[7],
        "flow_direction": sys.argv[8],
    }
    numeric_fields = {"src_port", "dst_port", "protocol"}
    expected = {
        field: int(value) if field in numeric_fields else value
        for field, value in raw_expected.items()
        if value
    }

selected_packets = 0
selected_bytes = 0
total_packets = 0
total_bytes = 0
selected_records = 0
background_records = 0
with open(path, encoding="utf-8") as records:
    for line_number, line in enumerate(records, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"invalid JSON record at line {line_number}: {error}")
        packets = int(record["packets"])
        byte_count = int(record["bytes"])
        total_packets += packets
        total_bytes += byte_count
        matches = not filter_enabled or all(record[field] == value for field, value in expected.items())
        if matches:
            selected_packets += packets
            selected_bytes += byte_count
            selected_records += 1
        else:
            background_records += 1
print(
    selected_packets,
    selected_bytes,
    total_packets,
    total_bytes,
    selected_records,
    background_records,
)
PY
)
export_errors="$(awk '/^flowcap_export_errors_total/ { sum += $NF } END { print sum + 0 }' "$output_dir/metrics.prom")"
map_full="$(awk '/^flowcap_dropped_packets_total\{reason="map_full"\}/ { print $NF }' "$output_dir/metrics.prom")"
scan_complete="$(awk '/^flowcap_export_scan_complete / { print $NF }' "$output_dir/metrics.prom")"
traffic_elapsed_seconds="$(awk -v ns="$traffic_elapsed_ns" 'BEGIN { printf "%.6f", ns / 1000000000 }')"
reference_pps="$(awk -v packets="$reference_packets" -v ns="$traffic_elapsed_ns" 'BEGIN { if (ns > 0) printf "%.2f", packets * 1000000000 / ns; else print "unknown" }')"
reference_mbps="$(awk -v bytes="$reference_bytes" -v ns="$traffic_elapsed_ns" 'BEGIN { if (ns > 0) printf "%.3f", bytes * 8 * 1000 / ns; else print "unknown" }')"
read -r average_cpu max_cpu average_rss max_rss < <(
  awk 'NR > 1 && NF >= 3 { cpu += $2; rss += $3; count++; if ($2 > max_cpu) max_cpu = $2; if ($3 > max_rss) max_rss = $3 } END { if (count) printf "%.2f %.2f %.0f %d\n", cpu/count, max_cpu, rss/count, max_rss; else print "unknown unknown unknown unknown" }' "$output_dir/resources.tsv"
)
background_packets="$((total_exported_packets-exported_packets))"
background_bytes="$((total_exported_bytes-exported_bytes))"

{
  echo "collector_exit_status=$collector_status"
  echo "traffic_exit_status=$traffic_status"
  echo "traffic_elapsed_seconds=$traffic_elapsed_seconds"
  echo "reference_packets_per_second=$reference_pps"
  echo "reference_megabits_per_second=$reference_mbps"
  echo "reference_flow=$reference_flow"
  echo "reference_packets=$reference_packets"
  echo "exported_packets=$exported_packets"
  echo "packet_difference=$((exported_packets-reference_packets))"
  echo "reference_bytes=$reference_bytes"
  echo "exported_bytes=$exported_bytes"
  echo "byte_difference=$((exported_bytes-reference_bytes))"
  echo "selected_records=$selected_records"
  echo "total_exported_packets=$total_exported_packets"
  echo "total_exported_bytes=$total_exported_bytes"
  echo "background_records=$background_records"
  echo "background_packets=$background_packets"
  echo "background_bytes=$background_bytes"
  echo "collector_average_cpu_percent=$average_cpu"
  echo "collector_max_cpu_percent=$max_cpu"
  echo "collector_average_rss_kib=$average_rss"
  echo "collector_max_rss_kib=$max_rss"
  echo "bpf_stats_enabled=$bpf_stats_enabled"
  echo "export_errors=$export_errors"
  echo "map_full_packets=${map_full:-unknown}"
  echo "last_scan_complete=${scan_complete:-unknown}"
} | tee "$output_dir/summary.txt"

if [[ "$collector_status" -ne 0 || "$export_errors" != "0" || "$exported_packets" != "$reference_packets" || "$exported_bytes" != "$reference_bytes" ]]; then
  echo "benchmark did not meet its supplied reference; artifacts: $output_dir" >&2
  exit 1
fi
echo "benchmark matched the supplied reference; artifacts: $output_dir"
