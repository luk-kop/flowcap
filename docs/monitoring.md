# Monitoring

## Prometheus Metrics

Prometheus metrics are disabled by default. Enable with `-metrics-addr`:

```bash
sudo ./flowcap -metrics-addr 127.0.0.1:9090 wg0
```

**Available metrics:**

```text
flowcap_map_flows                           # Number of flows in the eBPF map at the start of the export cycle
flowcap_exported_total{type="active"}       # Total exported active flows
flowcap_exported_total{type="inactive"}     # Total exported inactive flows
flowcap_exported_total{type="closed"}       # Total exported closed flows
flowcap_exported_bytes_total                # Total bytes exported
flowcap_exported_packets_total              # Total packets exported
flowcap_config_interval_seconds            # Configured export interval
flowcap_config_timeout_seconds             # Configured inactivity timeout
flowcap_config_max_flows                   # Configured max concurrent flows
flowcap_config_max_export_per_cycle        # Configured max flows per export cycle
flowcap_dropped_total{reason="fragments"}  # Total dropped IP fragments
flowcap_dropped_total{reason="non_ipv4"}   # Total dropped non-IPv4 packets (IPv6, ARP, etc.)
flowcap_dropped_total{reason="parse_error"} # Total dropped packets due to parse errors
```

**Raw output example** (`curl http://127.0.0.1:9090/metrics`):

```text
# HELP flowcap_config_interval_seconds Configured flow export interval in seconds
# TYPE flowcap_config_interval_seconds gauge
flowcap_config_interval_seconds 10
# HELP flowcap_config_max_export_per_cycle Configured maximum flows to export per cycle
# TYPE flowcap_config_max_export_per_cycle gauge
flowcap_config_max_export_per_cycle 10000
# HELP flowcap_config_max_flows Configured maximum number of concurrent flows
# TYPE flowcap_config_max_flows gauge
flowcap_config_max_flows 16384
# HELP flowcap_config_timeout_seconds Configured flow inactivity timeout in seconds
# TYPE flowcap_config_timeout_seconds gauge
flowcap_config_timeout_seconds 60
# HELP flowcap_dropped_total Total packets dropped (not tracked as flows) by reason
# TYPE flowcap_dropped_total counter
flowcap_dropped_total{reason="non_ipv4"} 2035
# HELP flowcap_exported_bytes_total Total bytes exported across all flows
# TYPE flowcap_exported_bytes_total counter
flowcap_exported_bytes_total 6.066156e+07
# HELP flowcap_exported_packets_total Total packets exported across all flows
# TYPE flowcap_exported_packets_total counter
flowcap_exported_packets_total 53229
# HELP flowcap_exported_total Total number of exported flows by type
# TYPE flowcap_exported_total counter
flowcap_exported_total{type="active"} 6292
flowcap_exported_total{type="closed"} 35
# HELP flowcap_map_flows Number of flows in the eBPF map at the start of the export cycle
# TYPE flowcap_map_flows gauge
flowcap_map_flows 22
```

> Standard Go runtime (`go_*`), process (`process_*`), and HTTP handler (`promhttp_*`) metrics are also exposed but omitted here for brevity.

**Scrape configuration:**

```yaml
scrape_configs:
  - job_name: 'flowcap'
    static_configs:
      - targets: ['localhost:9090']
```

**Example Grafana queries:**

```promql
# Flows in eBPF map (capacity planning)
flowcap_map_flows

# Flow export rate by type
rate(flowcap_exported_total[5m])

# Bandwidth throughput (bytes per second)
rate(flowcap_exported_bytes_total[1m])

# Packet rate
rate(flowcap_exported_packets_total[1m])

# Timeout rate (useful for tuning -timeout parameter)
rate(flowcap_exported_total{type="inactive"}[5m])

# Dropped packets by reason (fragments, non-IPv4, parse errors)
rate(flowcap_dropped_total[5m])

# Fragment drop rate (may indicate MTU/PMTUD issues)
rate(flowcap_dropped_total{reason="fragments"}[5m])
```

## Log Collectors

Use `-json` flag to output structured JSON for log collectors (Promtail, Filebeat, etc.):

```bash
sudo ./flowcap -json wg0 | tee -a /var/log/flows.json
```

**Promtail (Loki) configuration:**

```yaml
scrape_configs:
  - job_name: flow-logs
    static_configs:
      - targets: [localhost]
        labels:
          job: flowcap
          __path__: /var/log/flows.json
    pipeline_stages:
      - json:
          expressions:
            src_ip: src_ip
            dst_ip: dst_ip
            bytes: bytes
            packets: packets
```

**Filebeat (Elasticsearch) configuration:**

```yaml
filebeat.inputs:
  - type: log
    paths: ["/var/log/flows.json"]
    json.keys_under_root: true
    json.add_error_key: true
```

## Choosing a Backend

| Backend | Best for | Notes |
|---|---|---|
| **Loki** | Raw flow logs | Designed for log streams, native Grafana integration |
| **Elasticsearch** | Forensics, historical analysis | Powerful search and aggregation |
| **InfluxDB** | Time-series analysis | Better high-cardinality support than Prometheus |
| **Prometheus** | Aggregated metrics only | Not suitable for raw flows due to cardinality explosion |

**Recommendation:** Loki for raw flows (`-json`) + Prometheus for aggregated metrics (`-metrics-addr`).
