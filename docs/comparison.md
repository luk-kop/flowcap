# flowcap vs Other Network Monitoring Tools

## Overview

| | **flowcap** | **softflowd** | **Cilium Hubble** | **ntopng** | **tcpdump** | **Packetbeat** | **AWS VPC Flow Logs** |
|---|---|---|---|---|---|---|---|
| **Approach** | eBPF flow aggregation | libpcap + NetFlow export | eBPF (Cilium CNI) | DPI + flow analysis | Raw packet capture | libpcap + L7 decode | Managed AWS service |
| **Layer** | L3/L4 | L3/L4 | L3/L4 + K8s identity | L3-L7 (DPI) | L2-L7 (raw) | L7 (application) | L3/L4 |
| **Capture** | Kernel (eBPF) | Userspace (libpcap) | Kernel (eBPF) | Userspace (libpcap/nDPI) | Userspace (libpcap) | Userspace (libpcap/AF_PACKET) | AWS-managed (ENI) |
| **Overhead** | Minimal | Medium | Low | High | High | Medium-high | None (managed) |
| **Environment** | Any Linux | Any Linux/BSD | Kubernetes only | Any Linux | Anywhere | Any Linux | AWS VPC only |
| **Output** | stdout/JSON, Prometheus | NetFlow v5/v9, IPFIX | gRPC API, Prometheus | Web UI, API | pcap/text | Elasticsearch, Logstash, Kafka | CloudWatch, S3, Firehose |
| **Dependencies** | Kernel 6.6+ (TCX) | libpcap | Cilium CNI | nDPI, Redis | libpcap | Elastic Stack | AWS account |
| **Configuration** | Simple (CLI flags) | Simple | Complex (K8s) | Complex (Web UI) | Simple | Medium (YAML) | Limited |
| **License** | Open source | BSD | Apache 2.0 | GPLv3 | BSD | Apache 2.0 | Commercial |

## Detailed Comparison

### flowcap vs softflowd

softflowd is the closest equivalent - both produce flow records from live traffic.

| | **flowcap** | **softflowd** |
|---|---|---|
| **Capture method** | eBPF in kernel - zero packet copy | libpcap in userspace - copies every packet |
| **Aggregation** | Kernel hash map (O(1) lookup) | Userspace hash table |
| **Output** | Direct stdout/JSON | NetFlow/IPFIX - requires external collector (nfcapd) |
| **TCP lifecycle** | FIN/RST detection | Full TCP state tracking |
| **Monitoring** | Built-in Prometheus metrics | None |
| **High traffic** | Handles high rates without drops | May drop packets under load |
| **Pipeline** | Simple: flowcap -> Loki/file | Complex: softflowd -> nfcapd -> nfdump |

**Choose flowcap** when you need a simple, low-overhead flow exporter with direct JSON output.
**Choose softflowd** when you need standard NetFlow/IPFIX export for existing collectors.

### flowcap vs Cilium Hubble

| | **flowcap** | **Cilium Hubble** |
|---|---|---|
| **Environment** | Any Linux interface | Kubernetes only (requires Cilium CNI) |
| **Flow identity** | IP-based (5-tuple) | Identity-aware (pod, service, namespace) |
| **Visibility** | Network flows | Network flows + K8s context + network policy verdicts |
| **UI** | None (CLI) | Hubble UI, Hubble CLI |
| **Setup** | Single binary, root access | Cilium CNI deployment |
| **Protocol support** | TCP/UDP/ICMP | TCP/UDP/ICMP + HTTP, DNS, Kafka (L7) |

**Choose flowcap** for non-Kubernetes environments or simple interface-level monitoring.
**Choose Hubble** when running Kubernetes with Cilium and you need pod/service-level visibility.

### flowcap vs ntopng

| | **flowcap** | **ntopng** |
|---|---|---|
| **Focus** | Lightweight flow export | Full network monitoring platform |
| **Analysis** | L3/L4 flow aggregation | Deep packet inspection (L7), application detection |
| **UI** | None (CLI + Prometheus/Grafana) | Built-in web dashboard |
| **Alerting** | Via Prometheus/Grafana | Built-in alerts |
| **Resource usage** | Minimal (eBPF, ~100 bytes/flow) | High (DPI, in-memory DB) |
| **Dependencies** | None | nDPI, Redis, optional MySQL |
| **Deployment** | Single binary | Multi-component |

**Choose flowcap** for lightweight flow capture with minimal resource usage.
**Choose ntopng** when you need a full-featured network monitoring platform with DPI and built-in dashboards.

### flowcap vs tcpdump

| | **flowcap** | **tcpdump** |
|---|---|---|
| **Output** | Aggregated flows | Individual packets |
| **Data volume** | Compact (one record per flow per interval) | Massive (one record per packet) |
| **Use case** | Continuous monitoring | Debugging, forensics |
| **Storage** | Low | Very high |
| **Analysis** | Who talks to whom, how much data | Full packet payload and headers |
| **Long-term capture** | Yes (designed for it) | Impractical (data volume) |

**Choose flowcap** for continuous traffic monitoring and bandwidth analysis.
**Choose tcpdump** for short-term debugging and packet-level forensics.

### flowcap vs Packetbeat

| | **flowcap** | **Packetbeat** |
|---|---|---|
| **Layer** | L3/L4 (IP, TCP/UDP) | L7 (HTTP, DNS, MySQL, Redis, etc.) |
| **What it sees** | Who talks to whom, how much data | Request/response content, latency, status codes |
| **Capture** | eBPF (kernel) | libpcap/AF_PACKET (userspace) |
| **Overhead** | Minimal | Medium-high (protocol decoding) |
| **Output** | stdout/JSON, Prometheus | Elasticsearch, Logstash, Kafka |
| **Dependencies** | None | Elastic Stack |
| **Use case** | Bandwidth monitoring, flow analysis | APM, application debugging |

These tools are **complementary**: flowcap answers "who generates how much traffic", Packetbeat answers "what requests are made and how fast they are".

### flowcap vs AWS VPC Flow Logs

VPC Flow Logs capture network traffic at the ENI (Elastic Network Interface) level within an AWS VPC.

- **Aggregation window:** 1 minute or 10 minutes (not configurable beyond these options)
- **Flow key:** 5-tuple (src/dst IP, src/dst port, protocol) - same as flowcap
- **Metrics:** packets, bytes, action (ACCEPT/REJECT), log-status
- **Destination:** CloudWatch Logs, S3, Kinesis Data Firehose
- **Latency:** Minutes from capture to availability
- **Deployment:** Zero-touch, managed by AWS

| | **flowcap** | **AWS VPC Flow Logs** |
|---|---|---|
| **Environment** | Any Linux (bare metal, VM, container) | AWS VPC (ENI) only |
| **Latency** | Seconds (default 10s) | 1-10 minutes |
| **TCP flags** | Full per-flow flags | v5+ only (limited) |
| **Flow lifecycle** | Smart: FIN/RST detection, inactivity timeout | Simple time window |
| **Cost** | Free, minimal CPU overhead | Per GB ingested/stored |
| **Configuration** | Full control (interval, timeout, max-flows) | Limited |
| **Accept/Reject** | No - sees all traffic | Yes (security groups) |
| **Deployment** | Requires root + eBPF (kernel 6.6+) | Zero-touch |
| **Interface support** | Any interface (ethernet, WireGuard, bridges, VLANs) | AWS ENI only |

**Choose flowcap** for non-AWS infrastructure, VPN tunnels, real-time visibility, or cost control on high-traffic environments.
**Choose VPC Flow Logs** for AWS-native workloads, security group visibility, compliance, or multi-account centralized logging.

## Summary

| Use case | Recommended tool |
|---|---|
| Lightweight flow capture on any Linux host | **flowcap** |
| Standard NetFlow/IPFIX export | softflowd |
| Kubernetes network observability | Cilium Hubble |
| Full network monitoring with DPI | ntopng |
| Packet-level debugging | tcpdump |
| Application protocol monitoring (HTTP, DNS, DB) | Packetbeat |
| AWS cloud-native flow logging | AWS VPC Flow Logs |
