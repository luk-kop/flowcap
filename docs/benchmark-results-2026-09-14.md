# Benchmark results: Linux TUN, 2026-09-14

## Scope

These measurements validate Flowcap's correctness and bounded performance on
one real OpenVPN-backed Linux TUN interface. They are not a general throughput
claim for every interface, packet size, CPU topology, or kernel.

The tested collector was built from commit `cae19d994b9011e6671f4d86f7cda37745cec232`
with local uncommitted changes. Reproduce release measurements from a clean,
identified commit before publishing them as release figures.

## Environment

| Component | Value |
| --- | --- |
| Kernel | Linux `6.17.0-23-generic`, x86-64 |
| CPUs | 8 logical CPUs |
| Go | `1.27.1` |
| Clang/LLVM | `18.1.3`, BPF target `-mcpu=v3` |
| iproute2 / libbpf | `6.1.0` / `1.3.0` |
| bpftool | `7.7.0`, libbpf `1.7` |
| Interface | `tun0`, L3 TUN, MTU 1420, no packet-info or vnet header |
| Client / peer | `10.8.0.2` / `10.8.0.1` |
| UDP payload | 100 bytes, therefore 128 bytes at the L3 TC hook |
| Export interval | 1 second |

OpenVPN DCO was disabled for the accepted measurements. See the DCO kernel
issue below.

## Results

| Case | Controlled workload | Result |
| --- | --- | --- |
| Bidirectional ICMP correctness | 1,000 requests and 1,000 replies, 1,028 bytes each | Exact: 2,000 packets and 2,056,000 bytes; 1,000 packets in each direction |
| Stable UDP burst | One directional flow, 100,000 packets | Exact: 100,000 packets and 12,800,000 bytes; no drops or export errors |
| Churn correctness | 5,000 source ports, 10 packets per flow | Exact: 5,000 directional flow instances, 50,000 packets and 6,400,000 bytes |
| Profiled churn burst | The same 5,000 flows and 50,000 packets | 0.133182 s, 375,425.76 packets/s and 384.436 Mbit/s; no unexplained loss |
| Export backlog | 5,000 flows with `max-export-per-cycle=100` | Exact batches of 100, 100, and a 4,800-record final drain |
| HASH capacity | 5,000 flows with `max-flows=1024` | Expected admission result: 10,240 exported packets plus 39,760 `map_full` packets equals all 50,000 inputs |
| Sustained stable flow | 1,000,000 packets over 20 seconds | Exact selected flow: 49,920.35 packets/s, 51.118 Mbit/s and 128,000,000 bytes |
| Bidirectional UDP profile | 100,000 sent datagrams with a userspace echo peer | BPF/export agreement was exact; 100,000 UDP egress, 99,929 UDP ingress and 6 locally generated ICMP errors |
| Real pipe lifecycle | Signal during a blocked pipe, closed pipe, and write deadline | All `TestLifecycleRealPipe` modes passed and reported bounded incomplete shutdown where required |

All accepted correctness cases reported zero parser, linearization, iterator,
export, and unexplained packet errors. The capacity case intentionally returned
a non-zero harness result because the supplied reference described all input
traffic while the smaller HASH map deliberately rejected new flow instances.

The bidirectional UDP mismatch occurred before Flowcap's ingress hook. Kernel
BPF invocation counts exactly matched exported records:

| Program | BPF invocations | Exported packets | Mean BPF runtime |
| --- | ---: | ---: | ---: |
| Stable-flow egress | 1,000,000 | 1,000,000 | 89.07 ns/invocation |
| Churn egress | 50,000 | 50,000 | 94.69 ns/invocation |
| Bidirectional egress | 100,006 | 100,006 | 113.80 ns/invocation |
| Bidirectional ingress | 99,929 | 99,929 | 109.69 ns/invocation |

In the bidirectional case, 71 expected UDP replies did not reach TC ingress and
six 156-byte ICMP packets were emitted after the client socket closed. This
fully explains the whole-interface difference:

```text
-71 * 128 bytes + 6 * 156 bytes = -8,152 bytes
```

The sustained-flow collector RSS averaged 13,780 KiB and peaked at 13,884 KiB.
The userspace collector CPU rounded to 0.00% because it exported one flow delta
per second. This process metric excludes TC program execution in packet
processing context; the BPF runtime figures above are the relevant kernel-side
measurement.

## Decisions

- Retain `BPF_MAP_TYPE_HASH`. The capacity test made overload explicit and
  accounted for every rejected packet through `map_full`.
- Retain the default `max-flows=16384`. The tested 5,000-flow churn workload
  remained below the limit; operators expecting greater cardinality must size
  it explicitly and monitor capacity drops.
- Retain cumulative counters, locked snapshots, generation identifiers, and
  final unlimited drain. Stable, churn, rate-limited, and shutdown cases all
  preserved their supplied totals.
- Do not introduce per-CPU flow maps, double buffering, or batch-map APIs based
  on these results. No measured correctness or performance problem in the
  tested envelope justifies their additional state and lifecycle complexity.
- Retain `bpf_skb_pull_data`. Its cost is included in the measured whole-program
  runtime and did not require separate optimization in the tested envelope.
- Keep direction out of existing Prometheus label sets. Direction remains part
  of the raw flow identity and output record.

## OpenVPN DCO kernel issue

The first run used the `ovpn` DCO network device from Linux
`6.17.0-23-generic`. All 1,000 incoming ICMP replies reached the TCX ingress
program but were presented with a stale MAC-header offset and consequently
looked like fragments to Flowcap. Outgoing packets were unaffected.

This is a kernel driver issue fixed upstream by
[`a200cdbf9593`](https://git.kernel.org/netdev/net/c/a200cdbf9593), which resets
the MAC header after OpenVPN decapsulation. Use a kernel containing that fix or
start OpenVPN with `--disable-dco` so it uses the legacy TUN driver. After DCO
was disabled, the same bidirectional reference matched exactly.

### DCO baseline repeated on 2026-09-22

A second run on Linux `6.17.0-23-generic` used the `ovpn` DCO interface `tun0`
(MTU 1420) and a Flowcap build from
`cae19d994b9011e6671f4d86f7cda37745cec232` with local uncommitted changes.
The traffic command was
`ping -4 -n -q -I tun0 -c 1000 -s 1000 -i 0.005 10.8.0.1`.
Ping reported 1,000 requests and 1,000 replies with 0% packet loss. Each IPv4
packet was 1,028 bytes, giving a reference of 2,000 packets and 2,056,000 bytes.

Flowcap exported exactly 1,000 egress packets and 1,028,000 bytes, with no
ingress records. The `fragments` counter increased by 1,000; `parse_error`,
`linearize`, `map_full`, and export errors remained at zero. The collector exited
successfully and its final scan was complete. The benchmark reported a mismatch
because all 1,000 received replies were missing from Flowcap's output. BPF
runtime statistics were disabled, so this run is a correctness baseline rather
than a kernel-side performance measurement.

The complete raw result is copied locally to
`local-benchmarks/2026-09-22-openvpn-dco-baseline/`. That directory is ignored
by Git because it includes flow records and host-specific diagnostic output.

## Validated envelope and remaining limits

The evidence supports exact Flowcap accounting at its TC hooks for the tested
L3 TUN configuration up to:

- 50,000 packets/s sustained for one flow;
- approximately 375,000 packets/s in a short 5,000-flow burst;
- 5,000 new directional flow instances in 0.133 seconds;
- 5,000 retained flow instances with an intentionally restricted export rate;
- explicit capacity accounting at a 1,024-entry HASH limit.

Do not extrapolate these figures to 5/10 Gbit/s, minimum-size packets,
multi-generator CPU scaling, another interface type, or another kernel.
Precise scan-versus-serialization timing was not isolated from the full export
cycle. Kernel `6.6`, the documented minimum, still requires the same privileged
runtime suite before release support for that exact boundary is confirmed.
