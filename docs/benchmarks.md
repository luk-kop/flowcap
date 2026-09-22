# Benchmark plan

The first controlled TUN results and the resulting architecture decisions are
recorded in [Benchmark results: Linux TUN, 2026-09-14](benchmark-results-2026-09-14.md).

Run the harness as root on an isolated test interface. The traffic command must produce known packet and byte totals at the TC attachment point:

```bash
sudo -E env \
  TRAFFIC_CMD='./your-generator --interface tun-test --duration 60' \
  REFERENCE_PACKETS=1000000 \
  REFERENCE_BYTES=128000000 \
  DURATION=60 \
  ./scripts/benchmark.sh tun-test
```

Build the binary as the normal workspace user before starting the privileged harness. The harness starts Flowcap with one-second export cycles, executes the generator for at most `DURATION`, samples collector CPU/RSS, scrapes Prometheus metrics, sends SIGTERM, waits for the verified drain, and sums exported JSON deltas. It fails if the collector or generator fails, any export error is reported, or exported totals differ from the supplied reference. Artifacts are written below `/tmp/flowcap-benchmark-<timestamp>/` by default; set `OUTPUT_DIR` to choose another location. Additional collector flags can be supplied with `FLOWCAP_ARGS`.

On a real interface, unrelated traffic can make whole-interface totals differ even when the controlled flow is exact. Supply one or more selectors to compare the reference against matching records while still reporting total and background traffic:

```bash
sudo -E env \
  TRAFFIC_CMD='python3 /tmp/udp_sustained.py' \
  REFERENCE_PACKETS=1000000 \
  REFERENCE_BYTES=128000000 \
  REFERENCE_SRC_IP=10.8.0.2 \
  REFERENCE_SRC_PORT=30000 \
  REFERENCE_DST_IP=10.8.0.1 \
  REFERENCE_DST_PORT=9000 \
  REFERENCE_PROTOCOL=17 \
  REFERENCE_DIRECTION=egress \
  DURATION=40 \
  ./scripts/benchmark.sh tun0
```

Each selector is optional and an omitted field acts as a wildcard. For example, omit `REFERENCE_SRC_PORT` to match churn traffic across many source ports. `summary.txt` reports the selected totals, whole-interface totals, and their difference as background traffic. At least one selector enables filtering; with no selectors the reference applies to the whole interface.

Each result contains the commit, interface configuration and offloads, kernel/toolchain, reference totals, collector logs and output, CPU/RSS samples, pre-shutdown metrics, scan completeness, iterator duplicates, capacity failures, and the final delta comparison. The metrics snapshot is intentionally taken before `SIGTERM`; final-drain records are present in `flows.jsonl` but may not be represented in `metrics.prom`.

The sampled CPU percentage covers only the Flowcap userspace process. An eBPF TC program executes in packet-processing context, so this number does not measure its complete kernel cost. If `bpftool` is installed, the harness also writes `bpf-programs-before-shutdown.json`. Enable kernel BPF runtime statistics before a profiling run when their overhead is acceptable:

```bash
sudo sysctl -w kernel.bpf_stats_enabled=1
# Run the benchmark.
sudo sysctl -w kernel.bpf_stats_enabled=0
```

The environment and summary record whether BPF runtime statistics were enabled. The harness also reports the traffic command's elapsed time, supplied-reference PPS and throughput, plus average/maximum collector CPU and RSS.

Run separate controlled cases for stable existing flows, many new 5-tuples, bursts, HASH capacity pressure, and shutdown during active traffic. A slow-reader case needs an intentionally throttled downstream wrapper around Flowcap and should assert the documented non-zero timeout result; the standard harness writes directly to a file so that sink backpressure does not contaminate throughput measurements.

Do not treat a missing packet as an exporter loss without separating parser drops, HASH admission failures, and output failures. Results apply only to the tested interface and kernel.
