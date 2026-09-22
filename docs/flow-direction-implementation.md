# Flow Direction Implementation Plan

## Objective

Add an explicit `flow_direction` dimension to every captured flow. The value
describes the TCX observation hook on the monitored interface:

- `ingress`: the packet was observed by the TCX ingress program;
- `egress`: the packet was observed by the TCX egress program.

The direction is not the connection initiator and does not classify traffic as
internal or external to a network perimeter.

## Design

### eBPF flow identity

Extend `struct flow_key` with a one-byte `flow_direction` field. Replace one
byte of the existing padding so the key remains 16 bytes:

```c
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 flow_direction;
    __u8 pad[2];
};
```

Use numeric values compatible with the IPFIX `flowDirection` information
element:

| Value | Meaning |
|---:|---|
| `0` | ingress |
| `1` | egress |

Direction must be part of the map key rather than the map value. This prevents
an otherwise identical tuple observed at both hooks from sharing counters.

### eBPF programs

Move the common packet-processing logic into an always-inlined helper accepting
the direction. Expose two classifier entry points:

- `flow_capture_ingress` passes ingress;
- `flow_capture_egress` passes egress.

Both programs continue to use the same flow, generation, and drop-counter maps.

### Userspace attachment

Attach `flow_capture_ingress` only to `AttachTCXIngress` and
`flow_capture_egress` only to `AttachTCXEgress`. Resource ownership and shutdown
ordering remain unchanged.

### Output schema

Add a string field to JSON:

```json
"flow_direction": "ingress"
```

Add `direction=ingress` or `direction=egress` to the human-readable record.
Unknown numeric values should be rendered as `unknown` rather than causing the
export cycle to fail.

This is an additive output change. Flowcap does not pin its maps between runs,
so the internal key layout does not require an on-disk migration.

### Prometheus metrics

Do not change existing metric label sets in this change. Raw direction remains
available in flow records. Direction-specific aggregate metrics can be added
later under new metric names without breaking existing PromQL queries.

## Implementation Checklist

- [x] Define ingress and egress direction constants in eBPF.
- [x] Add `flow_direction` to `struct flow_key` without increasing its size.
- [x] Refactor packet processing into a shared direction-aware helper.
- [x] Add separate ingress and egress eBPF entry programs.
- [x] Regenerate the bpf2go bindings for both byte orders.
- [x] Attach the ingress program to TCX ingress and the egress program to TCX egress.
- [x] Add Go direction constants and a safe string conversion helper.
- [x] Include `flow_direction` in JSON flow records.
- [x] Include direction in human-readable flow records.
- [x] Include direction in the stable flow-instance ordering.
- [x] Update unit tests for JSON and text output.
- [x] Test that equal 5-tuples with different directions remain distinct exporter instances.
- [x] Add integration coverage for both eBPF entry programs and their map keys.
- [x] Update the TCX attach/detach integration test for the two programs.
- [x] Document the new key field and output field in README and architecture docs.
- [x] Update visualization guidance to use `flow_direction` consistently.
- [x] Run formatting, unit tests, lint, race tests, build, bytecode verification, and `git diff --check`.
- [x] Run the privileged kernel integration tests with `make test-integration`.

The privileged integration suite was validated on 2026-09-14 with:

- Linux `6.17.0-23-generic`;
- Go `1.27.1`;
- Clang/LLVM `18.1.3`;
- iproute2 `6.1.0` and libbpf `1.3.0`.

All three integration tests passed: locked snapshots and capacity, distinct
ingress/egress map entries, and TCX attach/detach. The attach/detach test uses a
temporary dummy interface which may remain DOWN because the test does not send
traffic through it.

## Acceptance Criteria

- Every exported flow record contains exactly one of `ingress`, `egress`, or
  the defensive fallback `unknown`.
- A packet processed by the ingress program creates or updates only an ingress
  map entry.
- The same packet processed by the egress program creates or updates a distinct
  egress map entry.
- Delta confirmation, rate limiting, final drain, and map capacity logic treat
  the two directions as distinct flow instances.
- Existing Prometheus metric names and label sets are unchanged.
- The eBPF flow key remains 16 bytes.
