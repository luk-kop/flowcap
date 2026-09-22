# Export protocol

Flowcap keeps cumulative counters in the kernel and exports deltas from the last successfully written snapshot. A normal export never deletes a flow map entry.

## Flow identity

The identity of one flow instance is:

```text
(source IP, destination IP, source port, destination port, protocol, flow direction, generation)
```

The eBPF program assigns `generation` from a global 64-bit atomic counter when it prepares a new map entry. Competing inserts may consume unused generation values, which is harmless. The entry that wins `BPF_NOEXIST` retains its generation. Production entries remain in the HASH map until final drain, so a directional 5-tuple has one generation during one program run. Identical packet-header tuples observed at ingress and egress are distinct flow instances.

Generation counter wraparound is not handled. At one billion new instances per second it would take more than 584 years to wrap 64 bits, so this is outside the supported operating lifetime of one loaded program.

## Snapshot confirmation

For each observed instance, userspace stores the last cumulative `packets` and `bytes` values whose delta was written successfully:

```text
delta = current kernel counters - last confirmed counters
```

The first observation exports the full cumulative value. An observation with no counter change produces no output. The confirmation advances only after the complete record, including its newline, has been accepted by the configured writer. If writing fails, the failed and unattempted observations remain unconfirmed.

Flowcap stops after an output error. A record may have been partially accepted by the operating system, so automatically retrying that record could produce a malformed or duplicated stream. Flowcap provides at-most-once write attempts, not exactly-once delivery or downstream durability.

## Concurrent updates

A packet arriving after a map value was copied is reflected in a later cumulative snapshot. Since normal export does not delete the live value, that update is not removed by the former read-then-delete sequence.

Packet updates hold the `bpf_spin_lock` embedded in the flow value. Userspace copies a value using `BPF_F_LOCK`. Consequently packets, bytes, first/last timestamps and flags come from one completed update boundary. `first_seen` is the minimum and `last_seen` the maximum packet timestamp, without a bounded retry loop.

## Iterator behavior

The key walk can return the same entry more than once or abort when the map changes concurrently. Flowcap keys confirmation state by full flow identity. An identical repeated snapshot has a zero delta and is not exported twice. A repeated snapshot with larger counters exports only the newly observed increment. The walk is bounded by map capacity, and rate-limited cycles rotate a stable flow order after the last confirmed instance to prevent starvation.

A scan error fails the cycle and is reported. The partial scan is not treated as a complete scan or successful final drain. This deliberately prefers an explicit failed cycle over releasing data based on an incomplete view.

## Capacity and state retention

The kernel map is `BPF_MAP_TYPE_HASH`. It retains entries until shutdown because deleting an active entry would reopen the read/delete race. At capacity, new flow inserts fail visibly and each unaccounted packet increments `map_full`; existing entries remain available. Userspace confirmation state is therefore bounded by the configured map capacity.

A missing iterator result is not used to discard confirmation. Before releasing state, userspace performs a locked direct lookup and proves that the instance is absent or has a different generation. Final drain verifies all deltas as confirmed, deletes entries only after TCX detach, and requires a subsequent complete empty scan.

## Rate limiting

`max-export-per-cycle` limits records with a non-zero delta. Records not attempted because the limit was reached remain unconfirmed and are eligible for a later cycle. It does not limit map scanning.

## Shutdown

The intended shutdown sequence is:

1. stop scheduling periodic exports;
2. detach egress and ingress TCX links;
3. keep eBPF maps open;
4. take one complete cumulative snapshot without the normal export limit;
5. write all remaining deltas and verify that none remains unconfirmed;
6. delete drained entries and verify a complete empty scan;
7. sync optional statistics and close resources.

Flowcap uses explicit `BPF_LINK_DETACH`, rather than relying on file-descriptor close. In [Linux 6.6 TCX](https://github.com/torvalds/linux/blob/v6.6/include/net/tcx.h#L50-L56), the detach path replaces the attachment and calls `synchronize_rcu()` before returning, which waits for users of the old attachment. If detach fails, final drain is skipped and the process exits non-zero. If flow output has already failed, shutdown does not retry it.

## Time fields

Each JSON record contains:

- `first_seen` and `last_seen`: wall-clock approximations derived from kernel monotonic timestamps;
- `window_start`: creation time for the first delta, then the previous confirmed observation time;
- `window_end`: time immediately after the map lookup that produced the current snapshot;
- `export_time`: wall-clock time paired with the monotonic reference used for conversion;
- `duration_ns`: lifetime activity duration, `last_seen - first_seen`.

`bytes / duration` is a burst/activity rate, not an average over the exported delta window. A window average uses `bytes / (window_end - window_start)`. The clock conversion is an approximation and can reflect wall-clock corrections between export cycles; durations remain based on the monotonic clock.
