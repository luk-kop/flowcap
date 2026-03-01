package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type flow_key -type flow_stats flow flowcap.c

var (
	// Prometheus metrics
	mapFlows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_map_flows",
		Help: "Number of flows in the eBPF map at the start of the export cycle",
	})
	exportedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flowcap_exported_total",
		Help: "Total number of exported flows by type",
	}, []string{"type"}) // type: active, inactive, closed
	exportedBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "flowcap_exported_bytes_total",
		Help: "Total bytes exported across all flows",
	})
	exportedPackets = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "flowcap_exported_packets_total",
		Help: "Total packets exported across all flows",
	})
	configInterval = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_config_interval_seconds",
		Help: "Configured flow export interval in seconds",
	})
	configTimeout = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_config_timeout_seconds",
		Help: "Configured flow inactivity timeout in seconds",
	})
	configMaxFlows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_config_max_flows",
		Help: "Configured maximum number of concurrent flows",
	})
	configMaxExport = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_config_max_export_per_cycle",
		Help: "Configured maximum flows to export per cycle",
	})
	droppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flowcap_dropped_total",
		Help: "Total packets dropped (not tracked as flows) by reason",
	}, []string{"reason"}) // reason: fragments, non_ipv4, parse_error
)

func init() {
	prometheus.MustRegister(mapFlows)
	prometheus.MustRegister(exportedTotal)
	prometheus.MustRegister(exportedBytes)
	prometheus.MustRegister(exportedPackets)
	prometheus.MustRegister(configInterval)
	prometheus.MustRegister(configTimeout)
	prometheus.MustRegister(configMaxFlows)
	prometheus.MustRegister(configMaxExport)
	prometheus.MustRegister(droppedTotal)
}

// Drop counter indices matching eBPF defines
const (
	dropFragments = 0
	dropNonIPv4   = 1
	dropParseErr  = 2
	dropMax       = 3
)

var dropReasonLabels = [dropMax]string{"fragments", "non_ipv4", "parse_error"}

func main() {
	interval := flag.Int("interval", 10, "flow export interval in seconds")
	timeout := flag.Int("timeout", 60, "flow inactivity timeout in seconds")
	maxFlows := flag.Int("max-flows", 16384, "maximum number of concurrent flows")
	maxExportPerCycle := flag.Int("max-export-per-cycle", 10000, "maximum flows to export per cycle")
	jsonOutput := flag.Bool("json", false, "output in JSON format")
	metricsAddr := flag.String("metrics-addr", "", "enable Prometheus metrics HTTP server at host:port (e.g. 127.0.0.1:9090)")
	statsFile := flag.String("stats-file", "", "optional file for detailed statistics logging")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <interface>\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	if *interval <= 0 {
		log.Fatalf("interval must be greater than 0, got %d", *interval)
	}
	if *interval > 3600 {
		log.Fatalf("interval too large (max: 3600s), got %d", *interval)
	}
	if *timeout <= 0 {
		log.Fatalf("timeout must be greater than 0, got %d", *timeout)
	}
	if *timeout > 86400 {
		log.Fatalf("timeout too large (max: 86400s), got %d", *timeout)
	}
	if *maxFlows <= 0 {
		log.Fatalf("max-flows must be greater than 0, got %d", *maxFlows)
	}
	if *maxFlows < 1024 {
		log.Fatalf("max-flows too small (min: 1024), got %d", *maxFlows)
	}
	if *maxFlows > 262144 {
		log.Fatalf("max-flows too large (max: 262144), got %d", *maxFlows)
	}
	if *maxExportPerCycle <= 0 {
		log.Fatalf("max-export-per-cycle must be greater than 0, got %d", *maxExportPerCycle)
	}
	if *maxExportPerCycle > *maxFlows {
		log.Fatalf("max-export-per-cycle (%d) cannot exceed max-flows (%d)", *maxExportPerCycle, *maxFlows)
	}
	if *timeout < *interval {
		log.Printf("Warning: timeout (%ds) is less than interval (%ds), flows may expire before export", *timeout, *interval)
	}
	if *metricsAddr != "" {
		host, port, err := net.SplitHostPort(*metricsAddr)
		if err != nil {
			log.Fatalf("invalid metrics-addr %q: must be host:port (e.g. 127.0.0.1:9090): %v", *metricsAddr, err)
		}
		if net.ParseIP(host) == nil {
			log.Fatalf("invalid metrics-addr %q: %q is not a valid IP address", *metricsAddr, host)
		}
		if port == "" {
			log.Fatalf("invalid metrics-addr %q: port is required", *metricsAddr)
		}
	}
	// Set config metrics
	configInterval.Set(float64(*interval))
	configTimeout.Set(float64(*timeout))
	configMaxFlows.Set(float64(*maxFlows))
	configMaxExport.Set(float64(*maxExportPerCycle))

	iface := flag.Arg(0)
	ifaceIndex := mustFindInterface(iface)

	// Open stats file if specified
	var statsWriter *os.File
	if *statsFile != "" {
		var err error
		statsWriter, err = os.OpenFile(*statsFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open stats file: %v", err)
		}
		defer func() {
			if err := statsWriter.Close(); err != nil {
				log.Printf("Failed to close stats file: %v", err)
			}
		}()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	spec, err := loadFlow()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Override max_entries for flows map
	spec.Maps["flows"].MaxEntries = uint32(*maxFlows)

	objs := &flowObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer func() {
		if err := objs.Close(); err != nil {
			log.Printf("Failed to close eBPF objects: %v", err)
		}
	}()

	// Attach to ingress (incoming packets)
	linkIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex,
		Program:   objs.FlowCapture,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("Failed to attach TC ingress: %v", err)
	}
	defer func() {
		if err := linkIngress.Close(); err != nil {
			log.Printf("Failed to close TC ingress link: %v", err)
		}
	}()

	// Attach to egress (outgoing packets)
	linkEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex,
		Program:   objs.FlowCapture,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("Failed to attach TC egress: %v", err)
	}
	defer func() {
		if err := linkEgress.Close(); err != nil {
			log.Printf("Failed to close TC egress link: %v", err)
		}
	}()

	// Optionally start Prometheus metrics server
	var metricsServer *http.Server
	metricsErrChan := make(chan error, 1)
	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		metricsServer = &http.Server{
			Addr:         *metricsAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  30 * time.Second,
		}
		go func() {
			log.Printf("Prometheus metrics available at http://%s/metrics", *metricsAddr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				metricsErrChan <- err
			}
		}()
	}

	log.Printf("Attached to %s, capturing flows (interval=%ds, timeout=%ds, max_flows=%d)...", iface, *interval, *timeout, *maxFlows)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(time.Duration(*interval) * time.Second)
	defer ticker.Stop()

	exporter := &flowExporter{}

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			exporter.exportFlows(objs.Flows, objs.DropCounters, *timeout, *jsonOutput, *maxExportPerCycle, statsWriter)
			if metricsServer != nil {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := metricsServer.Shutdown(shutdownCtx); err != nil {
					log.Printf("Metrics server shutdown error: %v", err)
				}
				shutdownCancel()
			}
			return
		case err := <-metricsErrChan:
			log.Printf("Metrics server failed: %v", err)
			return
		case <-ticker.C:
			exporter.exportFlows(objs.Flows, objs.DropCounters, *timeout, *jsonOutput, *maxExportPerCycle, statsWriter)
		}
	}
}

// ktimeNow returns the current monotonic clock time in nanoseconds using
// CLOCK_MONOTONIC, matching the bpf_ktime_get_ns() helper used in the eBPF
// program. Falls back to wall clock time if the syscall fails.
func ktimeNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Printf("Warning: ClockGettime failed: %v, falling back to wall clock", err)
		return uint64(time.Now().UnixNano())
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// readDropCounters reads the per-CPU drop counters from the eBPF map,
// sums values across all CPUs, and returns totals per drop reason.
func readDropCounters(dropMap *ebpf.Map) [dropMax]uint64 {
	var totals [dropMax]uint64
	for i := uint32(0); i < dropMax; i++ {
		var perCPU []uint64
		if err := dropMap.Lookup(i, &perCPU); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("Warning: drop counter lookup failed for %s: %v", dropReasonLabels[i], err)
			}
			continue
		}
		for _, v := range perCPU {
			totals[i] += v
		}
	}
	return totals
}

// exportFlows iterates over the eBPF flows map, exports each flow via
// printFlow, and deletes it from the map. Flows are classified as active,
// inactive (exceeded inactivityTimeout), or closed (TCP FIN/RST seen).
// At most maxExportPerCycle flows are exported per call to bound latency.
// If statsWriter is non-nil, a summary line is appended to that file.

// flowExporter holds state across export cycles. Must be used from a single
// goroutine (the main ticker loop) — no synchronisation is provided.
type flowExporter struct {
	prevDrops [dropMax]uint64
}

func (fe *flowExporter) exportFlows(flowMap *ebpf.Map, dropMap *ebpf.Map, timeoutSec int, jsonOutput bool, maxExportPerCycle int, statsWriter *os.File) {
	var key flowFlowKey
	var stats flowFlowStats
	iter := flowMap.Iterate()

	now := ktimeNow()
	inactivityTimeout := uint64(timeoutSec) * uint64(time.Second)

	var activeCount, inactiveCount, closedCount int
	var totalBytes, totalPackets uint64
	var currentFlows int
	var exportedCount int

	// Collect keys to delete after iteration to avoid modifying the map
	// during iteration, which can cause missed or duplicate entries.
	var keysToDelete []flowFlowKey

	for iter.Next(&key, &stats) {
		currentFlows++

		// Rate limiting check - break early to avoid unnecessary iteration
		if exportedCount >= maxExportPerCycle {
			break
		}

		if stats.Packets == 0 {
			// No new packets since flow was created by eBPF — should not
			// happen in normal operation, but clean up defensively.
			keysToDelete = append(keysToDelete, key)
			continue
		}

		inactive := now > stats.LastSeen && (now-stats.LastSeen) > inactivityTimeout
		tcpFinished := (stats.TcpFlags&0x01) != 0 || (stats.TcpFlags&0x04) != 0 // FIN or RST

		// Export and delete all flows with packets. New packets from the
		// same 5-tuple will create a fresh entry in the eBPF map with
		// accurate timestamps (like NetFlow active timeout).
		printFlow(key, stats, jsonOutput)
		keysToDelete = append(keysToDelete, key)
		exportedCount++
		totalBytes += stats.Bytes
		totalPackets += stats.Packets

		if tcpFinished {
			closedCount++
			exportedTotal.WithLabelValues("closed").Inc()
		} else if inactive {
			inactiveCount++
			exportedTotal.WithLabelValues("inactive").Inc()
		} else {
			activeCount++
			exportedTotal.WithLabelValues("active").Inc()
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("Error iterating flows: %v", err)
	}

	// Apply deferred deletes after iteration completes
	for _, k := range keysToDelete {
		if err := flowMap.Delete(k); err != nil {
			log.Printf("Error deleting flow: %v", err)
		}
	}

	// If rate limited, continue iterating to count remaining flows for accurate gauge.
	// cilium/ebpf Iterate() supports resuming after break.
	if exportedCount >= maxExportPerCycle {
		for iter.Next(&key, &stats) {
			currentFlows++
		}
		if err := iter.Err(); err != nil {
			log.Printf("Error iterating remaining flows: %v", err)
		}
		log.Printf("Warning: Export rate limited at %d flows, %d total flows in map", maxExportPerCycle, currentFlows)
	}

	// Update Prometheus metrics with accurate flow count
	mapFlows.Set(float64(currentFlows))
	exportedBytes.Add(float64(totalBytes))
	exportedPackets.Add(float64(totalPackets))

	// Read and update drop counters (compute delta from previous cycle)
	cumDrops := readDropCounters(dropMap)
	var drops [dropMax]uint64
	for i := 0; i < dropMax; i++ {
		if cumDrops[i] >= fe.prevDrops[i] {
			drops[i] = cumDrops[i] - fe.prevDrops[i]
		} else {
			// Counter reset detected (e.g. eBPF program reload)
			log.Printf("Warning: drop counter %s reset detected (prev=%d, cur=%d)",
				dropReasonLabels[i], fe.prevDrops[i], cumDrops[i])
			drops[i] = cumDrops[i]
		}
		if drops[i] > 0 {
			droppedTotal.WithLabelValues(dropReasonLabels[i]).Add(float64(drops[i]))
		}
	}
	fe.prevDrops = cumDrops

	// Write stats to file if enabled (single-threaded, no mutex needed)
	if statsWriter != nil {
		var statsLine string
		if jsonOutput {
			record := map[string]interface{}{
				"timestamp":      time.Now().Unix(),
				"active":         activeCount,
				"inactive":       inactiveCount,
				"closed":         closedCount,
				"total_flows":    currentFlows,
				"total_bytes":    totalBytes,
				"total_packets":  totalPackets,
				"drop_fragments": drops[dropFragments],
				"drop_non_ipv4":  drops[dropNonIPv4],
				"drop_parse_err": drops[dropParseErr],
			}
			data, err := json.Marshal(record)
			if err != nil {
				log.Printf("Stats JSON marshal error: %v", err)
			} else {
				statsLine = string(data) + "\n"
			}
		} else {
			statsLine = fmt.Sprintf("[%s] Exported: %d active, %d inactive, %d closed | Total flows: %d | Bytes: %d | Packets: %d | Drops: fragments=%d non_ipv4=%d parse_err=%d\n",
				time.Now().Format("2006-01-02 15:04:05"),
				activeCount, inactiveCount, closedCount, currentFlows, totalBytes, totalPackets,
				drops[dropFragments], drops[dropNonIPv4], drops[dropParseErr])
		}
		if statsLine != "" {
			_, _ = statsWriter.WriteString(statsLine)
			_ = statsWriter.Sync()
		}
	}
}

// printFlow formats and prints a single flow record to stdout. Output is
// either a JSON object or a human-readable one-liner depending on jsonOutput.
func printFlow(key flowFlowKey, stats flowFlowStats, jsonOutput bool) {
	srcIP := net.IP(binary.LittleEndian.AppendUint32(nil, key.SrcIp))
	dstIP := net.IP(binary.LittleEndian.AppendUint32(nil, key.DstIp))
	var duration time.Duration
	if stats.LastSeen >= stats.FirstSeen {
		duration = time.Duration(stats.LastSeen - stats.FirstSeen)
	}

	if jsonOutput {
		var durationNs uint64
		if stats.LastSeen >= stats.FirstSeen {
			durationNs = stats.LastSeen - stats.FirstSeen
		}
		record := map[string]interface{}{
			"timestamp":    time.Now().Unix(),
			"src_ip":       srcIP.String(),
			"src_port":     key.SrcPort,
			"dst_ip":       dstIP.String(),
			"dst_port":     key.DstPort,
			"protocol":     key.Protocol,
			"packets":      stats.Packets,
			"bytes":        stats.Bytes,
			"duration_ns":  durationNs,
			"duration_sec": duration.Seconds(),
			"tcp_flags":    fmt.Sprintf("0x%02x", stats.TcpFlags),
		}
		data, err := json.Marshal(record)
		if err != nil {
			log.Printf("JSON marshal error: %v", err)
			return
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("%s:%d -> %s:%d proto=%d packets=%d bytes=%d duration=%v flags=0x%02x\n",
			srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol,
			stats.Packets, stats.Bytes, duration, stats.TcpFlags)
	}
}

// mustFindInterface looks up a network interface by name and returns its index.
// Calls log.Fatalf if the interface does not exist. Logs a warning if the
// interface is currently DOWN.
func mustFindInterface(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		log.Printf("Warning: interface %s is currently DOWN, no packets will be captured until it comes UP", name)
	}
	return iface.Index
}
