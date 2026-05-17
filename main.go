package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -type flow_key -type flow_stats -cflags "-I/usr/include/$(uname -m)-linux-gnu" flow flowcap.c

var (
	// Prometheus metrics
	exportScanFlows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_export_scan_flows",
		Help: "Number of flows observed during the last export scan",
	})
	exportedFlowsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flowcap_exported_flows_total",
		Help: "Total exported flows by reason (active: periodic, inactive: idle timeout, closed: connection end)",
	}, []string{"reason"}) // reason: active, inactive, closed
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
	configInactivityTimeout = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_config_inactivity_timeout_seconds",
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
	droppedPacketsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flowcap_dropped_packets_total",
		Help: "Total packets dropped (not tracked as flows) by reason",
	}, []string{"reason"}) // reason: fragments, non_ipv4, parse_error, linearize, map_full
	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "flowcap_build_info",
		Help: "Flowcap build info (always 1)",
	}, []string{"version", "revision", "build_date"})
	captureInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "flowcap_capture_info",
		Help: "Flowcap capture target info (always 1)",
	}, []string{"interface", "l2_header_bytes"})
)

func init() {
	prometheus.MustRegister(exportScanFlows)
	prometheus.MustRegister(exportedFlowsTotal)
	prometheus.MustRegister(exportedBytes)
	prometheus.MustRegister(exportedPackets)
	prometheus.MustRegister(configInterval)
	prometheus.MustRegister(configInactivityTimeout)
	prometheus.MustRegister(configMaxFlows)
	prometheus.MustRegister(configMaxExport)
	prometheus.MustRegister(droppedPacketsTotal)
	prometheus.MustRegister(buildInfo)
	prometheus.MustRegister(captureInfo)
	initMetricLabels()
}

// Drop counter indices matching eBPF defines
const (
	dropFragments = 0
	dropNonIPv4   = 1
	dropParseErr  = 2
	dropLinearize = 3
	dropMapFull   = 4
	dropMax       = 5
)

var dropReasonLabels = [dropMax]string{"fragments", "non_ipv4", "parse_error", "linearize", "map_full"}

var exportReasonLabels = [...]string{"active", "inactive", "closed"}

func initMetricLabels() {
	for _, reason := range exportReasonLabels {
		exportedFlowsTotal.WithLabelValues(reason).Add(0)
	}
	for _, reason := range dropReasonLabels {
		droppedPacketsTotal.WithLabelValues(reason).Add(0)
	}
}

// version, revision, and buildDate are injected at build time via -ldflags.
var version = "dev"
var revision = "unknown"
var buildDate = "unknown"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func writef(w io.Writer, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeln(w io.Writer, args ...interface{}) {
	_, _ = fmt.Fprintln(w, args...)
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("flowcap", flag.ContinueOnError)
	fs.SetOutput(stderr)

	interval := fs.Int("interval", 10, "flow export interval in seconds")
	timeout := fs.Int("timeout", 60, "flow inactivity timeout in seconds")
	maxFlows := fs.Int("max-flows", 16384, "maximum number of concurrent flows")
	maxExportPerCycle := fs.Int("max-export-per-cycle", 10000, "maximum flows to export per cycle")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	metricsAddr := fs.String("metrics-addr", "", "enable Prometheus metrics HTTP server at host:port (e.g. 127.0.0.1:9090)")
	statsFile := fs.String("stats-file", "", "optional file for detailed statistics logging")
	showVersion := fs.Bool("version", false, "Print version and exit")
	fs.Usage = func() {
		writef(stderr, "Usage: %s [options] <interface>\n\nOptions:\n", fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		writef(stdout, "%s revision=%s build_date=%s\n", version, revision, buildDate)
		return 0
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return 1
	}
	if *interval <= 0 {
		writef(stderr, "interval must be greater than 0, got %d\n", *interval)
		return 1
	}
	if *interval > 3600 {
		writef(stderr, "interval too large (max: 3600s), got %d\n", *interval)
		return 1
	}
	if *timeout <= 0 {
		writef(stderr, "timeout must be greater than 0, got %d\n", *timeout)
		return 1
	}
	if *timeout > 86400 {
		writef(stderr, "timeout too large (max: 86400s), got %d\n", *timeout)
		return 1
	}
	if *maxFlows <= 0 {
		writef(stderr, "max-flows must be greater than 0, got %d\n", *maxFlows)
		return 1
	}
	if *maxFlows < 1024 {
		writef(stderr, "max-flows too small (min: 1024), got %d\n", *maxFlows)
		return 1
	}
	if *maxFlows > 262144 {
		writef(stderr, "max-flows too large (max: 262144), got %d\n", *maxFlows)
		return 1
	}
	if *maxExportPerCycle <= 0 {
		writef(stderr, "max-export-per-cycle must be greater than 0, got %d\n", *maxExportPerCycle)
		return 1
	}
	if *maxExportPerCycle > *maxFlows {
		writef(stderr, "max-export-per-cycle (%d) cannot exceed max-flows (%d)\n", *maxExportPerCycle, *maxFlows)
		return 1
	}
	if *timeout < *interval {
		log.Printf("Warning: timeout (%ds) is less than interval (%ds), flows may expire before export", *timeout, *interval)
	}
	if *metricsAddr != "" {
		host, port, err := net.SplitHostPort(*metricsAddr)
		if err != nil {
			writef(stderr, "invalid metrics-addr %q: must be host:port (e.g. 127.0.0.1:9090): %v\n", *metricsAddr, err)
			return 1
		}
		if net.ParseIP(host) == nil {
			writef(stderr, "invalid metrics-addr %q: %q is not a valid IP address\n", *metricsAddr, host)
			return 1
		}
		if port == "" {
			writef(stderr, "invalid metrics-addr %q: port is required\n", *metricsAddr)
			return 1
		}
	}
	// Set config metrics
	configInterval.Set(float64(*interval))
	configInactivityTimeout.Set(float64(*timeout))
	configMaxFlows.Set(float64(*maxFlows))
	configMaxExport.Set(float64(*maxExportPerCycle))
	buildInfo.WithLabelValues(version, revision, buildDate).Set(1)

	iface := fs.Arg(0)
	log.Print(startupLogLine(iface, *interval, *timeout, *maxFlows, *maxExportPerCycle, *jsonOutput, *metricsAddr, *statsFile))

	ifaceObj, err := findInterface(iface)
	if err != nil {
		writeln(stderr, err)
		return 1
	}
	ifaceIndex := ifaceObj.Index

	// Open stats file if specified
	var statsWriter *os.File
	if *statsFile != "" {
		var err error
		statsWriter, err = os.OpenFile(*statsFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			writef(stderr, "Failed to open stats file: %v\n", err)
			return 1
		}
		defer func() {
			if err := statsWriter.Close(); err != nil {
				log.Printf("Failed to close stats file: %v", err)
			}
		}()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		writef(stderr, "Failed to remove memlock: %v\n", err)
		return 1
	}

	spec, err := loadFlow()
	if err != nil {
		writef(stderr, "Failed to load eBPF spec: %v\n", err)
		return 1
	}

	// Override max_entries for flows map
	spec.Maps["flows"].MaxEntries = uint32(*maxFlows)

	l2HdrLen := l2HeaderLenForInterface(ifaceObj)
	if l2HdrLen == 0 {
		log.Printf("Detected L3 interface %s, skipping L2 header parse", iface)
	}
	if err := spec.Variables["l2_hdr_len"].Set(l2HdrLen); err != nil {
		writef(stderr, "Failed to set eBPF constant l2_hdr_len: %v\n", err)
		return 1
	}
	captureInfo.WithLabelValues(iface, fmt.Sprint(l2HdrLen)).Set(1)

	objs := &flowObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		writef(stderr, "Failed to load eBPF objects: %v\n", err)
		return 1
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
		writef(stderr, "Failed to attach TC ingress: %v\n", err)
		return 1
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
		writef(stderr, "Failed to attach TC egress: %v\n", err)
		return 1
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
			exporter.exportFlows(objs.Flows, objs.DropCounters, *timeout, *jsonOutput, *maxExportPerCycle, stdout, statsWriter)
			if metricsServer != nil {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := metricsServer.Shutdown(shutdownCtx); err != nil {
					log.Printf("Metrics server shutdown error: %v", err)
				}
				shutdownCancel()
			}
			return 0
		case err := <-metricsErrChan:
			log.Printf("Metrics server failed: %v", err)
			return 1
		case <-ticker.C:
			exporter.exportFlows(objs.Flows, objs.DropCounters, *timeout, *jsonOutput, *maxExportPerCycle, stdout, statsWriter)
		}
	}
}

func startupLogLine(iface string, interval, timeout, maxFlows, maxExportPerCycle int, jsonOutput bool, metricsAddr, statsFile string) string {
	return fmt.Sprintf("starting flowcap version=%s revision=%s build_date=%s interface=%s interval=%ds timeout=%ds max_flows=%d max_export_per_cycle=%d json=%t metrics_addr=%q stats_file=%q",
		version, revision, buildDate, iface, interval, timeout, maxFlows, maxExportPerCycle, jsonOutput, metricsAddr, statsFile)
}

const (
	arphrdEther    = 1
	arphrdLoopback = 772
	arphrdNone     = 65534
	ethHeaderLen   = 14
)

func l2HeaderLenForInterface(iface *net.Interface) uint32 {
	linkType, err := readInterfaceLinkType(iface.Name)
	if err == nil {
		return l2HeaderLenForLinkType(linkType, iface.HardwareAddr)
	}
	log.Printf("Warning: failed to read interface type for %s: %v", iface.Name, err)
	return l2HeaderLenForLinkType(-1, iface.HardwareAddr)
}

func readInterfaceLinkType(name string) (int, error) {
	data, err := os.ReadFile("/sys/class/net/" + name + "/type")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func l2HeaderLenForLinkType(linkType int, hardwareAddr net.HardwareAddr) uint32 {
	switch linkType {
	case arphrdNone:
		return 0
	case arphrdEther, arphrdLoopback:
		return ethHeaderLen
	default:
		if len(hardwareAddr) == 0 {
			return 0
		}
		return ethHeaderLen
	}
}

// ktimeNow returns the current monotonic clock time in nanoseconds using
// CLOCK_MONOTONIC, matching the bpf_ktime_get_ns() helper used in the eBPF
// program. Fatally exits if the syscall fails — wrong timestamps from a wall
// clock fallback would silently corrupt flow duration and timeout calculations.
func ktimeNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("ClockGettime(CLOCK_MONOTONIC) failed: %v", err)
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

type flowRecord struct {
	key   flowFlowKey
	stats flowFlowStats
}

type exportSummary struct {
	activeCount   int
	inactiveCount int
	closedCount   int
	currentFlows  int
	exportedCount int
	totalBytes    uint64
	totalPackets  uint64
	drops         [dropMax]uint64
	rateLimited   bool
	keysToDelete  []flowFlowKey
}

func (fe *flowExporter) exportFlows(flowMap *ebpf.Map, dropMap *ebpf.Map, timeoutSec int, jsonOutput bool, maxExportPerCycle int, output io.Writer, statsWriter *os.File) {
	var key flowFlowKey
	var stats flowFlowStats
	iter := flowMap.Iterate()

	var records []flowRecord
	for iter.Next(&key, &stats) {
		records = append(records, flowRecord{key: key, stats: stats})
	}

	if err := iter.Err(); err != nil {
		log.Printf("Error iterating flows: %v", err)
	}

	var statsOutput io.Writer
	if statsWriter != nil {
		statsOutput = statsWriter
	}
	summary := fe.exportRecords(records, readDropCounters(dropMap), ktimeNow(), timeoutSec, jsonOutput, maxExportPerCycle, output, statsOutput)

	// Apply deferred deletes after iteration completes
	for _, k := range summary.keysToDelete {
		if err := flowMap.Delete(k); err != nil {
			log.Printf("Error deleting flow: %v", err)
		}
	}

	if summary.rateLimited {
		log.Printf("Warning: Export rate limited at %d flows, %d total flows in map", maxExportPerCycle, summary.currentFlows)
	}

	if statsWriter != nil {
		if err := statsWriter.Sync(); err != nil {
			log.Printf("Failed to sync stats file: %v", err)
		}
	}
}

func (fe *flowExporter) exportRecords(records []flowRecord, cumDrops [dropMax]uint64, now uint64, timeoutSec int, jsonOutput bool, maxExportPerCycle int, output io.Writer, statsWriter io.Writer) exportSummary {
	inactivityTimeout := uint64(timeoutSec) * uint64(time.Second)
	summary := exportSummary{currentFlows: len(records)}

	for _, record := range records {
		if summary.exportedCount >= maxExportPerCycle {
			summary.rateLimited = true
			continue
		}

		if record.stats.Packets == 0 {
			// No new packets since flow was created by eBPF — should not
			// happen in normal operation, but clean up defensively.
			summary.keysToDelete = append(summary.keysToDelete, record.key)
			continue
		}

		inactive := now > record.stats.LastSeen && (now-record.stats.LastSeen) > inactivityTimeout
		tcpFinished := (record.stats.TcpFlags&0x01) != 0 || (record.stats.TcpFlags&0x04) != 0 // FIN or RST

		// Export and delete all scanned flows with packets. New packets from the
		// same 5-tuple will create a fresh entry in the eBPF map with
		// accurate timestamps (like NetFlow active timeout).
		printFlowTo(output, record.key, record.stats, jsonOutput)
		summary.keysToDelete = append(summary.keysToDelete, record.key)
		summary.exportedCount++
		summary.totalBytes += record.stats.Bytes
		summary.totalPackets += record.stats.Packets

		if tcpFinished {
			summary.closedCount++
			exportedFlowsTotal.WithLabelValues("closed").Inc()
		} else if inactive {
			summary.inactiveCount++
			exportedFlowsTotal.WithLabelValues("inactive").Inc()
		} else {
			summary.activeCount++
			exportedFlowsTotal.WithLabelValues("active").Inc()
		}
	}

	// Update Prometheus metrics with the number of flows observed in this scan.
	exportScanFlows.Set(float64(summary.currentFlows))
	exportedBytes.Add(float64(summary.totalBytes))
	exportedPackets.Add(float64(summary.totalPackets))

	// Read and update drop counters (compute delta from previous cycle)
	for i := 0; i < dropMax; i++ {
		if cumDrops[i] >= fe.prevDrops[i] {
			summary.drops[i] = cumDrops[i] - fe.prevDrops[i]
		} else {
			// Counter reset detected (e.g. eBPF program reload)
			log.Printf("Warning: drop counter %s reset detected (prev=%d, cur=%d)",
				dropReasonLabels[i], fe.prevDrops[i], cumDrops[i])
			summary.drops[i] = cumDrops[i]
		}
		if summary.drops[i] > 0 {
			droppedPacketsTotal.WithLabelValues(dropReasonLabels[i]).Add(float64(summary.drops[i]))
		}
	}
	fe.prevDrops = cumDrops

	// Write stats to file if enabled (single-threaded, no mutex needed)
	if statsWriter != nil {
		var statsLine string
		if jsonOutput {
			record := map[string]interface{}{
				"timestamp":      time.Now().Unix(),
				"active":         summary.activeCount,
				"inactive":       summary.inactiveCount,
				"closed":         summary.closedCount,
				"total_flows":    summary.currentFlows,
				"total_bytes":    summary.totalBytes,
				"total_packets":  summary.totalPackets,
				"drop_fragments": summary.drops[dropFragments],
				"drop_non_ipv4":  summary.drops[dropNonIPv4],
				"drop_parse_err": summary.drops[dropParseErr],
				"drop_linearize": summary.drops[dropLinearize],
				"drop_map_full":  summary.drops[dropMapFull],
			}
			data, err := json.Marshal(record)
			if err != nil {
				log.Printf("Stats JSON marshal error: %v", err)
			} else {
				statsLine = string(data) + "\n"
			}
		} else {
			statsLine = fmt.Sprintf("[%s] Exported: %d active, %d inactive, %d closed | Total flows: %d | Bytes: %d | Packets: %d | Drops: fragments=%d non_ipv4=%d parse_err=%d linearize=%d map_full=%d\n",
				time.Now().Format("2006-01-02 15:04:05"),
				summary.activeCount, summary.inactiveCount, summary.closedCount, summary.currentFlows, summary.totalBytes, summary.totalPackets,
				summary.drops[dropFragments], summary.drops[dropNonIPv4], summary.drops[dropParseErr], summary.drops[dropLinearize], summary.drops[dropMapFull])
		}
		if statsLine != "" {
			if _, err := io.WriteString(statsWriter, statsLine); err != nil {
				log.Printf("Failed to write stats: %v", err)
			}
		}
	}

	return summary
}

// printFlow formats and prints a single flow record to stdout. Output is
// either a JSON object or a human-readable one-liner depending on jsonOutput.
func printFlow(key flowFlowKey, stats flowFlowStats, jsonOutput bool) {
	printFlowTo(os.Stdout, key, stats, jsonOutput)
}

func printFlowTo(output io.Writer, key flowFlowKey, stats flowFlowStats, jsonOutput bool) {
	srcIP := net.IP(binary.NativeEndian.AppendUint32(nil, key.SrcIp))
	dstIP := net.IP(binary.NativeEndian.AppendUint32(nil, key.DstIp))
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
		writeln(output, string(data))
	} else {
		writef(output, "%s:%d -> %s:%d proto=%d packets=%d bytes=%d duration=%v flags=0x%02x\n",
			srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol,
			stats.Packets, stats.Bytes, duration, stats.TcpFlags)
	}
}

// findInterface looks up a network interface by name and returns it. Logs a
// warning if the interface is currently DOWN.
func findInterface(name string) (*net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		log.Printf("Warning: interface %s is currently DOWN, no packets will be captured until it comes UP", name)
	}
	return iface, nil
}
