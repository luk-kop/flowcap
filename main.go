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
	"sort"
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -type flow_key -type flow_stats -cflags "-mcpu=v3 -I/usr/include/$(uname -m)-linux-gnu" flow flowcap.c

var (
	// Prometheus metrics
	exportScanFlows = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_export_scan_flows",
		Help: "Number of flows observed during the last export scan",
	})
	exportScanComplete = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_export_scan_complete",
		Help: "Whether the last flow-map scan completed without an iterator error",
	})
	exportIteratorDuplicates = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "flowcap_export_iterator_duplicates_total",
		Help: "Total repeated flow-instance snapshots observed within one map scan",
	})
	exportLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "flowcap_export_last_success_timestamp_seconds",
		Help: "Unix time of the last successful flow export cycle",
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
	exportErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flowcap_export_errors_total",
		Help: "Total flow export errors by stage",
	}, []string{"stage"}) // stage: scan, state, encode, write
	statsErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "flowcap_stats_errors_total",
		Help: "Total statistics file errors by operation",
	}, []string{"operation"}) // operation: write, sync
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
		Help: "Configured maximum retained flow instances",
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
	prometheus.MustRegister(exportScanComplete)
	prometheus.MustRegister(exportIteratorDuplicates)
	prometheus.MustRegister(exportLastSuccess)
	prometheus.MustRegister(exportedFlowsTotal)
	prometheus.MustRegister(exportedBytes)
	prometheus.MustRegister(exportedPackets)
	prometheus.MustRegister(exportErrorsTotal)
	prometheus.MustRegister(statsErrorsTotal)
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

const (
	flowDirectionIngress uint8 = 0
	flowDirectionEgress  uint8 = 1
)

var dropReasonLabels = [dropMax]string{"fragments", "non_ipv4", "parse_error", "linearize", "map_full"}

var exportReasonLabels = [...]string{"active", "inactive", "closed"}

var exportErrorStageLabels = [...]string{"scan", "state", "encode", "write"}

var statsErrorOperationLabels = [...]string{"write", "sync"}

func initMetricLabels() {
	for _, reason := range exportReasonLabels {
		exportedFlowsTotal.WithLabelValues(reason).Add(0)
	}
	for _, stage := range exportErrorStageLabels {
		exportErrorsTotal.WithLabelValues(stage).Add(0)
	}
	for _, operation := range statsErrorOperationLabels {
		statsErrorsTotal.WithLabelValues(operation).Add(0)
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
	// Let EPIPE follow the same cleanup path as other output failures.
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func writef(w io.Writer, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeln(w io.Writer, args ...interface{}) {
	_, _ = fmt.Fprintln(w, args...)
}

type timeoutWriter struct {
	writer  io.Writer
	timeout time.Duration
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

func (w timeoutWriter) Write(p []byte) (int, error) {
	setter, supportsDeadline := w.writer.(writeDeadlineSetter)
	if !supportsDeadline || w.timeout <= 0 {
		return w.writer.Write(p)
	}
	if err := setter.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		if errors.Is(err, os.ErrNoDeadline) {
			return w.writer.Write(p)
		}
		return 0, fmt.Errorf("set output deadline: %w", err)
	}
	defer func() {
		_ = setter.SetWriteDeadline(time.Time{})
	}()
	return w.writer.Write(p)
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("flowcap", flag.ContinueOnError)
	fs.SetOutput(stderr)

	interval := fs.Int("interval", 10, "flow export interval in seconds")
	timeout := fs.Int("timeout", 60, "flow inactivity timeout in seconds")
	maxFlows := fs.Int("max-flows", 16384, "maximum flow instances retained until shutdown")
	maxExportPerCycle := fs.Int("max-export-per-cycle", 10000, "maximum flows to export per cycle")
	outputTimeout := fs.Duration("output-timeout", 30*time.Second, "maximum duration of one flow output write when supported by the destination")
	shutdownTimeout := fs.Duration("shutdown-timeout", 30*time.Second, "maximum duration of the shutdown procedure")
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
	if *outputTimeout <= 0 {
		writef(stderr, "output-timeout must be greater than 0, got %s\n", *outputTimeout)
		return 1
	}
	if *shutdownTimeout <= 0 {
		writef(stderr, "shutdown-timeout must be greater than 0, got %s\n", *shutdownTimeout)
		return 1
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

	resources := &captureResources{}
	handedOff := false
	defer func() {
		if !handedOff {
			if err := resources.Close(); err != nil {
				log.Printf("Startup cleanup failed: %v", err)
			}
		}
	}()
	// Open stats file if specified
	var statsWriter *os.File
	if *statsFile != "" {
		var err error
		statsWriter, err = os.OpenFile(*statsFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			writef(stderr, "Failed to open stats file: %v\n", err)
			return 1
		}
		resources.stats = statsWriter
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
	resources.objects = objs

	// Attach to ingress (incoming packets)
	linkIngress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex,
		Program:   objs.FlowCaptureIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		writef(stderr, "Failed to attach TC ingress: %v\n", err)
		return 1
	}
	resources.ingress = &captureHook{link: linkIngress}

	// Attach to egress (outgoing packets)
	linkEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex,
		Program:   objs.FlowCaptureEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		writef(stderr, "Failed to attach TC egress: %v\n", err)
		return 1
	}
	resources.egress = &captureHook{link: linkEgress}

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
	flowOutput := timeoutWriter{writer: stdout, timeout: *outputTimeout}
	export := func(maxRecords int) error {
		if maxRecords == 0 {
			return exporter.drainFlows(objs.Flows, objs.DropCounters, *timeout, *jsonOutput, flowOutput, statsWriter)
		}
		return exporter.exportFlows(objs.Flows, objs.DropCounters, *timeout, *jsonOutput, maxRecords, flowOutput, statsWriter)
	}
	cleanup := func(shutdownCtx context.Context) error {
		var serverErr error
		if metricsServer != nil {
			serverErr = metricsServer.Shutdown(shutdownCtx)
		}
		return errors.Join(serverErr, resources.Close())
	}
	// Lifecycle owns resources even after a timeout. It closes them only after
	// the worker has stopped. main exits on timeout; no map is closed under an
	// outstanding lookup/write by a deferred cleanup in this goroutine.
	handedOff = true
	if err := runCapture(ctx, ticker.C, metricsErrChan, *maxExportPerCycle, *shutdownTimeout, export, resources.Stop, cleanup); err != nil {
		var drainErr *incompleteDrainError
		if errors.As(err, &drainErr) && drainErr.known {
			log.Printf("Capture stopped with incomplete export/cleanup; %d records remain: %v", drainErr.remaining, err)
		} else {
			log.Printf("Capture stopped with incomplete export/cleanup; remaining records unknown: %v", err)
		}
		return 1
	}
	return 0
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

// exportFlows iterates over the eBPF flows map and exports counter deltas since
// the last confirmed write. Flows are classified as active, inactive (exceeded
// inactivityTimeout), or closed (TCP FIN/RST seen).
// At most maxExportPerCycle flows are exported per call to bound latency.
// If statsWriter is non-nil, a summary line is appended to that file.

// flowExporter holds state across export cycles. The single export worker owns
// it; no synchronization is provided for concurrent callers.
type flowExporter struct {
	prevDrops [dropMax]uint64
	confirmed map[flowInstance]flowConfirmation
	cursor    flowInstance
	hasCursor bool
}

type flowInstance struct {
	key        flowFlowKey
	generation uint64
}

type flowConfirmation struct {
	packets    uint64
	bytes      uint64
	observedAt uint64
}

type flowRecord struct {
	key        flowFlowKey
	stats      flowFlowStats
	observedAt uint64
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
}

type exportJob struct {
	maxRecords int
	result     chan<- error
}

func startExportWorker(jobs <-chan exportJob, export func(maxRecords int) error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for job := range jobs {
			job.result <- export(job.maxRecords)
		}
	}()
	return done
}

func exportFailurePreventsRetry(err error) bool {
	var stageErr *exportStageError
	return errors.As(err, &stageErr) && (stageErr.stage == "encode" || stageErr.stage == "write")
}

type exportStageError struct {
	stage string
	err   error
}

func (e *exportStageError) Error() string {
	return fmt.Sprintf("%s: %v", e.stage, e.err)
}

func (e *exportStageError) Unwrap() error {
	return e.err
}

func newExportStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &exportStageError{stage: stage, err: err}
}

func recordExportError(err error) {
	var stageErr *exportStageError
	if errors.As(err, &stageErr) {
		exportErrorsTotal.WithLabelValues(stageErr.stage).Inc()
	}
}

func (fe *flowExporter) exportFlows(flowMap *ebpf.Map, dropMap *ebpf.Map, timeoutSec int, jsonOutput bool, maxExportPerCycle int, output io.Writer, statsWriter *os.File) error {
	records, err := scanFlowMap(flowMap)
	if err != nil {
		exportScanComplete.Set(0)
		err = newExportStageError("scan", err)
		recordExportError(err)
		return err
	}
	exportScanComplete.Set(1)
	if err := fe.pruneConfirmations(flowMap, records); err != nil {
		err = newExportStageError("state", err)
		recordExportError(err)
		return err
	}
	uniqueFlows := fe.uniqueFlowCount(records)
	if duplicates := len(records) - uniqueFlows; duplicates > 0 {
		exportIteratorDuplicates.Add(float64(duplicates))
	}

	var statsOutput io.Writer
	if statsWriter != nil {
		statsOutput = statsWriter
	}
	summary, exportErr := fe.exportRecords(records, readDropCounters(dropMap), ktimeNow(), timeoutSec, jsonOutput, maxExportPerCycle, output, statsOutput)

	if summary.rateLimited {
		log.Printf("Warning: Export rate limited at %d flows, %d total flows in map", maxExportPerCycle, summary.currentFlows)
	}

	if statsWriter != nil {
		if err := statsWriter.Sync(); err != nil {
			statsErrorsTotal.WithLabelValues("sync").Inc()
			log.Printf("Failed to sync stats file: %v", err)
		}
	}

	if exportErr != nil {
		recordExportError(exportErr)
		return exportErr
	}
	exportLastSuccess.SetToCurrentTime()
	return nil
}

func (fe *flowExporter) exportRecords(records []flowRecord, cumDrops [dropMax]uint64, now uint64, timeoutSec int, jsonOutput bool, maxExportPerCycle int, output io.Writer, statsWriter io.Writer) (exportSummary, error) {
	inactivityTimeout := uint64(timeoutSec) * uint64(time.Second)
	exportWallTime := time.Now().UTC()
	fe.ensureState()
	records = fe.orderRecords(records)
	summary := exportSummary{currentFlows: fe.uniqueFlowCount(records)}

	for _, record := range records {
		if record.stats.Packets == 0 {
			continue
		}

		instance := flowInstance{key: record.key, generation: flowGeneration(record.stats)}
		observedAt := record.observedAt
		if observedAt == 0 {
			observedAt = now
		}
		delta, windowStart, hasDelta, err := fe.deltaFor(instance, record.stats, observedAt)
		if err != nil {
			return summary, newExportStageError("state", err)
		}
		if !hasDelta {
			continue
		}
		if maxExportPerCycle > 0 && summary.exportedCount >= maxExportPerCycle {
			summary.rateLimited = true
			continue
		}

		inactive := now > record.stats.LastSeen && (now-record.stats.LastSeen) > inactivityTimeout
		tcpFinished := (record.stats.TcpFlags&0x01) != 0 || (record.stats.TcpFlags&0x04) != 0 // FIN or RST

		if err := printFlowAt(output, record.key, delta, jsonOutput, windowStart, observedAt, now, exportWallTime); err != nil {
			return summary, err
		}
		fe.confirmed[instance] = flowConfirmation{packets: record.stats.Packets, bytes: record.stats.Bytes, observedAt: observedAt}
		fe.cursor, fe.hasCursor = instance, true
		summary.exportedCount++
		summary.totalBytes += delta.Bytes
		summary.totalPackets += delta.Packets

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
		exportedBytes.Add(float64(delta.Bytes))
		exportedPackets.Add(float64(delta.Packets))
	}

	// Update Prometheus metrics with the number of flows observed in this scan.
	exportScanFlows.Set(float64(summary.currentFlows))

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
				statsErrorsTotal.WithLabelValues("write").Inc()
				log.Printf("Failed to write stats: %v", err)
			}
		}
	}

	return summary, nil
}

func flowGeneration(stats flowFlowStats) uint64 {
	return stats.Generation
}

func (fe *flowExporter) ensureState() {
	if fe.confirmed == nil {
		fe.confirmed = make(map[flowInstance]flowConfirmation)
	}
}

// A missed scan is never proof that an instance disappeared. A direct lookup
// is required before discarding its acknowledgement. Production HASH entries
// currently live until shutdown, so confirmations are bounded by map capacity.
func (fe *flowExporter) pruneConfirmations(flowMap flowMapReader, records []flowRecord) error {
	observed := make(map[flowInstance]bool, len(records))
	for _, record := range records {
		instance := flowInstance{key: record.key, generation: flowGeneration(record.stats)}
		observed[instance] = true
	}
	for instance := range fe.confirmed {
		if observed[instance] {
			continue
		}
		var current flowFlowStats
		err := flowMap.LookupWithFlags(&instance.key, &current, ebpf.LookupLock)
		if errors.Is(err, ebpf.ErrKeyNotExist) || (err == nil && flowGeneration(current) != instance.generation) {
			delete(fe.confirmed, instance)
		} else if err != nil {
			return fmt.Errorf("check retained confirmation: %w", err)
		}
	}
	return nil
}

func instanceLess(a, b flowInstance) bool {
	if a.generation != b.generation {
		return a.generation < b.generation
	}
	if a.key.SrcIp != b.key.SrcIp {
		return a.key.SrcIp < b.key.SrcIp
	}
	if a.key.DstIp != b.key.DstIp {
		return a.key.DstIp < b.key.DstIp
	}
	if a.key.SrcPort != b.key.SrcPort {
		return a.key.SrcPort < b.key.SrcPort
	}
	if a.key.DstPort != b.key.DstPort {
		return a.key.DstPort < b.key.DstPort
	}
	if a.key.Protocol != b.key.Protocol {
		return a.key.Protocol < b.key.Protocol
	}
	return a.key.FlowDirection < b.key.FlowDirection
}

// Rotate a stable ordering after the last confirmed instance. Busy flows at
// the start of a hash walk cannot consume every cycle's budget forever.
func (fe *flowExporter) orderRecords(input []flowRecord) []flowRecord {
	records := append([]flowRecord(nil), input...)
	identity := func(r flowRecord) flowInstance { return flowInstance{r.key, flowGeneration(r.stats)} }
	sort.SliceStable(records, func(i, j int) bool { return instanceLess(identity(records[i]), identity(records[j])) })
	if !fe.hasCursor {
		return records
	}
	start := sort.Search(len(records), func(i int) bool { return instanceLess(fe.cursor, identity(records[i])) })
	return append(records[start:len(records):len(records)], records[:start]...)
}

func (fe *flowExporter) uniqueFlowCount(records []flowRecord) int {
	unique := make(map[flowInstance]struct{}, len(records))
	for _, record := range records {
		unique[flowInstance{key: record.key, generation: flowGeneration(record.stats)}] = struct{}{}
	}
	return len(unique)
}

func (fe *flowExporter) deltaFor(instance flowInstance, current flowFlowStats, observedAt uint64) (flowFlowStats, uint64, bool, error) {
	previous, ok := fe.confirmed[instance]
	if !ok {
		windowStart := current.FirstSeen
		if windowStart == 0 || windowStart > observedAt {
			windowStart = observedAt
		}
		return current, windowStart, current.Packets != 0 || current.Bytes != 0, nil
	}
	if current.Packets < previous.packets || current.Bytes < previous.bytes {
		return flowFlowStats{}, 0, false, fmt.Errorf(
			"flow counters decreased without a generation change (generation=%d packets=%d->%d bytes=%d->%d)",
			instance.generation, previous.packets, current.Packets, previous.bytes, current.Bytes,
		)
	}
	delta := current
	delta.Packets -= previous.packets
	delta.Bytes -= previous.bytes
	return delta, previous.observedAt, delta.Packets != 0 || delta.Bytes != 0, nil
}

// printFlow formats and prints a single flow record to stdout. Output is
// either a JSON object or a human-readable one-liner depending on jsonOutput.
func printFlow(key flowFlowKey, stats flowFlowStats, jsonOutput bool) error {
	return printFlowTo(os.Stdout, key, stats, jsonOutput)
}

func printFlowTo(output io.Writer, key flowFlowKey, stats flowFlowStats, jsonOutput bool) error {
	now := ktimeNow()
	return printFlowAt(output, key, stats, jsonOutput, stats.FirstSeen, now, now, time.Now().UTC())
}

type jsonFlowRecord struct {
	Generation    uint64  `json:"generation"`
	WindowStart   string  `json:"window_start"`
	WindowEnd     string  `json:"window_end"`
	FirstSeen     string  `json:"first_seen"`
	LastSeen      string  `json:"last_seen"`
	ExportTime    string  `json:"export_time"`
	SrcIP         string  `json:"src_ip"`
	SrcPort       uint16  `json:"src_port"`
	DstIP         string  `json:"dst_ip"`
	DstPort       uint16  `json:"dst_port"`
	Protocol      uint8   `json:"protocol"`
	FlowDirection string  `json:"flow_direction"`
	Packets       uint64  `json:"packets"`
	Bytes         uint64  `json:"bytes"`
	DurationNS    uint64  `json:"duration_ns"`
	DurationSec   float64 `json:"duration_sec"`
	TCPFlags      string  `json:"tcp_flags"`
}

func flowDirectionName(direction uint8) string {
	switch direction {
	case flowDirectionIngress:
		return "ingress"
	case flowDirectionEgress:
		return "egress"
	default:
		return "unknown"
	}
}

func printFlowAt(output io.Writer, key flowFlowKey, stats flowFlowStats, jsonOutput bool, windowStart, windowEnd, referenceMono uint64, referenceWall time.Time) error {
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
		record := jsonFlowRecord{
			Generation:    stats.Generation,
			WindowStart:   monotonicWallTime(windowStart, referenceMono, referenceWall).Format(time.RFC3339Nano),
			WindowEnd:     monotonicWallTime(windowEnd, referenceMono, referenceWall).Format(time.RFC3339Nano),
			FirstSeen:     monotonicWallTime(stats.FirstSeen, referenceMono, referenceWall).Format(time.RFC3339Nano),
			LastSeen:      monotonicWallTime(stats.LastSeen, referenceMono, referenceWall).Format(time.RFC3339Nano),
			ExportTime:    referenceWall.Format(time.RFC3339Nano),
			SrcIP:         srcIP.String(),
			SrcPort:       key.SrcPort,
			DstIP:         dstIP.String(),
			DstPort:       key.DstPort,
			Protocol:      key.Protocol,
			FlowDirection: flowDirectionName(key.FlowDirection),
			Packets:       stats.Packets,
			Bytes:         stats.Bytes,
			DurationNS:    durationNs,
			DurationSec:   duration.Seconds(),
			TCPFlags:      fmt.Sprintf("0x%02x", stats.TcpFlags),
		}
		data, err := json.Marshal(record)
		if err != nil {
			return newExportStageError("encode", err)
		}
		if _, err := fmt.Fprintln(output, string(data)); err != nil {
			return newExportStageError("write", err)
		}
	} else {
		if _, err := fmt.Fprintf(output, "%s:%d -> %s:%d proto=%d direction=%s generation=%d packets=%d bytes=%d duration=%v first_seen=%s last_seen=%s window_start=%s window_end=%s export_time=%s flags=0x%02x\n",
			srcIP, key.SrcPort, dstIP, key.DstPort, key.Protocol,
			flowDirectionName(key.FlowDirection), stats.Generation, stats.Packets, stats.Bytes, duration,
			monotonicWallTime(stats.FirstSeen, referenceMono, referenceWall).Format(time.RFC3339Nano),
			monotonicWallTime(stats.LastSeen, referenceMono, referenceWall).Format(time.RFC3339Nano),
			monotonicWallTime(windowStart, referenceMono, referenceWall).Format(time.RFC3339Nano),
			monotonicWallTime(windowEnd, referenceMono, referenceWall).Format(time.RFC3339Nano),
			referenceWall.Format(time.RFC3339Nano), stats.TcpFlags); err != nil {
			return newExportStageError("write", err)
		}
	}
	return nil
}

func monotonicWallTime(value, referenceMono uint64, referenceWall time.Time) time.Time {
	if value >= referenceMono {
		return referenceWall.Add(time.Duration(value - referenceMono))
	}
	return referenceWall.Add(-time.Duration(referenceMono - value))
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
