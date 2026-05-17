package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// captureStdout runs fn and returns whatever it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	origStdout := os.Stdout
	os.Stdout = w

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("w.Close: %v", err)
	}
	os.Stdout = origStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("r.Close: %v", err)
	}
	return string(out)
}

func TestPrintFlowText_IPv4(t *testing.T) {
	key := flowFlowKey{
		SrcIp:    0x0100007f, // 127.0.0.1 in LE
		DstIp:    0x0800007f, // 127.0.0.8 in LE
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6, // TCP
	}
	stats := flowFlowStats{
		Packets:   10,
		Bytes:     1500,
		FirstSeen: 1000,
		LastSeen:  2000,
		TcpFlags:  0x02,
	}

	out := captureStdout(t, func() {
		printFlow(key, stats, false)
	})

	if !strings.Contains(out, "127.0.0.1:12345") {
		t.Errorf("expected src 127.0.0.1:12345, got: %s", out)
	}
	if !strings.Contains(out, "127.0.0.8:80") {
		t.Errorf("expected dst 127.0.0.8:80, got: %s", out)
	}
	if !strings.Contains(out, "proto=6") {
		t.Errorf("expected proto=6, got: %s", out)
	}
	if !strings.Contains(out, "packets=10") {
		t.Errorf("expected packets=10, got: %s", out)
	}
	if !strings.Contains(out, "bytes=1500") {
		t.Errorf("expected bytes=1500, got: %s", out)
	}
	if !strings.Contains(out, "flags=0x02") {
		t.Errorf("expected flags=0x02, got: %s", out)
	}
}

func TestPrintFlowJSON_IPv4(t *testing.T) {
	key := flowFlowKey{
		SrcIp:    0x0100007f,
		DstIp:    0x0800007f,
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	stats := flowFlowStats{
		Packets:   10,
		Bytes:     1500,
		FirstSeen: 1000,
		LastSeen:  2000,
		TcpFlags:  0x02,
	}

	out := captureStdout(t, func() {
		printFlow(key, stats, true)
	})

	var record map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &record); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, out)
	}

	if record["src_ip"] != "127.0.0.1" {
		t.Errorf("expected src_ip 127.0.0.1, got %v", record["src_ip"])
	}
	if record["dst_ip"] != "127.0.0.8" {
		t.Errorf("expected dst_ip 127.0.0.8, got %v", record["dst_ip"])
	}
	if record["src_port"].(float64) != 12345 {
		t.Errorf("expected src_port 12345, got %v", record["src_port"])
	}
	if record["dst_port"].(float64) != 80 {
		t.Errorf("expected dst_port 80, got %v", record["dst_port"])
	}
}

func TestPrintFlow_UDP(t *testing.T) {
	key := flowFlowKey{
		SrcIp:    0x0100007f,
		DstIp:    0x0800007f,
		SrcPort:  53,
		DstPort:  12345,
		Protocol: 17, // UDP
	}
	stats := flowFlowStats{
		Packets:   5,
		Bytes:     500,
		FirstSeen: 1000,
		LastSeen:  1500,
		TcpFlags:  0,
	}

	out := captureStdout(t, func() {
		printFlow(key, stats, false)
	})

	if !strings.Contains(out, "proto=17") {
		t.Errorf("expected proto=17 (UDP), got: %s", out)
	}
	if !strings.Contains(out, ":53") {
		t.Errorf("expected src port 53, got: %s", out)
	}
	if !strings.Contains(out, "flags=0x00") {
		t.Errorf("expected flags=0x00 for UDP, got: %s", out)
	}
}

func TestPrintFlow_TCPFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint64
		expected string
	}{
		{"SYN", 0x02, "0x02"},
		{"FIN", 0x01, "0x01"},
		{"RST", 0x04, "0x04"},
		{"SYN+ACK", 0x12, "0x12"},
		{"FIN+ACK", 0x11, "0x11"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := flowFlowKey{
				SrcIp:    0x0100007f,
				DstIp:    0x0800007f,
				SrcPort:  12345,
				DstPort:  80,
				Protocol: 6,
			}
			stats := flowFlowStats{
				Packets:   1,
				Bytes:     100,
				FirstSeen: 1000,
				LastSeen:  1000,
				TcpFlags:  tt.flags,
			}

			out := captureStdout(t, func() {
				printFlow(key, stats, false)
			})

			if !strings.Contains(out, "flags="+tt.expected) {
				t.Errorf("expected flags=%s, got: %s", tt.expected, out)
			}
		})
	}
}

func TestPrintFlow_ZeroPackets(t *testing.T) {
	key := flowFlowKey{
		SrcIp:    0x0100007f,
		DstIp:    0x0800007f,
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	stats := flowFlowStats{
		Packets:   0,
		Bytes:     0,
		FirstSeen: 1000,
		LastSeen:  1000,
		TcpFlags:  0,
	}

	out := captureStdout(t, func() {
		printFlow(key, stats, false)
	})

	if !strings.Contains(out, "packets=0") {
		t.Errorf("expected packets=0, got: %s", out)
	}
	if !strings.Contains(out, "bytes=0") {
		t.Errorf("expected bytes=0, got: %s", out)
	}
}

func TestPrintFlow_Duration(t *testing.T) {
	key := flowFlowKey{
		SrcIp:    0x0100007f,
		DstIp:    0x0800007f,
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6,
	}
	stats := flowFlowStats{
		Packets:   100,
		Bytes:     10000,
		FirstSeen: uint64(time.Second),
		LastSeen:  uint64(11 * time.Second),
		TcpFlags:  0x18,
	}

	out := captureStdout(t, func() {
		printFlow(key, stats, false)
	})

	if !strings.Contains(out, "duration=10s") {
		t.Errorf("expected duration=10s, got: %s", out)
	}
}

func TestPrintFlowJSON_AllFields(t *testing.T) {
	key := flowFlowKey{
		SrcIp:    0x0100007f,
		DstIp:    0x0800007f,
		SrcPort:  443,
		DstPort:  54321,
		Protocol: 6,
	}
	stats := flowFlowStats{
		Packets:   1000,
		Bytes:     1500000,
		FirstSeen: 1000000000,
		LastSeen:  2000000000,
		TcpFlags:  0x18,
	}

	out := captureStdout(t, func() {
		printFlow(key, stats, true)
	})

	var record map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &record); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if record["protocol"].(float64) != 6 {
		t.Errorf("expected protocol 6, got %v", record["protocol"])
	}
	if record["packets"].(float64) != 1000 {
		t.Errorf("expected packets 1000, got %v", record["packets"])
	}
	if record["bytes"].(float64) != 1500000 {
		t.Errorf("expected bytes 1500000, got %v", record["bytes"])
	}
	if record["tcp_flags"] != "0x18" {
		t.Errorf("expected tcp_flags 0x18, got %v", record["tcp_flags"])
	}
	if _, ok := record["timestamp"]; !ok {
		t.Error("expected timestamp field")
	}
	if _, ok := record["duration_ns"]; !ok {
		t.Error("expected duration_ns field")
	}
	if _, ok := record["duration_sec"]; !ok {
		t.Error("expected duration_sec field")
	}
}

func TestDropCounterDelta_Normal(t *testing.T) {
	fe := &flowExporter{}
	// Simulate first cycle: counters go from 0 to some values
	fe.prevDrops = [dropMax]uint64{0, 0, 0, 0, 0}
	cumDrops := [dropMax]uint64{10, 20, 5, 2, 1}

	var drops [dropMax]uint64
	for i := 0; i < dropMax; i++ {
		if cumDrops[i] >= fe.prevDrops[i] {
			drops[i] = cumDrops[i] - fe.prevDrops[i]
		} else {
			drops[i] = cumDrops[i]
		}
	}
	fe.prevDrops = cumDrops

	if drops[dropFragments] != 10 {
		t.Errorf("expected fragments delta=10, got %d", drops[dropFragments])
	}
	if drops[dropNonIPv4] != 20 {
		t.Errorf("expected non_ipv4 delta=20, got %d", drops[dropNonIPv4])
	}
	if drops[dropParseErr] != 5 {
		t.Errorf("expected parse_err delta=5, got %d", drops[dropParseErr])
	}
	if drops[dropLinearize] != 2 {
		t.Errorf("expected linearize delta=2, got %d", drops[dropLinearize])
	}
	if drops[dropMapFull] != 1 {
		t.Errorf("expected map_full delta=1, got %d", drops[dropMapFull])
	}

	// Simulate second cycle: counters increase
	cumDrops2 := [dropMax]uint64{15, 25, 5, 3, 1}
	var drops2 [dropMax]uint64
	for i := 0; i < dropMax; i++ {
		if cumDrops2[i] >= fe.prevDrops[i] {
			drops2[i] = cumDrops2[i] - fe.prevDrops[i]
		} else {
			drops2[i] = cumDrops2[i]
		}
	}
	fe.prevDrops = cumDrops2

	if drops2[dropFragments] != 5 {
		t.Errorf("expected fragments delta=5, got %d", drops2[dropFragments])
	}
	if drops2[dropNonIPv4] != 5 {
		t.Errorf("expected non_ipv4 delta=5, got %d", drops2[dropNonIPv4])
	}
	if drops2[dropParseErr] != 0 {
		t.Errorf("expected parse_err delta=0, got %d", drops2[dropParseErr])
	}
	if drops2[dropLinearize] != 1 {
		t.Errorf("expected linearize delta=1, got %d", drops2[dropLinearize])
	}
	if drops2[dropMapFull] != 0 {
		t.Errorf("expected map_full delta=0, got %d", drops2[dropMapFull])
	}
}

func TestDropCounterDelta_Reset(t *testing.T) {
	fe := &flowExporter{}
	// Simulate accumulated state from previous cycles
	fe.prevDrops = [dropMax]uint64{100, 200, 50, 30, 10}

	// Counter reset: current values are lower than previous (e.g. eBPF reload)
	cumDrops := [dropMax]uint64{3, 0, 1, 0, 2}

	var drops [dropMax]uint64
	for i := 0; i < dropMax; i++ {
		if cumDrops[i] >= fe.prevDrops[i] {
			drops[i] = cumDrops[i] - fe.prevDrops[i]
		} else {
			// Reset detected — treat current value as the delta
			drops[i] = cumDrops[i]
		}
	}
	fe.prevDrops = cumDrops

	if drops[dropFragments] != 3 {
		t.Errorf("after reset, expected fragments delta=3, got %d", drops[dropFragments])
	}
	if drops[dropNonIPv4] != 0 {
		t.Errorf("after reset, expected non_ipv4 delta=0, got %d", drops[dropNonIPv4])
	}
	if drops[dropParseErr] != 1 {
		t.Errorf("after reset, expected parse_err delta=1, got %d", drops[dropParseErr])
	}
	if drops[dropLinearize] != 0 {
		t.Errorf("after reset, expected linearize delta=0, got %d", drops[dropLinearize])
	}
	if drops[dropMapFull] != 2 {
		t.Errorf("after reset, expected map_full delta=2, got %d", drops[dropMapFull])
	}
}

func TestDropReasonLabels(t *testing.T) {
	if len(dropReasonLabels) != dropMax {
		t.Fatalf("dropReasonLabels length %d != dropMax %d", len(dropReasonLabels), dropMax)
	}
	expected := [dropMax]string{"fragments", "non_ipv4", "parse_error", "linearize", "map_full"}
	for i := 0; i < dropMax; i++ {
		if dropReasonLabels[i] != expected[i] {
			t.Errorf("dropReasonLabels[%d] = %q, want %q", i, dropReasonLabels[i], expected[i])
		}
	}
}

func TestFlowExporterZeroInit(t *testing.T) {
	fe := &flowExporter{}
	for i := 0; i < dropMax; i++ {
		if fe.prevDrops[i] != 0 {
			t.Errorf("expected prevDrops[%d]=0 on init, got %d", i, fe.prevDrops[i])
		}
	}
}

func TestRunVersionDoesNotRequireInterface(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"--version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%q", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "revision=") || !strings.Contains(got, "build_date=") {
		t.Fatalf("expected version metadata, got %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestRunMissingInterfaceReturnsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected empty stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: flowcap [options] <interface>") {
		t.Fatalf("expected usage on stderr, got %q", stderr.String())
	}
}

func TestRunRejectsInvalidMetricsAddr(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"-metrics-addr", "localhost:9090", "eth0"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "is not a valid IP address") {
		t.Fatalf("expected invalid IP error, got %q", stderr.String())
	}
}

func TestStartupLogLineIncludesVersionMetadata(t *testing.T) {
	oldVersion, oldRevision, oldBuildDate := version, revision, buildDate
	version, revision, buildDate = "v-test", "abc123", "2026-05-17T12:00:00Z"
	t.Cleanup(func() {
		version, revision, buildDate = oldVersion, oldRevision, oldBuildDate
	})

	line := startupLogLine("eth0", 10, 60, 16384, 10000, true, "127.0.0.1:9090", "/tmp/stats.log")

	for _, want := range []string{
		"version=v-test",
		"revision=abc123",
		"build_date=2026-05-17T12:00:00Z",
		"interface=eth0",
		"interval=10s",
		"timeout=60s",
		"max_flows=16384",
		"max_export_per_cycle=10000",
		"json=true",
		`metrics_addr="127.0.0.1:9090"`,
		`stats_file="/tmp/stats.log"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("expected startup log line to contain %q, got %q", want, line)
		}
	}
}

func TestL2HeaderLenForLinkType(t *testing.T) {
	tests := []struct {
		name         string
		linkType     int
		hardwareAddr net.HardwareAddr
		want         uint32
	}{
		{name: "ethernet", linkType: arphrdEther, hardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, want: ethHeaderLen},
		{name: "loopback", linkType: arphrdLoopback, want: ethHeaderLen},
		{name: "tun wireguard", linkType: arphrdNone, want: 0},
		{name: "unknown with hardware address", linkType: 9999, hardwareAddr: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, want: ethHeaderLen},
		{name: "unknown without hardware address", linkType: 9999, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := l2HeaderLenForLinkType(tt.linkType, tt.hardwareAddr); got != tt.want {
				t.Fatalf("expected l2 header length %d, got %d", tt.want, got)
			}
		})
	}
}

func TestExportRecordsRateLimit(t *testing.T) {
	fe := &flowExporter{}
	records := []flowRecord{
		{
			key: flowFlowKey{SrcIp: 0x0100007f, DstIp: 0x0200007f, SrcPort: 1000, DstPort: 80, Protocol: 6},
			stats: flowFlowStats{
				Packets:   2,
				Bytes:     200,
				FirstSeen: uint64(9 * time.Second),
				LastSeen:  uint64(10 * time.Second),
				TcpFlags:  0x02,
			},
		},
		{
			key: flowFlowKey{SrcIp: 0x0300007f, DstIp: 0x0400007f, SrcPort: 2000, DstPort: 443, Protocol: 6},
			stats: flowFlowStats{
				Packets:   3,
				Bytes:     300,
				FirstSeen: uint64(7 * time.Second),
				LastSeen:  uint64(8 * time.Second),
				TcpFlags:  0x04,
			},
		},
		{
			key: flowFlowKey{SrcIp: 0x0500007f, DstIp: 0x0600007f, SrcPort: 3000, DstPort: 53, Protocol: 17},
			stats: flowFlowStats{
				Packets:   4,
				Bytes:     400,
				FirstSeen: uint64(1 * time.Second),
				LastSeen:  uint64(2 * time.Second),
				TcpFlags:  0,
			},
		},
	}
	cumDrops := [dropMax]uint64{dropFragments: 5}
	var output, stats bytes.Buffer

	activeBefore := counterValue(t, "active")
	closedBefore := counterValue(t, "closed")
	inactiveBefore := counterValue(t, "inactive")

	summary := fe.exportRecords(records, cumDrops, uint64(10*time.Second), 5, false, 2, &output, &stats)

	if !summary.rateLimited {
		t.Fatal("expected rateLimited=true")
	}
	if summary.currentFlows != 3 {
		t.Fatalf("expected currentFlows=3, got %d", summary.currentFlows)
	}
	if summary.exportedCount != 2 {
		t.Fatalf("expected exportedCount=2, got %d", summary.exportedCount)
	}
	if len(summary.keysToDelete) != 2 {
		t.Fatalf("expected 2 keys to delete, got %d", len(summary.keysToDelete))
	}
	if summary.activeCount != 1 || summary.closedCount != 1 || summary.inactiveCount != 0 {
		t.Fatalf("unexpected classifications: active=%d closed=%d inactive=%d", summary.activeCount, summary.closedCount, summary.inactiveCount)
	}
	if summary.totalBytes != 500 || summary.totalPackets != 5 {
		t.Fatalf("unexpected totals: bytes=%d packets=%d", summary.totalBytes, summary.totalPackets)
	}
	if summary.drops[dropFragments] != 5 {
		t.Fatalf("expected fragments drop delta=5, got %d", summary.drops[dropFragments])
	}
	if lines := strings.Count(strings.TrimSpace(output.String()), "\n") + 1; lines != 2 {
		t.Fatalf("expected 2 output lines, got %d: %q", lines, output.String())
	}
	if !strings.Contains(stats.String(), "Exported: 1 active, 0 inactive, 1 closed") {
		t.Fatalf("unexpected stats output: %q", stats.String())
	}
	if got := counterValue(t, "active") - activeBefore; got != 1 {
		t.Fatalf("expected active counter +1, got %v", got)
	}
	if got := counterValue(t, "closed") - closedBefore; got != 1 {
		t.Fatalf("expected closed counter +1, got %v", got)
	}
	if got := counterValue(t, "inactive") - inactiveBefore; got != 0 {
		t.Fatalf("expected inactive counter unchanged, got %v", got)
	}
}

func TestExportRecordsDropCounterReset(t *testing.T) {
	fe := &flowExporter{
		prevDrops: [dropMax]uint64{
			dropFragments: 10,
		},
	}
	cumDrops := [dropMax]uint64{
		dropFragments: 2,
	}
	var output, stats bytes.Buffer

	summary := fe.exportRecords(nil, cumDrops, uint64(10*time.Second), 5, false, 10, &output, &stats)

	if summary.drops[dropFragments] != 2 {
		t.Fatalf("expected fragments drop delta after reset=2, got %d", summary.drops[dropFragments])
	}
	if fe.prevDrops[dropFragments] != 2 {
		t.Fatalf("expected prevDrops to be updated after reset, got %d", fe.prevDrops[dropFragments])
	}
}

func TestExportRecordsDoesNotTreatTypedNilStatsFileAsWriter(t *testing.T) {
	fe := &flowExporter{}
	var output bytes.Buffer
	var statsFile *os.File
	var statsWriter io.Writer
	if statsFile != nil {
		statsWriter = statsFile
	}

	summary := fe.exportRecords(nil, [dropMax]uint64{}, uint64(10*time.Second), 5, true, 10, &output, statsWriter)

	if summary.currentFlows != 0 {
		t.Fatalf("expected no records, got %d", summary.currentFlows)
	}
	if output.Len() != 0 {
		t.Fatalf("expected empty output, got %q", output.String())
	}
}

func TestBuildInfoMetric(t *testing.T) {
	buildInfo.WithLabelValues("test-version", "test-revision", "test-date").Set(1)

	metric, err := buildInfo.GetMetricWithLabelValues("test-version", "test-revision", "test-date")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var dtoMetric dto.Metric
	if err := metric.Write(&dtoMetric); err != nil {
		t.Fatalf("metric.Write: %v", err)
	}
	if got := dtoMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("expected build info gauge=1, got %v", got)
	}
}

func TestCaptureInfoMetric(t *testing.T) {
	captureInfo.WithLabelValues("test0", "14").Set(1)

	metric, err := captureInfo.GetMetricWithLabelValues("test0", "14")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var dtoMetric dto.Metric
	if err := metric.Write(&dtoMetric); err != nil {
		t.Fatalf("metric.Write: %v", err)
	}
	if got := dtoMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("expected capture info gauge=1, got %v", got)
	}
}

func TestMetricLabelsArePreinitialized(t *testing.T) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	exportedFamily := metricFamily(t, families, "flowcap_exported_flows_total")
	for _, reason := range exportReasonLabels {
		if !hasMetricLabel(exportedFamily, "reason", reason) {
			t.Fatalf("expected exported reason %q to be preinitialized", reason)
		}
	}

	droppedFamily := metricFamily(t, families, "flowcap_dropped_packets_total")
	for _, reason := range dropReasonLabels {
		if !hasMetricLabel(droppedFamily, "reason", reason) {
			t.Fatalf("expected drop reason %q to be preinitialized", reason)
		}
	}
}

func metricFamily(t *testing.T, families []*dto.MetricFamily, name string) *dto.MetricFamily {
	t.Helper()

	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	t.Fatalf("metric family %q not found", name)
	return nil
}

func hasMetricLabel(family *dto.MetricFamily, labelName, labelValue string) bool {
	for _, metric := range family.GetMetric() {
		for _, label := range metric.GetLabel() {
			if label.GetName() == labelName && label.GetValue() == labelValue {
				return true
			}
		}
	}
	return false
}

func counterValue(t *testing.T, label string) float64 {
	t.Helper()

	counter, err := exportedFlowsTotal.GetMetricWithLabelValues(label)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%q): %v", label, err)
	}
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatalf("counter.Write(%q): %v", label, err)
	}
	return metric.GetCounter().GetValue()
}
