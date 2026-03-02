package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
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
