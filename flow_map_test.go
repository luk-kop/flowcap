package main

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

type testFlowMap struct {
	values                        map[flowFlowKey]flowFlowStats
	keys                          []flowFlowKey // optional scripted iterator, including duplicates
	next                          int
	capacity                      uint32
	scanErr, lookupErr, deleteErr error
	keepDeleted                   bool
}

func (m *testFlowMap) MaxEntries() uint32 { return m.capacity }
func (m *testFlowMap) NextKey(key, out any) error {
	if m.keys != nil {
		if m.next == len(m.keys) {
			if m.scanErr != nil {
				return m.scanErr
			}
			return ebpf.ErrKeyNotExist
		}
		*out.(*flowFlowKey) = m.keys[m.next]
		m.next++
		return nil
	}
	var keys []flowFlowKey
	for k := range m.values {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].SrcPort < keys[j].SrcPort })
	for _, k := range keys {
		if key == nil || k.SrcPort > key.(*flowFlowKey).SrcPort {
			*out.(*flowFlowKey) = k
			return nil
		}
	}
	if m.scanErr != nil {
		return m.scanErr
	}
	return ebpf.ErrKeyNotExist
}
func (m *testFlowMap) LookupWithFlags(key, out any, flags ebpf.MapLookupFlags) error {
	if flags != ebpf.LookupLock {
		return errors.New("snapshot did not take value lock")
	}
	if m.lookupErr != nil {
		return m.lookupErr
	}
	v, ok := m.values[*key.(*flowFlowKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out.(*flowFlowStats) = v
	return nil
}
func (m *testFlowMap) Delete(key any) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if !m.keepDeleted {
		delete(m.values, *key.(*flowFlowKey))
	}
	return nil
}

func TestLockedScanDuplicatesAndErrors(t *testing.T) {
	k := flowFlowKey{SrcPort: 1}
	failure := errors.New("scan failed")
	for _, tc := range []struct {
		name      string
		keys      []flowFlowKey
		cap       uint32
		err, want error
		count     int
	}{
		{"duplicate", []flowFlowKey{k, k}, 2, nil, nil, 2},
		{"partial", []flowFlowKey{k}, 2, failure, failure, 1},
		{"bounded", []flowFlowKey{k, k, k}, 2, nil, ebpf.ErrIterationAborted, 2},
		{"missing", []flowFlowKey{{SrcPort: 2}, k}, 2, nil, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &testFlowMap{capacity: tc.cap, keys: tc.keys, scanErr: tc.err, values: map[flowFlowKey]flowFlowStats{k: {Generation: 1, Packets: 1, Bytes: 100}}}
			records, err := scanFlowMap(m)
			if !errors.Is(err, tc.want) || len(records) != tc.count {
				t.Fatalf("records=%d err=%v", len(records), err)
			}
		})
	}
}

func TestConfirmationSurvivesArbitrarilyManyMissedScans(t *testing.T) {
	k := flowFlowKey{SrcPort: 1}
	m := &testFlowMap{capacity: 1, values: map[flowFlowKey]flowFlowStats{k: {Generation: 1, Packets: 10, Bytes: 1000}}}
	fe := &flowExporter{}
	r, err := scanFlowMap(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fe.exportRecords(r, [dropMax]uint64{}, 20, 60, true, 1, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if err := fe.pruneConfirmations(m, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := fe.exportRecords(nil, [dropMax]uint64{}, 20, 60, true, 1, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := fe.exportRecords(r, [dropMax]uint64{}, 20, 60, true, 1, io.Discard, nil)
	if err != nil || summary.exportedCount != 0 {
		t.Fatalf("duplicate after missed scans: %+v %v", summary, err)
	}
	m.lookupErr = errors.New("lookup failed")
	if err := fe.pruneConfirmations(m, nil); !errors.Is(err, m.lookupErr) || len(fe.confirmed) != 1 {
		t.Fatal("lookup failure discarded acknowledgement")
	}
	m.lookupErr = nil
	delete(m.values, k)
	if err := fe.pruneConfirmations(m, nil); err != nil || len(fe.confirmed) != 0 {
		t.Fatal("missing instance not reclaimed", err)
	}
}

func TestExporterTreatsDirectionsAsDistinctFlowInstances(t *testing.T) {
	base := flowFlowKey{SrcPort: 12345, DstPort: 443, Protocol: 6}
	ingress := base
	ingress.FlowDirection = flowDirectionIngress
	egress := base
	egress.FlowDirection = flowDirectionEgress
	records := []flowRecord{
		{key: ingress, stats: flowFlowStats{Generation: 1, Packets: 2, Bytes: 200}},
		{key: egress, stats: flowFlowStats{Generation: 1, Packets: 3, Bytes: 300}},
	}

	fe := &flowExporter{}
	summary, err := fe.exportRecords(records, [dropMax]uint64{}, 1, 60, true, 0, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.exportedCount != 2 || summary.totalPackets != 5 || summary.totalBytes != 500 {
		t.Fatalf("directions were not exported independently: %+v", summary)
	}
	if len(fe.confirmed) != 2 {
		t.Fatalf("directional confirmations=%d, want 2", len(fe.confirmed))
	}
	if !instanceLess(flowInstance{key: ingress, generation: 1}, flowInstance{key: egress, generation: 1}) {
		t.Fatal("stable ordering does not distinguish ingress from egress")
	}
}

func TestGenerationReplacementAndGrowingDuplicates(t *testing.T) {
	for _, newCount := range []uint64{2, 200} {
		fe := &flowExporter{}
		k := flowFlowKey{SrcPort: 1}
		initial := flowFlowStats{Generation: 1, Packets: 10, Bytes: 1000}
		if _, err := fe.exportRecords([]flowRecord{{key: k, stats: initial}}, [dropMax]uint64{}, 1, 60, true, 0, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
		next := flowFlowStats{Generation: 2, Packets: newCount, Bytes: newCount * 100}
		m := &testFlowMap{values: map[flowFlowKey]flowFlowStats{k: next}}
		if err := fe.pruneConfirmations(m, nil); err != nil {
			t.Fatal(err)
		}
		larger := next
		larger.Packets++
		larger.Bytes += 100
		s, err := fe.exportRecords([]flowRecord{{key: k, stats: next}, {key: k, stats: larger}}, [dropMax]uint64{}, 2, 60, true, 0, io.Discard, nil)
		if err != nil || s.totalPackets != newCount+1 {
			t.Fatalf("new generation/growing duplicate: %+v %v", s, err)
		}
	}
}

type callbackWriter struct{ write func() }

func (w callbackWriter) Write(p []byte) (int, error) { w.write(); return len(p), nil }

func TestUpdateDuringWriteRemainsForNextDelta(t *testing.T) {
	fe := &flowExporter{}
	k := flowFlowKey{SrcPort: 1}
	m := &testFlowMap{capacity: 1, values: map[flowFlowKey]flowFlowStats{k: {Generation: 1, Packets: 10, Bytes: 1000}}}
	r, err := scanFlowMap(m)
	if err != nil {
		t.Fatal(err)
	}
	writer := callbackWriter{func() { s := m.values[k]; s.Packets += 3; s.Bytes += 300; m.values[k] = s }}
	a, err := fe.exportRecords(r, [dropMax]uint64{}, 1, 60, true, 0, writer, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err = scanFlowMap(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := fe.exportRecords(r, [dropMax]uint64{}, 2, 60, true, 0, io.Discard, nil)
	if err != nil || a.totalPackets+b.totalPackets != 13 || a.totalBytes+b.totalBytes != 1300 {
		t.Fatalf("lost update: %+v %+v %v", a, b, err)
	}
}

func TestExportLimitMakesProgressWithAllFlowsBusy(t *testing.T) {
	fe := &flowExporter{}
	records := make([]flowRecord, 5)
	for i := range records {
		records[i] = flowRecord{key: flowFlowKey{SrcPort: uint16(i + 1)}, stats: flowFlowStats{Generation: uint64(i + 1), Packets: 1, Bytes: 100}}
	}
	for range 5 {
		s, err := fe.exportRecords(records, [dropMax]uint64{}, 100, 60, true, 1, io.Discard, nil)
		if err != nil || s.exportedCount != 1 {
			t.Fatal(s, err)
		}
		for i := range records {
			records[i].stats.Packets++
			records[i].stats.Bytes += 100
		}
	}
	if len(fe.confirmed) != 5 {
		t.Fatalf("starved flows: only %d confirmed", len(fe.confirmed))
	}
}

func TestDrainRequiresConfirmedEmptyMap(t *testing.T) {
	for _, mode := range []string{"success", "pending", "scan-error", "delete-error", "no-progress"} {
		t.Run(mode, func(t *testing.T) {
			m := &testFlowMap{capacity: 10, values: map[flowFlowKey]flowFlowStats{}}
			for i := uint16(1); i <= 5; i++ {
				m.values[flowFlowKey{SrcPort: i}] = flowFlowStats{Generation: uint64(i), Packets: 1, Bytes: 100}
			}
			fe := &flowExporter{}
			r, err := scanFlowMap(m)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			limit := 0
			if mode == "pending" {
				limit = 1
			}
			s, err := fe.exportRecords(r, [dropMax]uint64{}, 1, 60, true, limit, &output, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "scan-error":
				m.scanErr = errors.New("scan")
			case "delete-error":
				m.deleteErr = errors.New("delete")
			case "no-progress":
				m.keepDeleted = true
			}
			err = fe.releaseDrained(m)
			if mode == "success" {
				if err != nil || s.exportedCount != 5 || len(m.values) != 0 || len(fe.confirmed) != 0 {
					t.Fatal(s, err)
				}
			} else if err == nil {
				t.Fatal("incomplete drain reported success")
			} else {
				var drainErr *incompleteDrainError
				if !errors.As(err, &drainErr) {
					t.Fatalf("missing structured drain status: %v", err)
				}
				if mode == "scan-error" && drainErr.known {
					t.Fatal("partial scan reported an exact remaining count")
				}
				if mode != "scan-error" && (!drainErr.known || drainErr.remaining == 0) {
					t.Fatalf("known failure did not report remaining entries: %+v", drainErr)
				}
			}
		})
	}
}
