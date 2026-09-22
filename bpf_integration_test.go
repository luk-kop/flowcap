//go:build integration

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func loadIntegrationObjects(t *testing.T, maxEntries uint32, l2Length uint32) *flowObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock limit: %v", err)
	}

	spec, err := loadFlow()
	if err != nil {
		t.Fatalf("load generated collection spec: %v", err)
	}
	spec.Maps["flows"].MaxEntries = maxEntries
	if err := spec.Variables["l2_hdr_len"].Set(l2Length); err != nil {
		t.Fatalf("set l2 header length: %v", err)
	}

	objects := &flowObjects{}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		t.Fatalf("load program and maps through kernel verifier: %v", err)
	}
	t.Cleanup(func() {
		if err := objects.Close(); err != nil {
			t.Errorf("close eBPF objects: %v", err)
		}
	})
	return objects
}

func udpFrame(srcPort, dstPort uint16) ([]byte, flowFlowKey) {
	p := make([]byte, 14+20+8)
	p[12], p[13] = 0x08, 0x00
	ip := p[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 28)
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 2})
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	return p, flowFlowKey{
		SrcIp: binary.NativeEndian.Uint32(ip[12:16]), DstIp: binary.NativeEndian.Uint32(ip[16:20]),
		SrcPort: srcPort, DstPort: dstPort, Protocol: 17, FlowDirection: flowDirectionIngress,
	}
}

func TestIntegrationLockedSnapshotsAndCapacity(t *testing.T) {
	objects := loadIntegrationObjects(t, 2, 14)
	frame, key := udpFrame(1000, 53)
	const workers, packetsPerWorker = 4, 50
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range packetsPerWorker {
				if _, _, err := objects.FlowCaptureIngress.Test(frame); err != nil {
					t.Errorf("run program: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	var stats flowFlowStats
	if err := objects.Flows.LookupWithFlags(&key, &stats, ebpf.LookupLock); err != nil {
		t.Fatalf("locked lookup: %v", err)
	}
	if stats.Packets != workers*packetsPerWorker || stats.Bytes != stats.Packets*uint64(len(frame)) {
		t.Fatalf("incoherent counters: packets=%d bytes=%d", stats.Packets, stats.Bytes)
	}
	if stats.Generation == 0 || stats.FirstSeen == 0 || stats.LastSeen < stats.FirstSeen {
		t.Fatalf("invalid identity/timestamps: %+v", stats)
	}
	firstGeneration := stats.Generation

	frame2, _ := udpFrame(1001, 53)
	frame3, _ := udpFrame(1002, 53)
	if _, _, err := objects.FlowCaptureIngress.Test(frame2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := objects.FlowCaptureIngress.Test(frame3); err != nil {
		t.Fatal(err)
	}
	if drops := readDropCounters(objects.DropCounters); drops[dropMapFull] != 1 {
		t.Fatalf("expected one visible capacity failure, drops=%v", drops)
	}

	if err := objects.Flows.Delete(&key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := objects.FlowCaptureIngress.Test(frame); err != nil {
		t.Fatal(err)
	}
	if err := objects.Flows.LookupWithFlags(&key, &stats, ebpf.LookupLock); err != nil {
		t.Fatal(err)
	}
	if stats.Generation == firstGeneration {
		t.Fatal("re-created key reused generation")
	}
}

func TestIntegrationFlowDirectionSeparatesMapEntries(t *testing.T) {
	objects := loadIntegrationObjects(t, 2, 14)
	frame, ingressKey := udpFrame(1000, 53)
	egressKey := ingressKey
	egressKey.FlowDirection = flowDirectionEgress

	if _, _, err := objects.FlowCaptureIngress.Test(frame); err != nil {
		t.Fatalf("run ingress program: %v", err)
	}
	if _, _, err := objects.FlowCaptureEgress.Test(frame); err != nil {
		t.Fatalf("run egress program: %v", err)
	}

	var ingressStats, egressStats flowFlowStats
	if err := objects.Flows.LookupWithFlags(&ingressKey, &ingressStats, ebpf.LookupLock); err != nil {
		t.Fatalf("lookup ingress flow: %v", err)
	}
	if err := objects.Flows.LookupWithFlags(&egressKey, &egressStats, ebpf.LookupLock); err != nil {
		t.Fatalf("lookup egress flow: %v", err)
	}
	if ingressStats.Packets != 1 || egressStats.Packets != 1 {
		t.Fatalf("directions did not retain independent counters: ingress=%d egress=%d", ingressStats.Packets, egressStats.Packets)
	}
	if ingressStats.Generation == 0 || egressStats.Generation == 0 || ingressStats.Generation == egressStats.Generation {
		t.Fatalf("directions did not create distinct instances: ingress=%d egress=%d", ingressStats.Generation, egressStats.Generation)
	}
}

func TestIntegrationTCXAttachDetach(t *testing.T) {
	objects := loadIntegrationObjects(t, 16, 14)
	name := fmt.Sprintf("fcit%d", testProcessSuffix())
	if output, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("create isolated dummy interface: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "delete", name).Run() })
	iface, err := findInterface(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		attach  ebpf.AttachType
		program *ebpf.Program
	}{
		{ebpf.AttachTCXIngress, objects.FlowCaptureIngress},
		{ebpf.AttachTCXEgress, objects.FlowCaptureEgress},
	} {
		attached, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: tc.program, Attach: tc.attach})
		if err != nil {
			t.Fatalf("attach TCX %v: %v", tc.attach, err)
		}
		if err := attached.Detach(); err != nil {
			t.Fatalf("detach TCX %v: %v", tc.attach, err)
		}
		if err := attached.Close(); err != nil {
			t.Fatalf("close detached TCX %v: %v", tc.attach, err)
		}
	}
}

func testProcessSuffix() int {
	// Linux interface names are limited to 15 bytes; the test process ID is
	// unique on a CI host and keeps cleanup targets unambiguous.
	return os.Getpid()
}
