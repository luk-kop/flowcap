package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
)

// Only the operations needed for a coherent, bounded scan and state checks.
type flowMapReader interface {
	NextKey(key, nextKeyOut any) error
	LookupWithFlags(key, valueOut any, flags ebpf.MapLookupFlags) error
	MaxEntries() uint32
}

type flowMapStore interface {
	flowMapReader
	Delete(key any) error
}

type incompleteDrainError struct {
	stage     string
	remaining int
	known     bool
	err       error
}

func (e *incompleteDrainError) Error() string {
	if e.known {
		return fmt.Sprintf("%s (%d entries remain): %v", e.stage, e.remaining, e.err)
	}
	return fmt.Sprintf("%s (remaining entries unknown): %v", e.stage, e.err)
}

func (e *incompleteDrainError) Unwrap() error { return e.err }

func knownDrainFailure(stage string, remaining int, err error) error {
	return &incompleteDrainError{stage: stage, remaining: remaining, known: true, err: err}
}

func unknownDrainFailure(stage string, err error) error {
	return &incompleteDrainError{stage: stage, known: false, err: err}
}

// Call only after synchronous detach and after the normal export worker has
// completed. Zero is the explicit unlimited export mode.
func (fe *flowExporter) drainFlows(m *ebpf.Map, drops *ebpf.Map, timeout int, jsonOutput bool, output io.Writer, stats *os.File) error {
	if err := fe.exportFlows(m, drops, timeout, jsonOutput, 0, output, stats); err != nil {
		return err
	}
	if err := fe.releaseDrained(m); err != nil {
		err = newExportStageError("state", err)
		recordExportError(err)
		return err
	}
	return nil
}

func (fe *flowExporter) releaseDrained(m flowMapStore) error {
	records, err := scanFlowMap(m)
	if err != nil {
		return unknownDrainFailure("verify final confirmations", err)
	}
	pendingCount := 0
	for _, r := range records {
		instance := flowInstance{r.key, flowGeneration(r.stats)}
		_, _, pending, err := fe.deltaFor(instance, r.stats, r.observedAt)
		if err != nil {
			return err
		}
		if pending {
			pendingCount++
		}
	}
	if pendingCount != 0 {
		return knownDrainFailure("final snapshot has unconfirmed data", pendingCount, errors.New("export acknowledgement missing"))
	}
	for i, r := range records {
		if err := m.Delete(&r.key); err != nil {
			return knownDrainFailure("delete drained entry", len(records)-i, err)
		}
		delete(fe.confirmed, flowInstance{r.key, flowGeneration(r.stats)})
	}
	remaining, err := scanFlowMap(m)
	if err != nil {
		return unknownDrainFailure("verify empty map", err)
	}
	if len(remaining) != 0 || len(fe.confirmed) != 0 {
		return knownDrainFailure("incomplete drain", len(remaining), fmt.Errorf("%d acknowledgement records remain", len(fe.confirmed)))
	}
	return nil
}

// Map.Iterate uses an unlocked lookup. Walk keys explicitly so each value is
// copied under the same spin lock as packet updates. Bound work even if a map
// is changed externally and the kernel repeatedly restarts its key walk.
func scanFlowMap(m flowMapReader) ([]flowRecord, error) {
	var records []flowRecord
	var cursor any
	for attempts := uint32(0); ; attempts++ {
		var key flowFlowKey
		if err := m.NextKey(cursor, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return records, nil
			}
			return records, fmt.Errorf("next flow key: %w", err)
		}
		if attempts >= m.MaxEntries() {
			return records, fmt.Errorf("flow scan exceeded map capacity: %w", ebpf.ErrIterationAborted)
		}
		cursor = &key
		var stats flowFlowStats
		if err := m.LookupWithFlags(&key, &stats, ebpf.LookupLock); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return records, fmt.Errorf("locked flow lookup: %w", err)
		}
		records = append(records, flowRecord{key: key, stats: stats, observedAt: ktimeNow()})
	}
}
