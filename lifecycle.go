package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type detachableLink interface {
	Detach() error
	Close() error
}

type captureHook struct {
	link     detachableLink
	detached bool
}

func (h *captureHook) stop() error {
	if h == nil || h.detached {
		return nil
	}
	// BPF_LINK_DETACH executes TCX's synchronize_rcu before returning. Closing
	// an fd can defer release; use the explicit detach syscall for the barrier.
	if err := h.link.Detach(); err != nil {
		return err
	}
	h.detached = true
	return nil
}

type captureResources struct {
	ingress, egress *captureHook
	objects, stats  io.Closer
}

func (r *captureResources) Stop() error {
	var failures []error
	for _, hook := range []struct {
		name  string
		value *captureHook
	}{{"egress", r.egress}, {"ingress", r.ingress}} {
		if err := hook.value.stop(); err != nil {
			failures = append(failures, fmt.Errorf("detach %s: %w", hook.name, err))
		}
	}
	return errors.Join(failures...)
}

func (r *captureResources) Close() error {
	var failures []error
	for _, hook := range []*captureHook{r.egress, r.ingress} {
		if hook != nil {
			failures = append(failures, hook.link.Close())
		}
	}
	r.egress, r.ingress = nil, nil
	for _, closer := range []io.Closer{r.stats, r.objects} {
		if closer != nil {
			failures = append(failures, closer.Close())
		}
	}
	r.stats, r.objects = nil, nil
	return errors.Join(failures...)
}

// One worker owns all exporter state. Ticks coalesce while it is busy. The
// shutdown budget covers detach, the active write, drain and resource cleanup.
func runCapture(ctx context.Context, ticks <-chan time.Time, serverErrors <-chan error, limit int, shutdownTimeout time.Duration,
	export func(int) error, stop func() error, cleanup func(context.Context) error) error {
	jobs := make(chan exportJob)
	done := startExportWorker(jobs, export)
	start := func(n int) <-chan error {
		result := make(chan error, 1)
		jobs <- exportJob{maxRecords: n, result: result}
		return result
	}
	var active <-chan error
	var failure error
capture:
	for {
		select {
		case <-ctx.Done():
			break capture
		case failure = <-serverErrors:
			break capture
		case <-ticks:
			if active == nil {
				active = start(limit)
			}
		case err := <-active:
			active = nil
			if err != nil {
				failure = err
				break capture
			}
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		stopErr := stop()
		noRetry := exportFailurePreventsRetry(failure)
		if active != nil {
			err := <-active
			failure = errors.Join(failure, err)
			noRetry = noRetry || exportFailurePreventsRetry(err)
		}
		if stopErr == nil && !noRetry && shutdownCtx.Err() == nil {
			failure = errors.Join(failure, <-start(0))
		}
		close(jobs)
		<-done
		finished <- errors.Join(failure, stopErr, cleanup(shutdownCtx))
	}()
	select {
	case err := <-finished:
		return err
	case <-shutdownCtx.Done():
		return fmt.Errorf("shutdown deadline; remaining records unknown: %w", shutdownCtx.Err())
	}
}
