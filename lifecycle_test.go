package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type testCaptureLink struct {
	name   string
	events *[]string
	fail   error
}

func (l *testCaptureLink) Detach() error {
	*l.events = append(*l.events, "detach "+l.name)
	return l.fail
}
func (l *testCaptureLink) Close() error { *l.events = append(*l.events, "close "+l.name); return nil }

func TestCaptureResourceOwnership(t *testing.T) {
	for _, failed := range []string{"", "ingress", "egress"} {
		t.Run(failed, func(t *testing.T) {
			var events []string
			in := &testCaptureLink{name: "ingress", events: &events}
			out := &testCaptureLink{name: "egress", events: &events}
			if failed == "ingress" {
				in.fail = errors.New("detach")
			}
			if failed == "egress" {
				out.fail = errors.New("detach")
			}
			r := &captureResources{ingress: &captureHook{link: in}, egress: &captureHook{link: out}}
			err := r.Stop()
			if (err != nil) != (failed != "") {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(events, []string{"detach egress", "detach ingress"}) {
				t.Fatal(events)
			}
			if failed == "" {
				if err := r.Stop(); err != nil {
					t.Fatal(err)
				}
				if len(events) != 2 {
					t.Fatal("duplicate detach")
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if len(events) != 4 {
				t.Fatal("duplicate close", events)
			}
		})
	}
	var events []string
	r := &captureResources{ingress: &captureHook{link: &testCaptureLink{name: "ingress", events: &events}}}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"close ingress"}) {
		t.Fatal("partial attach cleanup", events)
	}
}

func TestCaptureStopsBeforeDrainAndDoesNotRetryWriteFailure(t *testing.T) {
	for _, mode := range []string{"signal", "write", "detach", "drain", "server"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ticks := make(chan time.Time, 1)
			ticks <- time.Now()
			server := make(chan error, 1)
			var events []string
			export := func(n int) error {
				if n == 0 {
					events = append(events, "drain")
					if mode == "drain" {
						return errors.New("drain")
					}
					return nil
				}
				events = append(events, "export")
				if mode == "write" {
					return newExportStageError("write", io.ErrClosedPipe)
				}
				if mode == "server" {
					server <- errors.New("server")
				} else {
					cancel()
				}
				return nil
			}
			stop := func() error {
				events = append(events, "stop")
				if mode == "detach" {
					return errors.New("detach")
				}
				return nil
			}
			err := runCapture(ctx, ticks, server, 1, time.Second, export, stop, func(context.Context) error { events = append(events, "close"); return nil })
			if (err != nil) != (mode != "signal") {
				t.Fatal(err)
			}
			want := []string{"export", "stop", "drain", "close"}
			if mode == "write" || mode == "detach" {
				want = []string{"export", "stop", "close"}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("events=%v want=%v", events, want)
			}
		})
	}
}

func TestShutdownDeadlineCoversBlockedDetach(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release := make(chan struct{})
	closed := make(chan struct{})
	err := runCapture(ctx, nil, nil, 1, 20*time.Millisecond, func(int) error { t.Error("drain after deadline"); return nil }, func() error { <-release; return nil }, func(context.Context) error { close(closed); return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cleanup leaked")
	}
}

func TestBusyCaptureCoalescesTicksAndKeepsMapsOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 100)
	ticks <- time.Now()
	started := make(chan struct{})
	release := make(chan struct{})
	stopped := make(chan struct{})
	closed := make(chan struct{})
	finished := make(chan error, 1)
	var once sync.Once
	go func() {
		finished <- runCapture(ctx, ticks, nil, 1, 30*time.Millisecond, func(n int) error {
			if n == 0 {
				t.Error("drain after timeout")
				return nil
			}
			once.Do(func() { close(started) })
			<-release
			return nil
		}, func() error { close(stopped); return nil }, func(context.Context) error { close(closed); return nil })
	}()
	<-started
	for range 100 {
		ticks <- time.Now()
	}
	cancel()
	<-stopped
	err := <-finished
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-closed:
		t.Fatal("closed resources below blocked worker")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("worker leaked")
	}
}

// Exercise real process signals and a real pipe, including stdout's SIGPIPE
// behavior. The generic wrapper deliberately removes deadline support in the
// signal case so shutdown must bound an uninterruptible writer.
func TestLifecycleRealPipe(t *testing.T) {
	for _, mode := range []string{"signal", "closed", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLifecycleSubprocessHelper$")
			cmd.Env = append(os.Environ(), "FLOWCAP_PIPE_TEST="+mode)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close(); _ = w.Close() }()
			cmd.Stdout = w
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "closed" {
				_ = r.Close()
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = w.Close()
			reader := bufio.NewReader(stderr)
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "READY" {
				_ = cmd.Wait()
				t.Fatal(line, err)
			}
			if mode != "closed" {
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			diagnostic, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			if ctx.Err() != nil {
				t.Fatal("subprocess did not stop")
			}
			if err == nil || !strings.Contains(string(diagnostic), "INCOMPLETE") {
				t.Fatalf("expected explicit incomplete shutdown: %s %v", diagnostic, err)
			}
		})
	}
}

func TestLifecycleSubprocessHelper(t *testing.T) {
	mode := os.Getenv("FLOWCAP_PIPE_TEST")
	if mode == "" {
		return
	}
	signal.Ignore(syscall.SIGPIPE)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	var writer io.Writer = os.Stdout
	if mode == "signal" {
		writer = struct{ io.Writer }{writer}
	}
	out := timeoutWriter{writer: writer, timeout: 50 * time.Millisecond}
	err := runCapture(ctx, ticks, nil, 1, 100*time.Millisecond, func(int) error {
		_, _ = fmt.Fprintln(os.Stderr, "READY")
		_, err := out.Write(make([]byte, 1<<20))
		return newExportStageError("write", err)
	}, func() error { return nil }, func(context.Context) error { return nil })
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "INCOMPLETE:", err)
		os.Exit(1)
	}
	os.Exit(0)
}
