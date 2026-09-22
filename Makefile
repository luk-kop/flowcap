APP := flowcap
CMD := .
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP)
RELEASE_TMP := $(BIN_DIR)/release
BPF_OBJECTS := flow_bpfel.o flow_bpfeb.o
GO := GOCACHE=$(CURDIR)/.cache/go-build go
GOLANGCI_LINT := GOCACHE=$(CURDIR)/.cache/go-build GOLANGCI_LINT_CACHE=$(CURDIR)/.cache/golangci-lint golangci-lint
BPF2GO_CC ?= $(shell command -v clang-18 >/dev/null 2>&1 && echo clang-18 || echo clang)
LLVM_OBJDUMP ?= $(shell command -v llvm-objdump-18 >/dev/null 2>&1 && echo llvm-objdump-18 || echo llvm-objdump)
GOVULNCHECK_VERSION ?= v1.7.0
TESTFLAGS ?=
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
VERSION_NO_V := $(VERSION:v%=%)
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
ARGS ?= --version
LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.revision=$(REVISION)' \
	-X 'main.buildDate=$(BUILD_DATE)'

.PHONY: help check-deps generate verify-bpf-bytecode tidy update-patch update-minor fmt lint test race-test test-integration vulncheck benchmark build build-release run clean

help:
	@printf '%s\n' 'Available targets:'
	@printf '  %-13s %s\n' 'generate' 'regenerate eBPF Go bindings via bpf2go'
	@printf '  %-13s %s\n' 'verify-bpf-bytecode' 'verify required locking and atomic instructions'
	@printf '  %-13s %s\n' 'tidy' 'sync Go module dependencies'
	@printf '  %-13s %s\n' 'update-patch' 'update dependencies (patch only, safe)'
	@printf '  %-13s %s\n' 'update-minor' 'update dependencies (minor + patch)'
	@printf '  %-13s %s\n' 'fmt' 'format Go sources'
	@printf '  %-13s %s\n' 'lint' 'regenerate eBPF bindings and run golangci-lint and go vet'
	@printf '  %-13s %s\n' 'test' 'regenerate eBPF bindings and run all tests (override with TESTFLAGS="...")'
	@printf '  %-13s %s\n' 'race-test' 'regenerate eBPF bindings and run tests with the race detector'
	@printf '  %-13s %s\n' 'test-integration' 'load generated eBPF through the kernel verifier (requires root)'
	@printf '  %-13s %s\n' 'vulncheck' 'regenerate eBPF bindings and scan for reachable vulnerabilities'
	@printf '  %-13s %s\n' 'benchmark' 'run a controlled benchmark (requires IFACE and traffic reference variables)'
	@printf '  %-13s %s\n' 'build' 'build the flowcap binary with version metadata'
	@printf '  %-13s %s\n' 'build-release' 'build release archives for Linux'
	@printf '  %-13s %s\n' 'run' 'build and run flowcap (override with ARGS="...")'
	@printf '  %-13s %s\n' 'clean' 'remove build artifacts'

check-deps:
	@command -v go >/dev/null 2>&1 || { echo "Error: 'go' is required but not found in PATH." >&2; exit 1; }
	@command -v $(BPF2GO_CC) >/dev/null 2>&1 || { echo "Error: '$(BPF2GO_CC)' is required but not found in PATH." >&2; exit 1; }
	@major="$$($(BPF2GO_CC) --version | sed -n '1s/.*version \([0-9][0-9]*\).*/\1/p')"; \
		test -n "$$major" && test "$$major" -ge 18 || { echo "Error: clang 18+ is required." >&2; exit 1; }

generate: check-deps
	BPF2GO_CC=$(BPF2GO_CC) $(GO) run github.com/cilium/ebpf/cmd/bpf2go -go-package main -type flow_key -type flow_stats -cflags "-mcpu=v3 -I/usr/include/$$(uname -m)-linux-gnu" flow flowcap.c

verify-bpf-bytecode: generate
	@command -v $(LLVM_OBJDUMP) >/dev/null 2>&1 || { echo "Error: '$(LLVM_OBJDUMP)' is required." >&2; exit 1; }
	@$(LLVM_OBJDUMP) -d flow_bpfel.o | grep -q 'call 0x5d' || { echo "Missing bpf_spin_lock helper call." >&2; exit 1; }
	@$(LLVM_OBJDUMP) -d flow_bpfel.o | grep -q 'call 0x5e' || { echo "Missing bpf_spin_unlock helper call." >&2; exit 1; }
	@$(LLVM_OBJDUMP) -d flow_bpfel.o | grep -q 'atomic_fetch_add' || { echo "Missing atomic generation increment." >&2; exit 1; }

tidy:
	$(GO) mod tidy

update-patch:
	$(GO) get -u=patch ./...
	$(GO) mod tidy

update-minor:
	$(GO) get -u ./...
	$(GO) mod tidy

fmt:
	gofmt -w .

lint: generate
	$(GOLANGCI_LINT) run ./...
	$(GO) vet ./...

test: generate
	$(GO) test $(TESTFLAGS) ./...

race-test: generate
	$(GO) test -race -short ./...

test-integration: verify-bpf-bytecode
	sudo env "PATH=$(PATH)" "GOCACHE=$(CURDIR)/.cache/go-build" go test -tags=integration -run Integration -v ./...

benchmark:
	@test -n "$(IFACE)" || (echo "usage: make benchmark IFACE=<interface>" >&2; exit 2)
	./scripts/benchmark.sh "$(IFACE)"

# Reachability-aware vulnerability scan (needs generated eBPF objects to load the package).
vulncheck: generate
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

build: generate
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) $(CMD)

build-release: generate
	rm -rf $(RELEASE_TMP)
	mkdir -p $(RELEASE_TMP)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(RELEASE_TMP)/$(APP)_linux_amd64 $(CMD)
	mkdir -p $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_amd64
	cp $(RELEASE_TMP)/$(APP)_linux_amd64 $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_amd64/$(APP)
	cp README.md $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_amd64/README.md
	cp LICENSE $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_amd64/LICENSE
	tar -C $(RELEASE_TMP) -czf $(BIN_DIR)/$(APP)_$(VERSION_NO_V)_linux_amd64.tar.gz $(APP)_$(VERSION_NO_V)_linux_amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(RELEASE_TMP)/$(APP)_linux_arm64 $(CMD)
	mkdir -p $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_arm64
	cp $(RELEASE_TMP)/$(APP)_linux_arm64 $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_arm64/$(APP)
	cp README.md $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_arm64/README.md
	cp LICENSE $(RELEASE_TMP)/$(APP)_$(VERSION_NO_V)_linux_arm64/LICENSE
	tar -C $(RELEASE_TMP) -czf $(BIN_DIR)/$(APP)_$(VERSION_NO_V)_linux_arm64.tar.gz $(APP)_$(VERSION_NO_V)_linux_arm64
	cd $(BIN_DIR) && sha256sum $(APP)_$(VERSION_NO_V)_linux_amd64.tar.gz $(APP)_$(VERSION_NO_V)_linux_arm64.tar.gz > checksums.txt

run: build
	./$(BIN) $(ARGS)

clean:
	rm -rf $(BIN_DIR) .cache $(BPF_OBJECTS)
