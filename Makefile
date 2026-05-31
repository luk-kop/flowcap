APP := flowcap
CMD := .
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP)
RELEASE_TMP := $(BIN_DIR)/release
BPF_OBJECTS := flow_bpfel.o flow_bpfeb.o
GO := GOCACHE=$(CURDIR)/.cache/go-build go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
VERSION_NO_V := $(VERSION:v%=%)
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
ARGS ?= --version
LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.revision=$(REVISION)' \
	-X 'main.buildDate=$(BUILD_DATE)'

.PHONY: help check-deps generate tidy update-patch update-minor fmt test build build-release run clean

help:
	@printf '%s\n' 'Available targets:'
	@printf '  %-13s %s\n' 'generate' 'regenerate eBPF Go bindings via bpf2go'
	@printf '  %-13s %s\n' 'tidy' 'sync Go module dependencies'
	@printf '  %-13s %s\n' 'update-patch' 'update dependencies (patch only, safe)'
	@printf '  %-13s %s\n' 'update-minor' 'update dependencies (minor + patch)'
	@printf '  %-13s %s\n' 'fmt' 'format Go sources'
	@printf '  %-13s %s\n' 'test' 'regenerate eBPF bindings and run all tests'
	@printf '  %-13s %s\n' 'build' 'build the flowcap binary with version metadata'
	@printf '  %-13s %s\n' 'build-release' 'build release archives for Linux'
	@printf '  %-13s %s\n' 'run' 'build and run flowcap (override with ARGS="...")'
	@printf '  %-13s %s\n' 'clean' 'remove build artifacts'

check-deps:
	@command -v go >/dev/null 2>&1 || { echo "Error: 'go' is required but not found in PATH." >&2; exit 1; }
	@command -v clang >/dev/null 2>&1 || { echo "Error: 'clang' is required but not found in PATH." >&2; exit 1; }

generate: check-deps
	$(GO) run github.com/cilium/ebpf/cmd/bpf2go -go-package main -type flow_key -type flow_stats -cflags "-I/usr/include/$$(uname -m)-linux-gnu" flow flowcap.c

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

test: generate
	$(GO) test ./...

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
