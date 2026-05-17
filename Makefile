BINARY := flowcap
BINDIR := bin
RELEASE_TMP := $(BINDIR)/release
GENERATED := flow_bpfel.go flow_bpfel.o flow_bpfeb.go flow_bpfeb.o

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
VERSION_NO_V := $(VERSION:v%=%)
REVISION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.revision=$(REVISION)' \
	-X 'main.buildDate=$(BUILD_DATE)'

.PHONY: all build build-release generate test clean check-deps

all: build

check-deps:
	@command -v go >/dev/null 2>&1 || { echo "Error: 'go' is required but not found in PATH." >&2; exit 1; }
	@command -v clang >/dev/null 2>&1 || { echo "Error: 'clang' is required but not found in PATH." >&2; exit 1; }

generate: check-deps
	go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -type flow_key -type flow_stats -cflags "-I/usr/include/$$(uname -m)-linux-gnu" flow flowcap.c

build: generate
	go build -ldflags "$(LDFLAGS)" -o $(BINARY)

test: generate
	go test ./...

build-release: generate
	rm -rf $(RELEASE_TMP)
	mkdir -p $(RELEASE_TMP)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(RELEASE_TMP)/$(BINARY)_linux_amd64
	mkdir -p $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64
	cp $(RELEASE_TMP)/$(BINARY)_linux_amd64 $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/$(BINARY)
	cp README.md $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/README.md
	cp LICENSE $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_amd64/LICENSE
	tar -C $(RELEASE_TMP) -czf $(BINDIR)/$(BINARY)_$(VERSION_NO_V)_linux_amd64.tar.gz $(BINARY)_$(VERSION_NO_V)_linux_amd64
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(RELEASE_TMP)/$(BINARY)_linux_arm64
	mkdir -p $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64
	cp $(RELEASE_TMP)/$(BINARY)_linux_arm64 $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/$(BINARY)
	cp README.md $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/README.md
	cp LICENSE $(RELEASE_TMP)/$(BINARY)_$(VERSION_NO_V)_linux_arm64/LICENSE
	tar -C $(RELEASE_TMP) -czf $(BINDIR)/$(BINARY)_$(VERSION_NO_V)_linux_arm64.tar.gz $(BINARY)_$(VERSION_NO_V)_linux_arm64
	cd $(BINDIR) && sha256sum $(BINARY)_$(VERSION_NO_V)_linux_amd64.tar.gz $(BINARY)_$(VERSION_NO_V)_linux_arm64.tar.gz > checksums.txt

clean:
	rm -rf $(BINARY) $(BINDIR) $(GENERATED)
