BINARY := flowcap
GENERATED := flow_bpfel.go flow_bpfel.o flow_bpfeb.go flow_bpfeb.o

.PHONY: all build generate clean check-deps

all: build

check-deps:
	@command -v go >/dev/null 2>&1 || { echo "Error: 'go' is required but not found in PATH." >&2; exit 1; }
	@command -v clang >/dev/null 2>&1 || { echo "Error: 'clang' is required but not found in PATH." >&2; exit 1; }

generate: check-deps
	go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -type flow_key -type flow_stats -cflags "-I/usr/include/$$(uname -m)-linux-gnu" flow flowcap.c

build: generate
	go build -o $(BINARY)

clean:
	rm -f $(BINARY) $(GENERATED)
