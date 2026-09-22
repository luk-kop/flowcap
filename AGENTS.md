# Repository Guidelines

## Project Structure & Module Organization

Flowcap is a single-package Go application with an eBPF data plane. Go runtime and CLI code lives at the root; `flowcap.c` implements in-kernel packet parsing and aggregation. Tests sit beside their targets as `*_test.go`; `bpf_integration_test.go` covers Linux/kernel integration. Design and operational notes live in `docs/`, while `scripts/benchmark.sh` drives controlled benchmarks.

`flow_bpfel.go` and `flow_bpfeb.go` are generated, committed bindings. Regenerate them with `make generate`; do not edit them manually. Generated `.o` files, caches, and binaries are ignored build artifacts.

## Build, Test, and Development Commands

- `make build` regenerates eBPF bindings and writes `bin/flowcap` with version metadata.
- `make fmt` applies `gofmt` to Go sources.
- `make lint` runs binding generation, `golangci-lint`, and `go vet`.
- `make test TESTFLAGS="-v -short"` runs the unit suite as CI does.
- `make race-test` runs short tests with the race detector.
- `make test-integration` verifies bytecode and exercises real eBPF maps and TCX; it requires root and Linux kernel 6.6+.

Use `make run ARGS="--version"` to build and run locally. `make help` lists maintenance and release targets.

Development requires Go 1.27+, clang/LLVM 18+, and Linux headers.

## Coding Style & Naming Conventions

Use standard Go formatting and idioms: tabs from `gofmt`, short package-local names, and exported identifiers only when necessary. Keep Go filenames lowercase. Follow existing C `snake_case` and preserve Go/C struct layouts and integer widths shared through bpf2go. Run `make fmt` and `make lint` before submitting.

## Testing Guidelines

Use Go's `testing` package. Name tests `TestBehavior` and prefer table-driven subtests. Add unit tests beside changed logic and integration tests behind the `integration` build tag when kernel loading or TCX behavior matters. There is no fixed coverage threshold; cover regressions and error paths. Run unit and race tests locally, plus integration tests when possible.

## Commit & Pull Request Guidelines

Commits follow Conventional Commits, enforced by the commit-msg hook: `feat: add exporter option` or `fix: preserve flow counters`. Keep commits focused. Pull requests should explain the change, operational impact, and verification; link issues and update `README.md` or `docs/` when flags, metrics, deployment, or export semantics change. Include representative output for logging or metrics changes.

## Security & Configuration

Never commit credentials, private keys, captured traffic, or host-specific configuration. Use isolated interfaces for privileged checks; do not attach development builds to production interfaces. Install the pre-commit hooks to catch secrets, formatting errors, lint failures, and dependency issues.
