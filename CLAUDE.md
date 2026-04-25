# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

coolbpf is an eBPF development platform by Alibaba Cloud that wraps libbpf for simplified BPF program development. It has three main components:

1. **libcoolbpf** (C) — Core library wrapping libbpf skeleton lifecycle (open/load/attach/destroy) with convenience macros
2. **libprofiler** (Rust) — Profiling library (perf sampling, stack symbolization, heatmap) statically linked into libcoolbpf.so
3. **AgentSight** (Rust) — Zero-instrumentation LLM agent observability tool using eBPF to capture SSL/TLS traffic and process behavior

## Build Commands

### libcoolbpf (C library)
```bash
mkdir -p build && cd build && cmake .. && make install
# With tests:   cmake -DBUILD_TESTING=on ..
# With examples: cmake -DBUILD_EXAMPLE=on ..
# Quick install: ./install.sh
# Uninstall:    ./uninstall.sh
```

CMake options: `BUILD_TESTING`, `BUILD_EXAMPLE`, `BUILD_LCC`, `ENABLE_GCOV`, `ENABLE_ASAN`, `ENABLE_PROFILE` (default ON), `ENABLE_STATIC_LINK_ELF`

### AgentSight (Rust binary)
```bash
cd src/agentsight
make build-all          # Build frontend + Rust binary
# Or manually:
cd dashboard && npm install && npm run build:embed && cd ..
cargo build --release
```

### Running tests
```bash
# C tests (criterion framework, requires -DBUILD_TESTING=on)
cd build && ctest

# Rust tests
cd src/agentsight && cargo test
cd src/profiler && cargo test
```

## Architecture

### coolbpf library pattern
- BPF programs are `.bpf.c` files compiled with `clang -target bpf`
- `genskel()` CMake macro compiles BPF C → BPF object → skeleton header via `bpftool gen skeleton`
- Userspace code includes `.skel.h` and uses `coolbpf_object_new(skel)` or `coolbpf_object_open(skel)` macros
- `coolbpf_object` struct with `preload`/`preattach` callback function pointers
- Dual conditional compilation: headers used in both BPF (`#ifdef __VMLINUX_H__`) and userspace contexts
- Architecture-specific `vmlinux.h` in `arch/x86_64/` and `arch/aarch64/`

### Profiler integration
- Rust `cdylib` crate built via `cargo build -r` from CMake
- Statically linked into `libcoolbpf.so` using `WHOLE_ARCHIVE`

### AgentSight data pipeline
```
eBPF Probes → Event → Parser → ParsedMessage → Aggregator → AggregatedResult
                                                               ↓
                                                         Analyzer → AnalysisResult
                                                               ↓
                                                    GenAIBuilder → GenAISemanticEvent → Storage
```
- eBPF probes capture kernel events via ring buffer: sslsniff, proctrace, procmon, filewatch
- Multi-stage processing pipeline with typed event flow
- Storage: SQLite (local) + Alibaba Cloud SLS (cloud)
- HTTP API server (actix-web) with embedded React dashboard
- `build.rs` generates eBPF skeletons via `libbpf-cargo` and C bindings via `cbindgen`

### eNetSTL kernel module
- XDP BPF kfuncs library (fasthash, CRC, xxhash) in `bpf_kernel_modules/eNetSTL/`
- Build: `cd bpf_kernel_modules/eNetSTL && make` (use `make LLVM=1` if kernel was built with clang)

## Key Dependencies

- C: libbpf (bundled in `third/`), libelf, zlib, clang/llvm >= 11
- Rust: libbpf-rs, actix-web, rusqlite (bundled), openssl (vendored), capstone, symbolic-demangle
- Runtime: Linux kernel >= 5.8 (BTF support), Rust >= 1.80

## AgentSight CLI

```bash
sudo agentsight trace              # Start eBPF tracing (requires root)
agentsight serve                   # API server + Dashboard (http://127.0.0.1:7396)
agentsight token                   # Query token consumption
agentsight audit                   # Query audit events
agentsight discover                # Discover running AI agents
agentsight interruption list       # List interruption events
```

AgentSight has detailed documentation in `src/agentsight/AGENTS.md` and `src/agentsight/docs/`.
