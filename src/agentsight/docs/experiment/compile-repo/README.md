# compile repo



## env

```
# claude --version
1.0.62 (Claude Code)
```

on https://github.com/eunomia-bpf/bpf-developer-tutorial

time git submodule update --init --recursive && cd src && make -j8

## Without agentsight

```
(base) root@gpu01:~/yunwei37# python3 /root/yunwei37/build_benchmark.py
=== BPF Developer Tutorial Build Benchmark ===

Phase 1: Cloning repositories...
Cloning repository to /root/yunwei37/bpf-tutorial-1...
Successfully cloned to /root/yunwei37/bpf-tutorial-1
Cloning repository to /root/yunwei37/bpf-tutorial-2...
Successfully cloned to /root/yunwei37/bpf-tutorial-2
Cloning repository to /root/yunwei37/bpf-tutorial-3...
Successfully cloned to /root/yunwei37/bpf-tutorial-3

Phase 1 completed: All repositories cloned.

Phase 2: Building repositories and measuring time...

Build 1/3:
Building in /root/yunwei37/bpf-tutorial-1...
Build completed in 92.05 seconds

Build 2/3:
Building in /root/yunwei37/bpf-tutorial-2...
Build completed in 92.75 seconds

Build 3/3:
Building in /root/yunwei37/bpf-tutorial-3...
Build completed in 92.39 seconds

Phase 2 completed: All builds finished.

=== Build Time Results ===
Build 1: 92.05 seconds
Build 2: 92.75 seconds
Build 3: 92.39 seconds

Average build time: 92.40 seconds
Standard deviation: 0.35 seconds
Min time: 92.05 seconds
Max time: 92.75 seconds

Phase 3: Cleaning up...
Cleaning up /root/yunwei37/bpf-tutorial-1...
Removed /root/yunwei37/bpf-tutorial-1
Cleaning up /root/yunwei37/bpf-tutorial-2...
Removed /root/yunwei37/bpf-tutorial-2
Cleaning up /root/yunwei37/bpf-tutorial-3...
Removed /root/yunwei37/bpf-tutorial-3

Phase 3 completed: All directories cleaned up.

=== Benchmark completed ===
```

## With agentsight

```
(base) root@gpu01:~/yunwei37# python3 /root/yunwei37/build_benchmark.py
=== BPF Developer Tutorial Build Benchmark ===

Phase 1: Cloning repositories...
Cloning repository to /root/yunwei37/bpf-tutorial-1...
Successfully cloned to /root/yunwei37/bpf-tutorial-1
Cloning repository to /root/yunwei37/bpf-tutorial-2...
Successfully cloned to /root/yunwei37/bpf-tutorial-2
Cloning repository to /root/yunwei37/bpf-tutorial-3...
Successfully cloned to /root/yunwei37/bpf-tutorial-3

Phase 1 completed: All repositories cloned.

Phase 2: Building repositories and measuring time...

Build 1/3:
Building in /root/yunwei37/bpf-tutorial-1...
Build completed in 91.79 seconds

Build 2/3:
Building in /root/yunwei37/bpf-tutorial-2...
Build completed in 93.55 seconds

Build 3/3:
Building in /root/yunwei37/bpf-tutorial-3...
Build completed in 92.81 seconds

Phase 2 completed: All builds finished.

=== Build Time Results ===
Build 1: 91.79 seconds
Build 2: 93.55 seconds
Build 3: 92.81 seconds

Average build time: 92.72 seconds
Standard deviation: 0.88 seconds
Min time: 91.79 seconds
Max time: 93.55 seconds

Phase 3: Cleaning up...
Cleaning up /root/yunwei37/bpf-tutorial-1...
Removed /root/yunwei37/bpf-tutorial-1
Cleaning up /root/yunwei37/bpf-tutorial-2...
Removed /root/yunwei37/bpf-tutorial-2
Cleaning up /root/yunwei37/bpf-tutorial-3...
Removed /root/yunwei37/bpf-tutorial-3

Phase 3 completed: All directories cleaned up.

=== Benchmark completed ===
```

## Analysis

Here's the analysis of full repo compilation times:

* **Without AgentSight**: \~92.40 seconds average
* **With AgentSight**: \~92.72 seconds average
* **Absolute overhead**: \~0.32 seconds
* **Relative overhead**: \~0.35%

AgentSight introduces only a negligible compile-time overhead during full repository builds.
