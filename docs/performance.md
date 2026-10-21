[← Documentation](../README.md#documentation) · Previous: [Agent API](api.md) · Next: [Tested behaviour →](testing.md)

# Memory and performance

## Memory: built not to grow

Log agents that grow with log volume end up competing with the applications they watch. In grepalert, every structure that could grow with log volume has a hard limit:

| Concern | How grepalert bounds it |
|---|---|
| Reading lines | One fixed 32 KB read buffer per file, reused. Lines that don't match cause **0 allocations** (`go test -bench . ./internal/agent`). |
| Huge or binary lines | Each line is cut at `max_line_bytes` (16 KB). The agent never buffers a whole line past that. |
| Suppression state | An entry is freed when its window closes. There is a hard cap of 10,000 keys; past that, new keys share one overflow bucket. |
| Alert storms / slow webhooks | A bounded queue (`queue_size`) and a fixed set of workers. When the queue is full, alerts are **dropped and counted** rather than queued in memory. |
| Event log | A fixed-size ring buffer (`event_buffer`). |
| Rule reloads | Rules are compiled once and swapped atomically. Tailers and suppression state for removed rules are released. |
| Go runtime | `memory_limit` (64 MiB by default) sets the GC soft limit. The dashboard shows heap, OS memory, GC count, and goroutines for each agent. |

Soak test: 1,000,000 lines with a unique `group_by` value on every line (the worst case for suppression). Heap stayed between 3 and 5 MB, process memory stayed at about 26 MB, the goroutine count did not change, and suppression state went back to 0 once the windows closed.


## Performance with multi-GB logs

Measured on an i5-13400F with 4 rules per line, one of them `(?i)panic|fatal|segfault`:

| Test | Result |
|---|---|
| Start on an existing 5 GB file | Tailing from its end in 164 ms. File size does not matter, because the agent seeks to the end. |
| Read a whole 5 GB file (22.5M lines, the worst-case catch-up) | **18 s, ~310 MB/s**, process memory 11–17 MB |
| Live tail of a log written at 100 MB/s for 60 s (6 GB), rotating every 2 GB | Kept up. All 27.0M lines were read, the read position finished exactly at the end of the file, and memory was ~17 MB. |
| 10 VMs, each writing 10 MB/s and rotating at 1 GB, all in one dashboard group, for 3 min | Every agent kept up and read to the exact end of its file. Each used 18–22 MB. A rules push to all 10 under load took 560 ms; the dashboard overview took ≤ 72 ms. |

**Why case-insensitive rules stay fast.** Go's regexp engine is slow on case-insensitive alternations such as `(?i)panic|fatal`, at about 8 µs per line. So each rule first gets a *literal prefilter*: the plain strings at least one of which must appear in any match (`panic`, `fatal`, …). The agent checks those with a fast substring search and runs the regexp only on lines that pass, which brings the cost down to ~0.2 µs per line. The prefilter never skips a line the regexp would match: this is covered by a randomized cross-check over 3.6M lines and by fuzzing.

To get the most out of it, give rules a literal anchor where you can. `ERROR code=\w+` is fast. A rule with no literal text at all, such as `\d{3}ms$`, has to run the regexp on every line.

### One agent, many files

An agent does not start one goroutine per file. A small pool of reader workers (`read_workers`, 4 by default) polls all files:
- **Busy files** are checked every `poll_interval` (500 ms).
- **Idle files** back off to `idle_poll_interval` (2 s). This bounds how late the first line after a quiet period is noticed.
- **Backlogs** are read in turns of at most 4 MB, so a file with a large backlog cannot delay alerts on the others.
- **Stopping** gives every file a final read.

Measured with one agent in a container with a 64 MB memory limit and 4 rules:

| Files | Load | Result |
|---|---|---|
| 1 / 4 / 8 / 16 | Backlog of 1–8 GB, read from the start | 168 / 683 / 673 / 940 MB/s. CPU stays at about 4 cores (`read_workers`), and every file is read to the exact last byte. |
| 100 | 1 MB/s each (100 MB/s total), live | Kept up, at ~40% of one core and 11 MB of container memory |
| 500 | 0.1 MB/s each, live | Kept up, at ~45% CPU; 23 goroutines; 13 MB of container memory |
| 500 | idle | **1.3% CPU**, 2 GC runs per 10 s |

Raise `read_workers` to catch up faster on many files at once. It scales linearly up to the number of cores; with 8 cores, 8 files were read at 1.3 GB/s. Lower it to protect the applications running on the same VM.

### Load-test your own setup

[examples/loadtest](../examples/loadtest/compose.yaml) runs N simulated VMs. Each one runs `loadgen`, which writes realistic logs at a set rate with rotation, next to an agent. A dashboard and a webhook sink are included.

```bash
cd examples/loadtest
LOG_RATE=20MB docker compose up -d --build --scale vm=10
```

Then connect the VMs (`http://grepalert-loadtest-vm-N:9300`, token `loadtest-token`) in the dashboard at http://localhost:9410 (`admin` / `loadtest`). On a real VM you can also run `loadgen` alone to see what an agent can sustain:

```bash
go run ./examples/loadtest/loadgen -out /tmp/app.log -rate 50MB -rotate 1GB
```
