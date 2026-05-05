#!/usr/bin/env python3
"""
analyze_rtt.py - Post-process RTT CSV produced by fnp_node_perf_demo tx-rtt mode.

CSV format (header + data rows):
  seq,rtt_ns

Trims the first and last trim_s * kpps * 1000 records by index (arrival order),
then computes avg / min / p50 / p95 / p99 / max in microseconds.

Usage:
  analyze_rtt.py <rtt.csv> <kpps> [trim_s=5]
"""

import sys


def percentile(sorted_data, pct):
    n = len(sorted_data)
    if n == 0:
        return 0.0
    pos = (pct / 100.0) * (n - 1)
    lo = int(pos)
    hi = min(lo + 1, n - 1)
    f = pos - lo
    return sorted_data[lo] * (1.0 - f) + sorted_data[hi] * f


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <rtt.csv> <kpps> [trim_s=5]", file=sys.stderr)
        sys.exit(1)

    path   = sys.argv[1]
    kpps   = float(sys.argv[2])
    trim_s = int(sys.argv[3]) if len(sys.argv) > 3 else 5

    pps        = kpps * 1000.0
    trim_count = int(pps * trim_s)

    rtt_ns_list = []
    total_lines = 0

    with open(path, newline='') as f:
        next(f)  # skip header line
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            try:
                parts = line.split(',', 1)
                rtt_ns = int(parts[1])
                rtt_ns_list.append(rtt_ns)
            except (ValueError, IndexError):
                pass

    print(f"total_records={total_lines}  valid={len(rtt_ns_list)}  "
          f"trim_head={trim_count}  trim_tail={trim_count}")

    if not rtt_ns_list:
        print("ERROR: no valid data", file=sys.stderr)
        sys.exit(1)

    n     = len(rtt_ns_list)
    start = min(trim_count, n)
    end   = max(start, n - trim_count)
    trimmed = rtt_ns_list[start:end]

    if not trimmed:
        print("ERROR: no data after trim (trim_s too large?)", file=sys.stderr)
        sys.exit(1)

    trimmed_sorted = sorted(trimmed)
    m = len(trimmed_sorted)

    avg_us = sum(trimmed_sorted) / m / 1000.0
    p50_us = percentile(trimmed_sorted, 50)  / 1000.0
    p95_us = percentile(trimmed_sorted, 95)  / 1000.0
    p99_us = percentile(trimmed_sorted, 99)  / 1000.0
    min_us = trimmed_sorted[0]               / 1000.0
    max_us = trimmed_sorted[-1]              / 1000.0

    print(f"trimmed_samples={m}")
    print(f"avg_us={avg_us:.3f}")
    print(f"min_us={min_us:.3f}")
    print(f"p50_us={p50_us:.3f}")
    print(f"p95_us={p95_us:.3f}")
    print(f"p99_us={p99_us:.3f}")
    print(f"max_us={max_us:.3f}")


if __name__ == "__main__":
    main()
