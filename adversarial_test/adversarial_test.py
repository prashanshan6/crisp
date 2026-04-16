#!/usr/bin/env python3
"""
adversarial_test.py
-------------------
Runs adversarial subset sum instances through CRISP.

Default: n=1000, R=10^6, T=allsum//2, --limit 5 solutions per case.
Results appended to adversarial_results.jsonl (one JSON object per line).

Usage (from any shell, auto-spawns under WSL on Windows):
  python adversarial_test.py [--n N] [--R R] [--limit L] [--crisp PATH]
  python adversarial_test.py --items "3,7,11,15,20,25" --T 30   # single custom run
"""

import argparse
import json
import math
import os
import random
import subprocess
import sys
import time
from pathlib import Path

# All default paths are relative to this script's directory so the script
# works correctly regardless of the working directory it is invoked from.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Auto-spawn under WSL when invoked from Windows Python.
# The crisp binary is a Linux ELF; it must run inside WSL.
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    def _win_to_wsl(path):
        """Convert C:\\foo\\bar  ->  /mnt/c/foo/bar"""
        path = os.path.abspath(path)
        drive = path[0].lower()
        rest  = path[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"

    wsl_script = _win_to_wsl(os.path.abspath(__file__))
    wsl_cwd    = _win_to_wsl(os.path.dirname(os.path.abspath(__file__)))
    args_q = " ".join(f"'{a}'" for a in sys.argv[1:])
    cmd = ["wsl.exe", "bash", "-c",
           f"cd '{wsl_cwd}' && python3 '{wsl_script}' {args_q}"]
    sys.exit(subprocess.run(cmd).returncode)

# ---------------------------------------------------------------------------
# Adversarial item generators
# ---------------------------------------------------------------------------

def gen_random_uniform(n, R, seed=42):
    """Baseline: uniform random items in [1, R]."""
    rng = random.Random(seed)
    return [rng.randint(1, R) for _ in range(n)]

def gen_random_uniform_2(n, R, seed=137):
    """Second random baseline with a different seed."""
    rng = random.Random(seed)
    return [rng.randint(1, R) for _ in range(n)]

def gen_arithmetic(n, R):
    """Arithmetic progression: evenly spaced across [1, R].
    Dense-structure case — CRISP's compression should work well here."""
    step = max(1, (R - 1) // (n - 1))
    return [1 + i * step for i in range(n)]

def gen_geometric(n, R):
    """Geometric progression from 1 to R.
    Sparse at the high end; tests frontier sparsity at large values."""
    ratio = R ** (1.0 / (n - 1))
    items = []
    v = 1.0
    for _ in range(n):
        items.append(max(1, min(R, round(v))))
        v *= ratio
    return items

def gen_powers_of_two_cycling(n, R):
    """Items cycling through powers of 2 up to R.
    Highly structured; many identical values → very compressible frontier."""
    max_exp = int(math.log2(R))
    return [1 << (i % (max_exp + 1)) for i in range(n)]

def gen_all_equal(n, R):
    """All items identical.
    T = n//2 * val is trivially achievable — tests easy-case performance."""
    val = R // 2
    return [val] * n

def gen_near_max(n, R, seed=99):
    """All items clustered in [R-100, R].
    Very small diff alphabet — should compress extremely well."""
    rng = random.Random(seed)
    lo = max(1, R - 100)
    return [rng.randint(lo, R) for _ in range(n)]

def gen_near_one(n, R, seed=77):
    """All items in [1, 100] — tiny values.
    T = allsum//2 is small; tests low-T regime."""
    rng = random.Random(seed)
    return [rng.randint(1, min(R, 100)) for _ in range(n)]

def gen_two_clusters(n, R, seed=55):
    """Bimodal: half near R/4, half near 3R/4.
    Tests gapped frontier structure."""
    rng = random.Random(seed)
    half = n // 2
    lo_center = R // 4
    hi_center = 3 * R // 4
    spread = max(1, R // 200)
    a = [max(1, min(R, rng.randint(lo_center - spread, lo_center + spread)))
         for _ in range(half)]
    b = [max(1, min(R, rng.randint(hi_center - spread, hi_center + spread)))
         for _ in range(n - half)]
    return a + b

def gen_large_gcd(n, R, seed=33):
    """All items are multiples of a large GCD (R//100).
    If T is not a multiple of GCD, no solution exists — tests infeasibility."""
    rng = random.Random(seed)
    g = R // 100
    return [g * rng.randint(1, 100) for _ in range(n)]

def gen_fibonacci_capped(n, R):
    """Fibonacci sequence, values capped at R (cycling back when exceeded).
    Exponential growth until saturation; tests mixed sparsity."""
    items = []
    a, b = 1, 1
    for _ in range(n):
        items.append(a)
        a, b = b, a + b
        if a > R:
            a, b = 1, 1  # restart the sequence when it exceeds R
    return items

def gen_primes(n, R):
    """First n primes up to R (with cycling if needed).
    Primes have irregular spacing — relatively high-entropy diffs."""
    sieve = bytearray([1]) * (R + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(R ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    primes = [i for i in range(2, R + 1) if sieve[i]]
    if len(primes) >= n:
        return primes[:n]
    return (primes * (n // len(primes) + 2))[:n]

def gen_consecutive_small(n, R):
    """Items = 1, 2, ..., n (ignores R, all tiny).
    Ultra-dense frontier: maximum possible reachable sums for given range.
    T = n*(n+1)/4 when divisible."""
    return list(range(1, n + 1))

def gen_few_distinct(n, R, seed=21):
    """n items sampled from only 5 distinct values spread across [1, R].
    Tests frontier behavior with very low item diversity."""
    rng = random.Random(seed)
    pivots = [R // 5, 2 * R // 5, R // 2, 3 * R // 4, R]
    return [rng.choice(pivots) for _ in range(n)]

def gen_one_large_spike(n, R, seed=17):
    """One item = R, remaining n-1 items drawn from [1, R//100].
    T = allsum//2 will require carefully using the spike or not."""
    rng = random.Random(seed)
    rest = [rng.randint(1, max(1, R // 100)) for _ in range(n - 1)]
    return rest + [R]

def gen_super_increasing_reset(n, R):
    """Attempts super-increasing growth (each > sum of previous),
    resets to 1 when it would exceed R.
    Partial super-increasing segments stress frontier sparsity."""
    items = []
    running_sum = 0
    for _ in range(n):
        next_val = running_sum + 1
        if next_val > R:
            running_sum = 0
            next_val = 1
        items.append(next_val)
        running_sum += next_val
    return items

def gen_random_odd_total(n, R, seed=88):
    """Random items engineered so allsum is odd → T = allsum//2 has no exact solution.
    Tests solver behavior when T is not achievable."""
    rng = random.Random(seed)
    items = [rng.randint(1, R) for _ in range(n)]
    total = sum(items)
    if total % 2 == 0:
        # Flip last item by ±1 to make total odd
        items[-1] = max(1, items[-1] + 1) if items[-1] < R else items[-1] - 1
    return items

# ---------------------------------------------------------------------------
# Registry of all adversarial cases
# ---------------------------------------------------------------------------

CASES = [
    ("random_uniform",          lambda n, R: gen_random_uniform(n, R)),
    ("random_uniform_seed2",    lambda n, R: gen_random_uniform_2(n, R)),
    ("arithmetic_progression",  gen_arithmetic),
    ("geometric_progression",   gen_geometric),
    ("powers_of_two_cycling",   gen_powers_of_two_cycling),
    ("all_equal",               gen_all_equal),
    ("near_max_clustered",      gen_near_max),
    ("near_one_clustered",      gen_near_one),
    ("two_clusters_bimodal",    gen_two_clusters),
    ("large_gcd",               gen_large_gcd),
    ("fibonacci_capped",        gen_fibonacci_capped),
    ("primes",                  gen_primes),
    ("consecutive_1_to_n",      gen_consecutive_small),
    ("few_distinct_values",     gen_few_distinct),
    ("one_large_spike",         gen_one_large_spike),
    ("super_increasing_reset",  gen_super_increasing_reset),
    ("random_odd_total",        gen_random_odd_total),
]

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def parse_solutions(path):
    """Parse CRISP solutions file.
    Each line is:  k:T:item1,item2,...
    Returns list of dicts with keys: k, T, items.
    """
    sols = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: k:T:i1,i2,...
                parts = line.split(":", 2)
                if len(parts) == 3:
                    k_val  = int(parts[0])
                    t_val  = int(parts[1])
                    items  = list(map(int, parts[2].split(",")))
                    sols.append({"k": k_val, "T": t_val, "items": items})
                else:
                    # Fallback: plain space-separated values
                    vals = list(map(int, line.split()))
                    if vals:
                        sols.append({"k": len(vals), "T": sum(vals), "items": vals})
    except FileNotFoundError:
        pass
    return sols


def run_case(name, items, T_override, crisp_bin, limit, frontier_base, out_dir, timeout=300):
    """Run one CRISP instance. Returns a dict with all recorded data."""
    allsum = sum(items)
    T = T_override if T_override is not None else allsum // 2

    items_str = ",".join(str(v) for v in items)
    out_path = os.path.join(out_dir, f"{name}_solutions.txt")
    fdir = os.path.join(frontier_base, name)
    os.makedirs(fdir, exist_ok=True)

    cmd = [
        crisp_bin,
        "--items", items_str,
        "--T", str(T),
        "--recon",
        "--limit", str(limit),
        "--out", out_path,
        "--frontier-dir", fdir,
    ]

    record = {
        "case":        name,
        "n":           len(items),
        "allsum":      allsum,
        "T":           T,
        "allsum_odd":  allsum % 2 == 1,
        "items":       items,
        "cmd":         " ".join(cmd),
        "exit_code":   None,
        "stdout":      "",
        "stderr":      "",
        "elapsed_s":   None,
        "solutions":   [],
        "num_solutions": 0,
        "error":       None,
    }

    print(f"\n{'='*60}")
    print(f"  CASE: {name}")
    print(f"  n={len(items)}  allsum={allsum}  T={T}  odd={allsum%2==1}")
    print(f"{'='*60}")
    sys.stdout.flush()

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - t0
        record["exit_code"] = proc.returncode
        record["stdout"]    = proc.stdout
        record["stderr"]    = proc.stderr
        record["elapsed_s"] = round(elapsed, 3)

        # Echo live to terminal
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print("[stderr]", proc.stderr, end="", file=sys.stderr)

        # Parse solutions written to disk
        sols = parse_solutions(out_path)
        record["solutions"]     = sols
        record["num_solutions"] = len(sols)

        # Verify each solution sums to T
        wrong = [s for s in sols if s["T"] != T or sum(s["items"]) != T]
        record["verify_ok"] = len(wrong) == 0
        if wrong:
            record["verify_failures"] = len(wrong)
            print(f"  [WARN] {len(wrong)} solutions failed sum check!")

        print(f"  -> {len(sols)} solutions found in {elapsed:.2f}s  verify_ok={record['verify_ok']}")

    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - t0
        record["elapsed_s"] = round(elapsed, 3)
        record["error"] = "timeout after 300s"
        print(f"  [TIMEOUT] after {elapsed:.1f}s")
    except Exception as e:
        elapsed = time.perf_counter() - t0
        record["elapsed_s"] = round(elapsed, 3)
        record["error"] = str(e)
        print(f"  [ERROR] {e}")

    return record


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Adversarial CRISP test harness")
    ap.add_argument("--n",      type=int,   default=1000,         help="Number of items (default 1000)")
    ap.add_argument("--R",      type=int,   default=1_000_000,    help="Max item value (default 10^6)")
    ap.add_argument("--limit",   type=int,  default=5,            help="Max solutions per case (default 5)")
    ap.add_argument("--timeout", type=int,  default=300,          help="Per-case timeout in seconds (default 300)")
    ap.add_argument("--crisp",  type=str,
                    default=os.path.join(_SCRIPT_DIR, "..", "crisp"),
                    help="Path to crisp binary (default: ../crisp relative to script)")
    ap.add_argument("--out",    type=str,
                    default=os.path.join(_SCRIPT_DIR, "adversarial_results.jsonl"),
                    help="Output JSONL file")
    ap.add_argument("--out-dir", type=str,
                    default=os.path.join(_SCRIPT_DIR, "runs"),
                    help="Directory for per-case solution files")
    ap.add_argument("--frontier-dir", type=str,
                    default=os.path.join(_SCRIPT_DIR, "frontiers"),
                    help="Base dir for frontier files")
    ap.add_argument("--cases",  type=str,   default=None,
                    help="Comma-separated list of case names to run (default: all)")
    # Single custom run
    ap.add_argument("--items",  type=str,   default=None,
                    help="Inline comma-separated items for a single custom run")
    ap.add_argument("--T",      type=int,   default=None,
                    help="Override T for custom --items run (default: allsum//2)")
    ap.add_argument("--name",   type=str,   default="custom",
                    help="Case name when using --items")
    args = ap.parse_args()

    os.makedirs(args.out_dir,       exist_ok=True)
    os.makedirs(args.frontier_dir,  exist_ok=True)

    results = []

    # --- Custom single run ---
    if args.items is not None:
        items = [int(x.strip()) for x in args.items.split(",") if x.strip()]
        rec = run_case(
            name=args.name,
            items=items,
            T_override=args.T,
            crisp_bin=args.crisp,
            limit=args.limit,
            frontier_base=args.frontier_dir,
            out_dir=args.out_dir,
            timeout=args.timeout,
        )
        results.append(rec)
    else:
        # --- Adversarial sweep ---
        selected = None
        if args.cases:
            selected = set(c.strip() for c in args.cases.split(","))

        case_registry = [(name, fn) for name, fn in CASES
                         if selected is None or name in selected]

        print(f"Running {len(case_registry)} adversarial cases")
        print(f"n={args.n}  R={args.R}  limit={args.limit}")
        print(f"Output: {args.out}")

        for name, fn in case_registry:
            items = fn(args.n, args.R)
            rec = run_case(
                name=name,
                items=items,
                T_override=None,
                crisp_bin=args.crisp,
                limit=args.limit,
                frontier_base=args.frontier_dir,
                out_dir=args.out_dir,
                timeout=args.timeout,
            )
            rec["R"] = args.R
            results.append(rec)

            # Append incrementally so progress is saved on early exit
            with open(args.out, "a") as f:
                f.write(json.dumps(rec) + "\n")

    # --- Final summary table ---
    print(f"\n{'='*60}")
    print(f"  SUMMARY  ({len(results)} cases)")
    print(f"{'='*60}")
    header = f"{'CASE':<30}  {'N':>5}  {'T':>14}  {'SOLS':>4}  {'OK':>3}  {'TIME':>7}"
    print(header)
    print("-" * len(header))
    for rec in results:
        ok  = "yes" if rec.get("verify_ok", False) else ("err" if rec.get("error") else "no")
        t   = f"{rec['elapsed_s']:.2f}s" if rec["elapsed_s"] else "?"
        print(f"{rec['case']:<30}  {rec['n']:>5}  {rec['T']:>14}  "
              f"{rec['num_solutions']:>4}  {ok:>3}  {t:>7}")

    # Write final summary
    if results:
        summary_path = args.out.replace(".jsonl", "_summary.txt")
        with open(summary_path, "w") as f:
            f.write(f"Adversarial CRISP test  n={args.n}  R={args.R}\n")
            f.write(f"{'='*60}\n")
            f.write(f"{'CASE':<30}  {'N':>5}  {'T':>14}  {'SOLS':>4}  {'OK':>3}  {'TIME':>7}  {'NOTES'}\n")
            f.write(f"{'-'*80}\n")
            for rec in results:
                ok    = "yes" if rec.get("verify_ok", False) else ("err" if rec.get("error") else "no")
                t     = f"{rec['elapsed_s']:.2f}s" if rec["elapsed_s"] else "?"
                notes = []
                if rec.get("allsum_odd"):
                    notes.append("odd_total")
                if rec.get("error"):
                    notes.append(rec["error"])
                f.write(f"{rec['case']:<30}  {rec['n']:>5}  {rec['T']:>14}  "
                        f"{rec['num_solutions']:>4}  {ok:>3}  {t:>7}  "
                        f"{', '.join(notes)}\n")
        print(f"\nSummary written to {summary_path}")

    print(f"Full results in {args.out}")


if __name__ == "__main__":
    main()
