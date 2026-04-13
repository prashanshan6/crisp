# CRISP

A practical subset sum solver for moderate-n, bounded-R instances.

CRISP can solve random subset sum instances of n=1000 with values up to 10^10 on a laptop with under 1.5 GB of RAM in roughly 70 minutes, and can recover actual subset solutions (not just decision answers) via a backward DFS reconstruction walker. These are instances where classical Bellman dynamic programming is infeasible because the target T is too large to materialize as a bit array (~280 GB for T = 2.4 × 10^12).

This is research code from a long-running independent project on subset sum. It is provided as-is for evaluation, benchmarking, and integration into other algorithms or tooling.

## Benchmarks

All runs use n=1000, k=500 (planted), `--limit 10 --mem 1300 --cache-mb 1000`.
Run on WSL2 (Ubuntu) on a laptop. Build phase stops via saturation detection.

| n | R | k | T reached | build time | recon time | build peak RSS | recon peak cache | cache max config | k range found |
|---|---|---|---|---|---|---|---|---|---|
| 1000 | 10^5 | 500 | step 707 | 3.3s | 2.7s | 2.0 MB | 622.9 KB | 1000 MB | 282..286 |
| 1000 | 10^6 | 500 | step 691 | 3.8s | 2.9s | 2.0 MB | 6.3 MB | 1000 MB | 293..296 |
| 1000 | 10^7 | 500 | step 706 | 6.9s | 3.9s | 2.5 MB | 80.9 MB | 1000 MB | 294..298 |
| 1000 | 10^8 | 500 | step 708 | 42.7s | 18.1s | 9.7 MB | 944.5 MB | 1000 MB | 294..299 |
| 1000 | 10^9 | 500 | step 691 | 7.5min | 15.6min | 67.7 MB | 2.96 GB | 3000 MB | 294..298 |
| 1000 | 10^10 | Running... | Running... | Running... | Running... | Running... | Running... | 3000 MB | Running... |

\* At R=10^9 the cache budget (`--cache-mb 1000`) became binding — 607 cache evictions occurred during reconstruction. Smaller cache budgets would still produce correct results but with more disk re-reads.

**Notes on the columns:**
- **build peak RSS** is the peak resident set size of the entire process during the build phase, as reported by `/proc/self/status`. This is the dominant memory cost during build.
- **recon peak cache** is the peak bytes held in the LRU frontier cache during reconstruction, set by `--cache-mb`. The full process RSS during recon is approximately `build peak RSS + recon peak cache` since the cache is the dominant new allocation.
- **k range found** is the cardinality range of the actual subset solutions recovered by the reconstruction walker (which is biased toward small-k solutions via TAKE-first traversal).

R=10^7 and R=10^10 pending; will be added as those runs complete.

## Build

Requires GCC and a POSIX-ish system. Tested on Linux and WSL2.

```
gcc -O3 -march=native -o crisp crisp.c -lm
```

## Quick start

Build a fresh frontier and find 10 solutions for a planted instance:

```
./crisp --n 1000 --R 1000000 --k 500 --recon --limit 10 --mem 2048 --cache-mb 3000

./crisp --n 1000 --R 100000000 --k 500 --recon --limit 10 --mem 2048 --cache-mb 3000

./crisp --n 1000 --R 10000000000 --k 500 --recon --limit 10 --mem 2048 --cache-mb 3000
```

This will:

1. Generate 1000 random items with values up to 10^10
2. Plant a target T as the sum of 500 of them
3. Build the CRISP frontier step by step, saving each step to disk under `frontiers/run_<timestamp>_s<seed>/`
4. Walk the saved frontiers backward to reconstruct exact subsets summing to T
5. Write up to 10 solutions to `solutions.txt`

## Resuming reconstruction

Frontiers from previous runs are preserved on disk. You can re-run reconstruction against them without rebuilding:

```
./crisp --recon-from frontiers/run_<timestamp>_s<seed> --limit 50 --cache-mb 3000
```

You can also override the target T (provided the new target's effective search range fits within the saved frontier's clipping bound):

```
./crisp --recon-from frontiers/run_<timestamp>_s<seed> --T <new_target> --limit 10
```

## Diverse solutions

By default, the reconstruction walker uses a deterministic depth-first traversal that biases toward small-cardinality solutions. Consecutive solutions tend to share most of their items and differ only in the last few — useful for fee minimization but not for true diversity.

Use `--random-order` with different seeds to get solution clusters from different regions of the search space:

```
./crisp --recon-from <run_dir> --random-order --seed 1 --limit 10 --out sols_s1.txt
./crisp --recon-from <run_dir> --random-order --seed 2 --limit 10 --out sols_s2.txt
./crisp --recon-from <run_dir> --random-order --seed 3 --limit 10 --out sols_s3.txt
```

Concatenating the outputs gives a diverse pool. A single run with `--random-order` does not produce diverse solutions within itself; the diversity comes from running multiple seeds.

## Other useful flags

```
--stop-on-target     End the build phase as soon as the target becomes
                     reachable, then proceed to reconstruction. Saves time
                     when you only need a few solutions and don't care
                     about full saturation.

--find-k k1,k2,...   Find solutions at specific cardinalities only.

--cache-mb N         Limit the reconstruction walker's frontier cache to
                     N megabytes. The walker is correct at any cache size
                     but smaller caches mean more disk re-reads.

--mem N              Memory limit (MB) for the build phase. Build halts
                     if RSS exceeds this.

--items-file PATH    Use a specific list of items instead of generating
                     them randomly. One item per line.
```

## How it works

CRISP maintains a frontier of reachable subset sums and expands it one item at a time. The compression that makes this practical comes from an empirical observation about the structure of subset sum frontiers themselves: for almost all item sets — the exception being super-increasing sequences, where each item exceeds the sum of all smaller items — reachable subset sums form dense, tightly clustered regions rather than sparsely scattered values. As the frontier grows, the consecutive differences between reachable sums concentrate into a very small set of unique values, and the distribution of those differences is highly skewed: a few small differences (typically 1, 2, 3) dominate, with rarer larger gaps falling off in what looks empirically like a Zipf-like pattern.

This low-entropy structure is what makes CRISP's compression effective. The frontier is stored as a varint-encoded run-length stream and updated via a streaming merge that operates directly on the encoded representation without ever materializing the underlying bit array. On the instances tested, this achieves compression ratios of roughly two orders of magnitude over a naive bitset.

The other half of CRISP's memory story is offloading. The build phase only needs the *current* frontier in active memory at any one time — the previous step's frontier has already been merged into it. Rather than discarding old frontiers, CRISP writes each step's compressed frontier to disk as soon as it's no longer needed for the build, then frees it from RAM. Reconstruction later reads these per-step files back from disk through an LRU cache with a configurable byte budget (`--cache-mb`), so the walker can access historical frontiers on demand without ever holding all of them in memory at once. The combined effect of compression plus offloading is what allows CRISP to handle bounded-R instances at n=1000, R=10^10 with a peak working set under 1.5 GB of RAM, on a laptop, where classical Bellman dynamic programming would require hundreds of gigabytes for the bitset alone.

Reconstruction uses a backward depth-first walker over the saved per-step frontiers. At each step the walker decides whether the current item was used in the solution by checking whether the residual target is reachable in the previous frontier. The walker is biased toward small-cardinality solutions by trying TAKE before SKIP at every branching node, and supports randomized traversal order via `--random-order` for solution diversity across multiple runs.

The worst-case complexity matches Bellman dynamic programming (O(nT) time, O(T) space if you ignore compression). The empirical performance is much better than the worst case, driven by the diff-alphabet structure that the worst-case analysis does not capture. The exact asymptotic bound under this structure is open. The connection to super-increasing sequences is not coincidental: the original Merkle-Hellman knapsack cryptosystem deliberately used super-increasing sets precisely because they avoid this dense structure, and CRISP works on the regime where item sets do not have that protective property.

## Status

Research code. The algorithm has been developed and refined over a long period as an independent project. The current implementation has been tested across a range of n and R values and has produced verified exact subset solutions for instances at n=1000, R=10^10. It has not been peer-reviewed and the empirical scaling claims have not been independently replicated.

Bug reports and questions welcome via GitHub issues. Contributions welcome but please open an issue first to discuss before sending a pull request, especially for non-trivial changes.

## Author

Prashan P

- LinkedIn: https://www.linkedin.com/in/prashan-p-554424138/
- X: https://x.com/prashanshan6

## License

MIT. See `LICENSE`.

## Citation

If you use this in published work, please cite as:

```
Prashan P. CRISP: A practical subset sum solver for bounded-R instances.
GitHub repository, 2026. https://github.com/prashanshan6/crisp
```
