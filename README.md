# CRISP

A practical subset sum solver for moderate-n, bounded-R instances.

CRISP can solve random subset sum instances of n=1000 with values up to 10^10 on a laptop, with a build phase peaking under 600 MB of RAM and reconstruction running within a configurable cache budget. It recovers actual subset solutions (not just decision answers) via a backward DFS reconstruction walker. These are instances where classical Bellman dynamic programming is infeasible because the bitset for the target would require roughly 282 GB of memory.

This is research code from a long-running independent project on subset sum. It is provided as-is for evaluation, benchmarking, and integration into other algorithms or tooling.

## Benchmarks

All runs use n=1000, k=500 (planted), on WSL2 (Ubuntu) on a laptop. The build phase runs through all n steps by default — no early termination. Each row finds 10 exact subset solutions.

| n | R | T | k | T reached | build time | recon time | build peak RSS | recon peak cache | cache budget | k range found |
|---|---|---|---|---|---|---|---|---|---|---|
| 1000 | 10^5  | 25,145,285          | 500 | step 707 | 3.3s    | 2.7s    | 2.0 MB   | 622.9 KB | 1000 MB  | 282..286 |
| 1000 | 10^6  | 248,345,285         | 500 | step 691 | 3.8s    | 2.9s    | 2.0 MB   | 6.3 MB   | 1000 MB  | 293..296 |
| 1000 | 10^7  | 2,513,345,285       | 500 | step 706 | 6.9s    | 3.9s    | 2.5 MB   | 80.9 MB  | 1000 MB  | 294..298 |
| 1000 | 10^8  | 25,173,345,285      | 500 | step 708 | 42.7s   | 18.1s   | 9.7 MB   | 944.5 MB | 1000 MB  | 294..299 |
| 1000 | 10^9  | 242,673,345,285     | 500 | step 691 | 7.5min  | 15.6min | 67.7 MB  | 2.96 GB  | 3000 MB* | 294..298 |
| 1000 | 10^10 | 2,440,673,345,285   | 500 | step 710 | 66.1min | 67.9min | 567.9 MB | 3.18 GB  | 3000 MB† | 294..299 |

\* R=10^9 was re-run with a 3 GB cache after the default 1 GB cache thrashed during reconstruction (1.6% hit rate, reconstruction incomplete after 6 solutions). The 3 GB cache completed all 10 solutions.

† R=10^10 ran to completion but with a 0% cache hit rate (every frontier access was a disk miss, peak 50/1000 entries resident). A larger cache budget would significantly reduce reconstruction time. The build phase's peak RSS of 567.9 MB occurred mid-build during the densest phase of frontier growth; the final frontier was 62 MB and final RSS was 81 MB. Total disk usage for saved frontiers at R=10^10 was approximately 101 GB.

**For comparison**, naive Bellman bitset DP would require approximately 282 GB at R=10^10, 28 GB at R=10^9, and 2.9 GB at R=10^8 — the R=10^9 and R=10^10 instances are already infeasible on typical laptop hardware with the classical approach. CRISP handles all of these with a build memory footprint under 600 MB.

**Observations from the table:**
- **k range is stable across all R values.** The walker consistently recovers solutions with k ≈ 294-299 across five orders of magnitude of R, illustrating that the smallest-cardinality subsets summing to T are determined by structural properties of the item set rather than the magnitude of individual items.
- **Build time is roughly linear in R at the scales tested.** Each 10× in R costs about 9-10× in build time at R ≥ 10^7, reflecting the fact that CRISP is doing work proportional to the frontier size rather than shortcutting it. The algorithm's contribution is not a compute speedup — it is memory compression: the build fits in under 600 MB where a naive bitset would require ~280 GB at R=10^10. A machine with enough RAM to run naive Bellman DP at these scales could match CRISP's build time, but no commodity laptop has that much RAM.
- **Reconstruction becomes cache-bound at large R.** At R=10^9 and R=10^10, reconstruction throughput depends sensitively on the cache budget relative to total frontier size on disk.

**Notes on the columns:**
- **build peak RSS** is the peak resident set size of the entire process during the build phase, from `/proc/self/status`. This can exceed the final frontier size because the merge operation temporarily allocates new buffers before releasing the old ones.
- **recon peak cache** is the peak bytes held in the LRU frontier cache during reconstruction, set by `--cache-mb`. The full process RSS during recon is approximately `recon peak cache + small overhead`.
- **k range found** is the cardinality range of the actual subset solutions recovered by the reconstruction walker, which is biased toward small-k solutions via TAKE-first traversal.

## Build

Requires GCC and a POSIX-ish system. Tested on Linux and WSL2.

```
gcc -O3 -march=native -o crisp crisp.c -lm
```

## Quick start

Build a fresh frontier and find 10 solutions for a planted instance:

```
./crisp --n 1000 --R 100000000 --k 500 --recon --limit 10 --mem 2048 --cache-mb 1000
```

This will:

1. Generate 1000 random items with values up to 10^8
2. Plant a target T as the sum of 500 of them
3. Build the CRISP frontier step by step, saving each step to disk under `frontiers/run_<timestamp>_s<seed>/`
4. Walk the saved frontiers backward to reconstruct exact subsets summing to T
5. Write up to 10 solutions to `solutions.txt`

This instance finishes in about a minute. For larger instances (R up to 10^10), see the Benchmarks section above for expected times and memory footprints.

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

## Flags

```
--n N                Number of items to generate (default 50).
--R R                Maximum item value (random items drawn from [1, R]).
--k K                Plant a target T as the sum of K randomly chosen items.
--T T                Use a specific target value instead of planting.
--seed N             RNG seed (default 12345). Controls item generation and
                     --random-order traversal.
--items-file PATH    Use a specific list of items instead of generating
                     them randomly. One item per line.

--recon              Enable reconstruction after build. Saves per-step
                     frontiers to disk and walks them backward to find
                     actual subsets.
--recon-from DIR     Skip build; load saved frontiers from DIR and run
                     reconstruction only. Requires a previous --recon run.
--limit N            Maximum number of solutions to emit (default 1000).
--find-k k1,k2,...   Find solutions at specific cardinalities only.
--random-order       Randomize TAKE/SKIP order at branching nodes during
                     reconstruction. Use with different --seed values to
                     get diverse solution clusters.
--out PATH           Output file for solutions (default solutions.txt).
--frontier-dir DIR   Base directory for saved frontiers (default frontiers).

--stop-on-target     End the build phase as soon as the target becomes
                     reachable, then proceed to reconstruction. Faster but
                     may miss smaller-k solutions that would use items
                     processed after T is first reached.
--cache-mb N         Limit the reconstruction walker's frontier cache to
                     N megabytes. The walker is correct at any cache size,
                     but smaller caches mean more disk re-reads and slower
                     reconstruction at large R.
--mem N              Memory limit (MB) for the build phase. Build halts
                     if RSS exceeds this.
--quiet              Suppress per-step progress lines.
```

## How it works

CRISP maintains a frontier of reachable subset sums and expands it one item at a time. The compression that makes this practical comes from an empirical observation about the structure of subset sum frontiers themselves: for almost all item sets — the exception being super-increasing sequences, where each item exceeds the sum of all smaller items — reachable subset sums form dense, tightly clustered regions rather than sparsely scattered values. As the frontier grows, the consecutive differences between reachable sums concentrate into a very small set of unique values, and the distribution of those differences is highly skewed: a few small differences (typically 1, 2, 3) dominate, with rarer larger gaps falling off in what looks empirically like a Zipf-like pattern.

This low-entropy structure is what makes CRISP's compression effective. The frontier is stored as a varint-encoded run-length stream and updated via a streaming merge that operates directly on the encoded representation without ever materializing the underlying bit array. On the instances benchmarked above, compression ratios of a naive bitset to the final CRISP frontier range from roughly 10^3 at R=10^6 to roughly 5×10^3 at R=10^10 — three to four orders of magnitude.

The other half of CRISP's memory story is offloading. The build phase only needs the *current* frontier in active memory at any one time — the previous step's frontier has already been merged into it. Rather than discarding old frontiers, CRISP writes each step's compressed frontier to disk as soon as it's no longer needed for the build, then frees it from RAM. Reconstruction later reads these per-step files back from disk through an LRU cache with a configurable byte budget (`--cache-mb`), so the walker can access historical frontiers on demand without ever holding all of them in memory at once. The combined effect of compression plus offloading is what allows CRISP to handle instances at n=1000, R=10^10 on a laptop (build peak under 600 MB, reconstruction cache budget around 3 GB), where classical Bellman dynamic programming would require approximately 282 GB for the bitset alone.

Reconstruction uses a backward depth-first walker over the saved per-step frontiers. At each step the walker decides whether the current item was used in the solution by checking whether the residual target is reachable in the previous frontier. The walker is biased toward small-cardinality solutions by trying TAKE before SKIP at every branching node, and supports randomized traversal order via `--random-order` for solution diversity across multiple runs.

The worst-case complexity matches Bellman dynamic programming (O(nT) time, O(T) space if you ignore compression). The empirical performance is much better than the worst case, driven by the diff-alphabet structure that the worst-case analysis does not capture. The exact asymptotic bound under this structure is open. The connection to super-increasing sequences is not coincidental: the original Merkle-Hellman knapsack cryptosystem deliberately used super-increasing sets precisely because they avoid this dense structure, and CRISP works on the regime where item sets do not have that protective property.

## Practical limits

At the benchmarked scale (n=1000, R up to 10^10), the current bottlenecks are:

- **Build time.** Dominated by the decode-merge-encode loop, which is inherently sequential per step. Roughly 66 minutes at R=10^10 on a laptop; a workstation or parallel implementation could improve this by several factors.
- **Disk storage.** CRISP saves every step's frontier for reconstruction flexibility. Total disk usage scales roughly linearly with the final frontier size — about 100 GB at R=10^10. Going to R=10^11 would require approximately 1 TB of fast storage. Checkpoint-style saves (every k steps) would reduce this linearly but are not yet implemented.
- **Reconstruction cache budget.** At large R, reconstruction throughput depends sensitively on whether the frontier cache fits the working set of frontiers the walker visits. With a 3 GB cache at R=10^10, the walker saw 0% cache hit rate and took 68 minutes; a workstation with 32+ GB of RAM allocated to the cache would reduce this to minutes.

Memory for the build phase is *not* a bottleneck at the scales tested — build peak RSS stays under 600 MB at R=10^10. The algorithm's scaling limit on commodity hardware is set by disk and cache, not by build memory.

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