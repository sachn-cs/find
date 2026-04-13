# Algorithmic Reference: High-Performance search

This document provides a formal mathematical and algorithmic breakdown of the discovery logic used in the `find` tool.

## 🔬 Core Algorithm: Multi-Variant Range-Splitting

The problem is defined as finding a scalar $d \in [1, n-1]$ given an elliptic curve point $P = d \cdot G$ on the secp256k1 curve.

The tool implements a **parallel range-splitting engine** that explores multiple candidates simultaneously by shifting the target point $P$ into several different regions of the cyclic group $\mathbb{G}$.

### 1. Shift Variants ($V$)

The engine generates 512 variants $P_V$ such that:
$$P_V = P - (V \cdot G)$$

Where $V$ belongs to a set of pre-calculated anchors:
-   **Binary Anchors:** $V \in \{2^0, 2^1, \dots, 2^{255}\}$
-   **Cumulative Anchors:** $V \in \{\sum_{i=0}^k 2^i \mid k \in [0, 255]\}$

By shifting the target, the system essentially searches for a "small" scalar $j$ such that the X-coordinate of $j \cdot G$ matches any of the shifted points $P_V$.

### 2. The Matching Invariant

The search loop iterates through $j \in [1, R]$ and checks for the equality of X-coordinates:
$$x(j \cdot G) = x(P_V)$$

Due to the symmetry of X-coordinates on the curve ($x(P) = x(-P)$), a match implies:
1.  **Direct Match:** $j \cdot G = P - V \cdot G \implies P = (V + j) \cdot G$
2.  **Symmetric Match:** $j \cdot G = -(P - V \cdot G) \implies P = (V - j) \cdot G$

Therefore, each match yields two candidate private keys:
-   $d \equiv V + j \pmod n$
-   $d \equiv V - j \pmod n$

### 3. Batch Normalization (Simultaneous Inversion)

To maximize throughput, the engine processes scalars in batches of $N=32$. Coordinate extraction requires converting a projective point $(X:Y:Z)$ to affine $(X/Z, Y/Z)$, which involves a modular inversion of $Z$.

Instead of $N$ independent inversions, we use **Montgomery's Simultaneous Inversion**:
1.  Compute prefix products of $Z_i$.
2.  Perform a **single** inversion of the total product.
3.  Derive individual inverses $1/Z_i$ using the prefix products and the total inverse.

This reduces the complexity from $N$ inversions to **1 inversion** and $3(N-1)$ multiplications, yielding a 15-20x speedup in the normalization phase.

### 4. Complexity Analysis

| Operation | Complexity | Implementation Detail |
| :--- | :--- | :--- |
| **Variant Generation** | $O(V_{count})$ | Performed once per pubkey. Uses Projective subtract. |
| **Lookup (Index)** | $O(1)$ | BTreeMap key lookup for 32-byte X-coordinates. |
| **Sweep (CPU)** | $O(R)$ | Linear sweep over $j$. Multiplied by throughput of $d \cdot G$. |
| **Sweep (I/O)** | $O(R)$ | Sequential read-scan of binary cache. Extremely fast on NVMe. |

## Scalar Arithmetic Invariants

All scalar calculations are performed modulo $n$, where:
$n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$

The engine handles underflows in the negative parity case ($V - j$) by adding $n$ to the result before the final modulo operation, ensuring all candidates are valid private keys in $\mathbb{F}_n$.

## Parallelization Strategy

The tool utilizes **Work-Stealing Task Parallelism** via the `rayon` crate.
1.  The trillion-range segment is split into chunks sized for the CPU's L2/L3 cache hierarchies.
2.  Each thread independently calculates scalar multiples and probes the `VariantIndex`.
3.  The first thread to find a match triggers an early exit $(\text{find\_map\_any})$.
