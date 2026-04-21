# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Educational zero-knowledge proof demo implementing a **dynamic range proof** using R1CS → QAP conversion. Proves `lo ≤ age ≤ hi` for any verifier-specified range `0 ≤ lo < hi ≤ 256`, without revealing the actual age value. Intentionally verbose for learning purposes — not production ZK.

All arithmetic uses JS `BigInt` in field **F_(2^61−1)** (Mersenne prime).

## Commands

```bash
# Stage 1: Generate proving key and verification key for a range
node setup.js <lo> <hi>   # e.g. node setup.js 18 65

# Stage 2: Generate proof for an age in [lo, hi]
node prover.js <age>      # e.g. node prover.js 25

# Stage 3: Verify the proof
node verifier.js

# Run all tests
node test.js
```

npm aliases: `npm run setup -- <lo> <hi>`, `npm run prove -- <age>`, `npm run verify`, `npm test`.

No test framework or linter is configured.

## Architecture

Three-stage pipeline across three source files.

**`setup.js <lo> <hi>`** — Derives circuit parameters and builds the QAP for range `[lo, hi]`:
- Computes `gap = hi - lo` and `k = ⌈log₂(gap+1)⌉` (minimum bits to represent values 0..gap)
- Witness layout: `w = [1, age, a0..a_{k-1}, b0..b_{k-1}]`  (length `2 + 2k`)
  - `a = age - lo` decomposed into k bits (proves `age ≥ lo`)
  - `b = hi - age` decomposed into k bits (proves `age ≤ hi`)
- Builds `2k+2` R1CS constraints:
  - Constraints 1..k: `a_i*(a_i-1) = 0` (each a-bit is boolean)
  - Constraints k+1..2k: `b_i*(b_i-1) = 0` (each b-bit is boolean)
  - Constraint 2k+1: `age * 1 = lo + Σ 2^i·a_i` (age = lo + a)
  - Constraint 2k+2: `gap * 1 = Σ 2^i·a_i + Σ 2^i·b_i` (a + b = gap)
- Target polynomial `Z(x) = ∏_{i=1}^{2k+2} (x-i)` with roots at all constraint points
- `circuitDigest = sha256(prime‖lo‖hi‖constraintPoints‖R1CS)` binds proofs to this exact circuit
- Writes `proving_key.json` (full R1CS + digest) and `verification_key.json` (Z(x) + digest only)

**`prover.js <age>`** — Full proving pipeline:
- Reads `proving_key.json`; validates `lo ≤ age ≤ hi`
- Computes `a = age - lo`, `b = hi - age`; decomposes both into k bits via `toBits`
- Builds witness `w = [1, age, a-bits, b-bits]`; evaluates R1CS dot products at each constraint point
- Lagrange-interpolates to build polynomials `A(x)`, `B(x)`, `C(x)` of degree ≤ 2k+1
- Computes `P(x) = A(x)*B(x) - C(x)` (degree ≤ 4k+2); divides by `Z(x)` to get `H(x)` (zero remainder proves all constraints)
- Generates random `salt`; commitment = `sha256(JSON({circuitDigest, salt, A_x, B_x, C_x, H_x}))`
- Derives Fiat-Shamir `r` from commitment; writes `proof.json` (**witness is never written**)

**`verifier.js`** — Reads only `verification_key.json`:
1. Recomputes commitment from submitted coefficients + own `circuitDigest`; must match proof
2. Derives Fiat-Shamir `r` from verified commitment
3. Evaluates `A(r)`, `B(r)`, `C(r)`, `H(r)` from committed coefficients (never trusts prover-supplied values); computes `Z(r)` from vk
4. Checks: `A(r)*B(r) - C(r) == H(r)*Z(r)` (mod p)

## Key Design Details

- **Prime field**: `2^61 - 1` (Mersenne prime); soundness error = `deg(P)/p = (4k+2)/p` (e.g. ≈ 2⁻⁵⁷ for k=4)
- **BigInt**: all polynomial arithmetic and field operations use JS `BigInt` to avoid 53-bit overflow
- **k calculation**: `Math.max(1, Math.ceil(Math.log2(gap + 1)))` — minimum bits so `2^k - 1 ≥ gap`
- **Commitment binding**: verifier recomputes evaluations from committed coefficients — a prover cannot fabricate evaluations inconsistent with committed polynomials
- **Circuit integrity**: `circuitDigest` in vk catches any cross-range proof replay (different lo/hi → different digest)
- **Proving/verification key split**: verifier never reads R1CS matrices
- **Remaining ZK limitation**: polynomial coefficients in the proof are a deterministic function of the witness. True ZK requires replacing hash-based commitment with an EC polynomial commitment scheme (e.g. KZG with elliptic curve pairings)

## Generated Files

- `proving_key.json` — R1CS matrices, Z(x), range, k, witness layout, circuit digest (setup → prover)
- `verification_key.json` — Z(x), range, circuit digest only — no R1CS (setup → verifier)
- `proof.json` — commitment, salt, polynomial coefficients A_x/B_x/C_x/H_x (no witness, no pre-computed evaluations)
