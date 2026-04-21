# ZK Dynamic Range Proof (R1CS → QAP → KZG) Demo

An educational, from-scratch implementation of a **zero-knowledge range proof** that proves `lo ≤ age ≤ hi` for any verifier-specified range, without revealing the actual age.

Built on: R1CS → QAP → Lagrange interpolation → Fiat–Shamir → single-point identity check → **KZG polynomial commitments**.
All arithmetic uses JS `BigInt` in field **F_(2^61−1)** (Mersenne prime).

---

## Quick Start

```bash
# Step 1: Setup — generate proving key and verification key for a range
node setup.js <lo> <hi>        # e.g. node setup.js 18 65

# Step 2: Prove — prover commits to age being in [lo, hi]
node prover.js <age>           # e.g. node prover.js 25

# Step 3: Verify
node verifier.js
```

Or with npm:
```bash
npm run setup -- 18 65
npm run prove -- 25
npm run verify
npm test
```

### Example ranges

```bash
# Prove age is between 4 and 16
node setup.js 4 16 && node prover.js 10 && node verifier.js

# Prove age is 32 or older (up to 256)
node setup.js 32 256 && node prover.js 45 && node verifier.js

# Prove age is under 64
node setup.js 0 64 && node prover.js 21 && node verifier.js

# Prove age is between 18 and 256
node setup.js 18 256 && node prover.js 100 && node verifier.js
```

Supported range: `0 ≤ lo < hi ≤ 256`.

---

## Understanding the System — A Complete Walkthrough

This section explains every design decision from first principles, using **[18, 256]** as the running example.

### Step 1 — Why not compare numbers directly?

Arithmetic circuits (and R1CS) can only check equations of the form:

```
(some linear combination) × (some linear combination) = (some linear combination)
```

There is no "≤" operator. You cannot write `lo ≤ age` as a single constraint.
So we need a way to express a range check purely through multiplication and addition.

---

### Step 2 — The two-distance idea

Instead of checking the bounds directly, we ask the prover to reveal **two distances**:

```
a = age − lo    how far age sits above the minimum
b = hi  − age   how far age sits below the maximum
```

For **[18, 256], age = 100**:
```
a = 100 − 18  =  82   (82 steps above the floor)
b = 256 − 100 = 156   (156 steps below the ceiling)
```

Now notice: if we can prove **both a ≥ 0 and b ≥ 0**, we are done:
```
a ≥ 0  →  age − lo ≥ 0  →  age ≥ lo  (18)
b ≥ 0  →  hi − age ≥ 0  →  age ≤ hi  (256)
```

And we add one more constraint to tie them together:
```
a + b = gap     where gap = hi − lo = 238
```

This prevents the prover from inventing arbitrary a and b — once `age` and `lo` are fixed,
`a` is determined, and once `a` and `gap` are fixed, `b` is determined. There is no slack.

---

### Step 3 — Proving non-negativity with bits

Circuits can't check `a ≥ 0` directly either. But they can check something equivalent:
**a number is non-negative if and only if it can be written as a sum of weighted boolean bits.**

So the prover decomposes `a` and `b` into bits:
```
a = 82  = 0·1 + 1·2 + 0·4 + 0·8 + 1·16 + 0·32 + 1·64 + 0·128
        →  a0=0, a1=1, a2=0, a3=0, a4=1, a5=0, a6=1, a7=0

b = 156 = 0·1 + 0·2 + 1·4 + 1·8 + 1·16 + 0·32 + 0·64 + 1·128
        →  b0=0, b1=0, b2=1, b3=1, b4=1, b5=0, b6=0, b7=1
```

And the circuit forces every bit to actually be 0 or 1 using the constraint:

```
bit × (bit − 1) = 0
```

The only two numbers that satisfy `x(x−1) = 0` are `x = 0` and `x = 1`.
If any bit were 2, 3, -1, or anything else, this constraint would fail.

---

### Step 4 — How many bits k?

Both `a` and `b` can be as large as `gap` (a is largest when `age = hi`, b is largest when `age = lo`).
So `k` bits must be able to hold any value from **0 up to gap**.

```
k bits can represent values  0  to  2ᵏ − 1
Requirement:                 2ᵏ − 1  ≥  gap
                             2ᵏ      ≥  gap + 1
                             k       ≥  log₂(gap + 1)
                             k       =  ⌈log₂(gap + 1)⌉   ← minimum k
```

The `+1` is because we need `gap + 1` distinct values (0, 1, 2, ..., gap), and `k` bits gives exactly `2ᵏ` slots.

For **[18, 256]**: `gap = 238`, `gap + 1 = 239`, `log₂(239) ≈ 7.90`, so **k = 8**.

```
k = 7 would fail:  2⁷ − 1 = 127  <  238  (can't hold a = 238 when age = 256)
k = 8 works:       2⁸ − 1 = 255  ≥  238  ✓
k = 9 would waste: 2⁹ − 1 = 511  ≥  238  (works but adds 2 unnecessary constraints)
```

| Range       | gap | gap+1 | log₂(gap+1) | k |
|-------------|-----|-------|-------------|---|
| [0, 1]      |   1 |   2   | 1.00        | 1 |
| [0, 15]     |  15 |  16   | 4.00        | 4 |
| [4, 16]     |  12 |  13   | 3.70        | 4 |
| [18, 65]    |  47 |  48   | 5.58        | 6 |
| [0, 64]     |  64 |  65   | 6.02        | 7 |
| [18, 256]   | 238 | 239   | 7.90        | 8 |
| [32, 256]   | 224 | 225   | 7.81        | 8 |
| [0, 256]    | 256 | 257   | 8.00+       | 9 |

---

### Step 5 — The witness

The witness is the complete set of **private values** the prover holds.
For **[18, 256], age = 100, k = 8**:

```
w = [ 1,  100,  0,1,0,1,0,1,0,1,  0,0,1,1,1,0,0,1 ]
      ↑    ↑    └─── a-bits ────┘  └─── b-bits ────┘
    const  age   a=82 in 8 bits     b=156 in 8 bits
     [0]   [1]      [2..9]              [10..17]
```

Total length = `2 + 2k = 18` entries.

#### Why are lo and hi NOT in the witness?

The witness holds **private** values — things only the prover knows, hidden from the verifier.
`lo` and `hi` are the **opposite**: the verifier must know them to understand what is being proved.

More importantly, `lo` and `hi` are not runtime inputs to the circuit at all.
They are **compile-time constants baked directly into the R1CS matrix rows** during `setup.js`:

```
Constraint 17 C-row: [lo, 0, 1, 2, 4, 8, 16, 32, 64, 128, 0, ...]
                      ↑
                    18 is literally written into this matrix cell

Constraint 18 A-row: [gap, 0, 0, 0, ...]
                      ↑
                    238 is literally written into this matrix cell
```

The circuit **is** the range. Once setup runs, the matrices are fixed for [18, 256].
If you tried to use them for a different range, the circuit digest would mismatch and the proof would be rejected.

If `lo` and `hi` were in the witness (private), a malicious prover could set them to anything — e.g., `lo = 0, hi = 256` — and prove any age. The verifier would have no way to know what range was actually used.

---

### Step 6 — The 2k+2 = 18 constraints

Each constraint has the form `(A_row · w) × (B_row · w) = (C_row · w)`.
The sparse row vectors "pick out" the right witness values via dot product.

```
Constraints 1–8:   a_i × (a_i − 1) = 0      for i = 0..7   [each a-bit is boolean]
Constraints 9–16:  b_i × (b_i − 1) = 0      for i = 0..7   [each b-bit is boolean]
Constraint 17:     age × 1 = 18 + Σ(2ⁱ·aᵢ)               [age = lo + a  →  age ≥ 18]
Constraint 18:     238 × 1 = Σ(2ⁱ·aᵢ) + Σ(2ⁱ·bᵢ)         [a + b = gap  →  age ≤ 256]
```

Verified for age = 100:
```
Constraints 1–8:   each a-bit ∈ {0,1}  ✓
Constraints 9–16:  each b-bit ∈ {0,1}  ✓
Constraint 17:     100 = 18 + 82       ✓
Constraint 18:     238 = 82 + 156      ✓
```

---

### Step 7 — Why cheating is impossible

**Attack: age = 17 (one below lo)**

The prover would need `a = 17 − 18 = −1`.
Constraint 17 forces `a` to equal the bit sum `Σ(2ⁱ·aᵢ)`.
Every bit is 0 or 1 (from the boolean constraints) and every weight is positive,
so the sum is always ≥ 0. There is no bit assignment that equals −1.

**Attack: age = 257 (one above hi)**

The prover would need `b = 256 − 257 = −1`.
Same problem — b is fixed by constraint 18 once a is set, and b cannot be negative.

**Attack: use the field to "wrap" a negative number**

All arithmetic is mod `p = 2⁶¹ − 1`. In this field, `−1 ≡ p − 1 ≈ 2.3 × 10¹⁸`.
Could a cheater represent `a = p − 1` (which behaves like −1 in field arithmetic)?

```
Constraint 17 mod p:  17 = 18 + (p−1) mod p = 17  ✓  ← looks like it passes!
```

But now they must decompose `a = p − 1 ≈ 2.3 × 10¹⁸` into 8 boolean bits.
Maximum 8-bit sum = `1+2+4+8+16+32+64+128 = 255`.
`p − 1` is astronomically larger — no 8-bit assignment can reach it.
The boolean constraints (1–8) make this impossible.

This is the key security property: **k is chosen small enough that bit decompositions can never wrap around the field.** With `k = 8`, a is always 0..255 — a tiny positive island with no field-negative values anywhere near it.

**Attack: set a > gap**

Say a cheater sets `a = 240` (within 8 bits, but > gap = 238):
```
Constraint 18:  238 = 240 + b  →  b = −2
```
Again b is forced negative, impossible to decompose into bits.

---

### Step 8 — From constraints to the verification equation

**Assign constraint points.** Each of the 18 constraints gets a distinct evaluation point:
constraint 1 → x = 1, constraint 2 → x = 2, ..., constraint 18 → x = 18.

**Evaluate R1CS at the witness.** For each point x = j, compute three scalars:
```
aVal[j] = A_row_j · w
bVal[j] = B_row_j · w
cVal[j] = C_row_j · w
```
A satisfied constraint means `aVal[j] × bVal[j] = cVal[j]`.

**Lagrange interpolation.** Build three polynomials A(x), B(x), C(x) of degree ≤ 17
that pass through all 18 (point, value) pairs. These polynomials encode all constraint
values simultaneously.

**Form P(x).** Define:
```
P(x) = A(x)·B(x) − C(x)
```
Because every constraint is satisfied, `P(j) = 0` at every `j ∈ {1..18}`.

**Divisibility by Z(x).** Build the target polynomial:
```
Z(x) = (x−1)(x−2)(x−3)···(x−18)
```
Z(x) vanishes at exactly the 18 constraint points. Since `P(j) = 0` at all those same
points, Z(x) divides P(x) with zero remainder:
```
P(x) = H(x) · Z(x)
```
The prover computes `H(x) = P(x) / Z(x)` by polynomial long division.
A non-zero remainder would mean at least one constraint was violated.

**Fiat–Shamir single-point check.** Instead of checking the identity at all points
(which would reveal the witness), the verifier picks one random field point `r` derived
from a hash of the committed polynomial coefficients:
```
r = sha256(commitment | circuitDigest | counter) mod p
```
By the Schwartz–Zippel lemma, if `P(x) ≠ H(x)·Z(x)` as polynomials, the chance they
agree at a random `r` is at most `deg(P) / p ≈ 18 / 2⁶¹ ≈ 2⁻⁵⁵` — negligible.

**The final verification equation** (all 18 constraints checked in one step):
```
A(r)·B(r) − C(r)  ≡  H(r)·Z(r)   (mod 2⁶¹−1)
```

The verifier computes A(r), B(r), C(r), H(r) itself from the committed polynomial
coefficients. It never trusts evaluation values from the prover. Z(r) comes from the
public verification key. The prover never reveals `age`, `a`, or `b`.

---

### Step 9 — KZG Polynomial Commitments

The system now includes **KZG (Kate-Zaverucha-Goldberg) polynomial commitments**, which
replace the hash-based commitment for individual polynomial evaluations and add a second
layer of cryptographic verification.

#### Trusted setup

During `setup.js`, a **Structured Reference String (SRS)** is generated using a fixed
secret `τ = 42` (the "toxic waste"):

```
SRS[i] = τ^i mod p    for i = 0, 1, ..., 4k+4
```

In real KZG these would be elliptic curve points `[τ^i]G ∈ G1`. Here we simulate the
group using field elements in F_p, replacing EC operations with field arithmetic:

| Real KZG (EC group G1) | This simulation (F_p field) |
|---|---|
| `[x]G` (EC point) | `x ∈ F_p` |
| `k · [x]G` (scalar mult) | `k · x mod p` |
| `[x]G + [y]G` (group add) | `(x + y) mod p` |
| `e(a, b)` (pairing) | `a · b mod p` |

#### What the prover produces

After computing A(x), B(x), C(x), H(x), the prover generates:

| Value | Formula | Meaning |
|---|---|---|
| `C_A` | `A(τ) = Σ a[i]·τ^i mod p` | KZG commitment to A(x) |
| `C_B` | `B(τ)` | KZG commitment to B(x) |
| `C_C` | `C(τ)` | KZG commitment to C(x) |
| `C_H` | `H(τ)` | KZG commitment to H(x) |
| `π_A` | `q_A(τ)` where `q_A(x) = (A(x)−A(r))/(x−r)` | Opening proof for A(r) |
| `π_B` | `q_B(τ)` | Opening proof for B(r) |
| `π_C` | `q_C(τ)` | Opening proof for C(r) |
| `π_H` | `q_H(τ)` | Opening proof for H(r) |

The evaluation point `r` is the same Fiat–Shamir challenge used for the QAP identity check.

#### How the verifier checks a KZG opening proof

For each polynomial `f` with commitment `C = f(τ)`, claimed evaluation `y = f(r)`,
and opening proof `π = q(τ)` where `q(x) = (f(x)−y)/(x−r)`:

```
Real KZG:   e( C − y·G,  G₂ )  ==  e( π,  [τ]G₂ − [r]G₂ )

Simulated:  C − y  ==  π · (τ − r)   mod p
```

This works because `f(x) − f(r) = q(x) · (x−r)` as a polynomial identity,
so evaluating both sides at `x = τ` gives `C − y = π·(τ−r)` exactly.

The verifier also cross-checks the KZG claimed evaluations `y_A, y_B, y_C, y_H`
against its own recomputed values from the polynomial coefficients, ensuring consistency.

#### Note on hiding

In this simulation, `τ = 42` is public, so the commitments do not hide the polynomials.
In real KZG over an elliptic curve, `τ` is destroyed after the trusted setup ceremony —
the SRS points `[τ^i]G` reveal nothing about `τ` without solving the discrete log problem.

---

## Architecture: Three-Stage Pipeline

### `setup.js <lo> <hi>`

Builds the circuit for range `[lo, hi]` and writes two key files:

- **`proving_key.json`** — R1CS matrices, Z(x), circuit digest, KZG SRS
- **`verification_key.json`** — Z(x), circuit digest, KZG SRS (no R1CS)

The circuit digest is `sha256(prime ‖ lo ‖ hi ‖ constraintPoints ‖ R1CS)`.
It binds every proof to the exact circuit — a proof created for `[0, 15]` will be rejected
by a verifier holding a `[0, 30]` key, because the circuit digests differ.

### `prover.js <age>`

1. Reads `proving_key.json`; validates `lo ≤ age ≤ hi`
2. Computes `a = age − lo`, `b = hi − age`, decomposes both into k bits
3. Builds witness: `w = [1, age, a0..a_{k-1}, b0..b_{k-1}]`
4. Evaluates R1CS dot products at each constraint point
5. Lagrange-interpolates to get polynomials `A(x)`, `B(x)`, `C(x)`
6. Divides `P(x) = A(x)·B(x) − C(x)` by `Z(x)` to get `H(x)` (zero remainder = valid witness)
7. Generates random `salt`; computes Fiat–Shamir commitment and challenge `r`
8. **KZG commitments**: computes `C_A = A(τ)`, `C_B = B(τ)`, `C_C = C(τ)`, `C_H = H(τ)`
9. **KZG opening proofs**: computes `π_A, π_B, π_C, π_H` by dividing each polynomial by `(x − r)` and evaluating at `τ`
10. Writes **`proof.json`** — commitment, polynomial coefficients, KZG data (**witness never written**)

### `verifier.js`

Reads only `verification_key.json` (never sees R1CS or witness):

1. **Commitment check** — recomputes hash commitment from proof coefficients + own `circuitDigest`; must match
2. **Derive r** — re-derives Fiat–Shamir point `r` from verified commitment
3. **Evaluate** — computes `A(r)`, `B(r)`, `C(r)`, `H(r)` from committed coefficients; `Z(r)` from vk
4. **QAP check** — verifies `A(r)·B(r) − C(r) ≡ H(r)·Z(r)` (mod p)
5. **KZG verification** — for each polynomial, checks opening proof: `C − y == π·(τ−r)` and cross-validates evaluations

---

## Generated Files

| File | Written by | Read by | Contains |
|------|-----------|---------|----------|
| `proving_key.json` | setup | prover | R1CS, Z(x), range, k, circuitDigest, KZG SRS |
| `verification_key.json` | setup | verifier | Z(x), range, circuitDigest, KZG SRS (no R1CS) |
| `proof.json` | prover | verifier | commitment, salt, poly coefficients, KZG commitments + opening proofs |

### `proof.json` structure

```json
{
  "commitment": "<sha256 hash>",
  "salt": "<random hex>",
  "polynomialCoefficients": {
    "A_x": [...],
    "B_x": [...],
    "C_x": [...],
    "H_x": [...]
  },
  "kzg": {
    "C_A": "<A(τ)>",      "C_B": "<B(τ)>",
    "C_C": "<C(τ)>",      "C_H": "<H(τ)>",
    "evalPoint": "<r>",
    "y_A": "<A(r)>",      "y_B": "<B(r)>",
    "y_C": "<C(r)>",      "y_H": "<H(r)>",
    "pi_A": "<q_A(τ)>",   "pi_B": "<q_B(τ)>",
    "pi_C": "<q_C(τ)>",   "pi_H": "<q_H(τ)>"
  }
}
```

---

## Fiat–Shamir & Soundness

```
r = BigInt(sha256(commitment | circuitDigest | counter)) mod p
```

- `counter` increments if `r` lands on a forbidden point (where `Z(r) = 0`)
- Using the full 256-bit hash before reducing mod p keeps modular bias below 2⁻¹⁹⁵
- The same `r` is used for both the QAP identity check and the KZG opening proofs

Soundness error (Schwartz–Zippel): a cheating prover passes with probability at most `deg(P) / |F|`.

| Range     | k | deg(P) | Soundness error           |
|-----------|---|--------|---------------------------|
| [0, 15]   | 4 |  18    | 18/2⁶¹ ≈ 2⁻⁵⁷             |
| [18, 256] | 8 |  34    | 34/2⁶¹ ≈ 2⁻⁵⁶             |
| [0, 256]  | 9 |  38    | 38/2⁶¹ ≈ 2⁻⁵⁶             |

---

## Files

| File | Role |
|------|------|
| `setup.js` | Builds R1CS, QAP, Z(x), computes circuit digest, generates KZG SRS |
| `prover.js` | Witness construction, Lagrange interpolation, P/H computation, Fiat–Shamir, KZG commits + opens |
| `verifier.js` | Commitment check, QAP identity check, KZG opening proof verification |
| `kzg.js` | Self-contained KZG module: `generateSRS`, `commit`, `open`, `verify` + logging helpers |
| `test.js` | 78 tests across 8 groups |

---

## Running Tests

```bash
node test.js          # 78 tests across 8 groups
```

Tests cover: setup validation, full pipeline for many ranges, boundary values, out-of-range
rejection, proof tampering, cross-range replay attacks, circuit structure verification,
and KZG commitment/proof structure.

---

## ZK Limitation Note

**This demo is not fully zero-knowledge.** The polynomial coefficients in `proof.json` are
still included for the Fiat–Shamir commitment step, and from them a verifier can reconstruct
the witness values.

The KZG layer adds **binding** (you cannot forge an opening proof without knowing `τ`) but
not **hiding** in this simulation, because:
1. `τ = 42` is public, so `C = f(τ)` can be reversed if you know τ
2. The polynomial coefficients are still sent alongside the KZG data

### What full ZK would require

In a production KZG system:
1. **Trusted setup ceremony** — multiple parties compute the SRS over an elliptic curve
   (e.g. BN254) and destroy their shares of `τ`. No single party knows `τ`.
2. **Hiding commitments** — add a random blinding factor to each commitment so the
   verifier cannot learn `f(τ)` even from the commitment alone.
3. **Drop the coefficients** — the verifier only receives `C_A, C_B, C_C, C_H, π_A, π_B, π_C, π_H`
   and uses pairing equations to verify without seeing any polynomial coefficients.
4. **Pairing check** — `e(C − y·G, G₂) = e(π, [τ]G₂ − [r]G₂)` using a bilinear pairing
   on the elliptic curve. This requires a pairing-friendly curve like BN254 or BLS12-381.
