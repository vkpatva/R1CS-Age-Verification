# zk-2bit-range-proof (R1CS -> QAP) Demo

This project is a from-scratch, educational implementation of a **2-bit range proof** for:

* Prove that a witness `Age` exists and satisfies `0 <= Age <= 3`.
* Under the hood, it builds a tiny arithmetic circuit, represents it as **R1CS**, converts it to a **QAP**, and then verifies a single-point QAP identity at a Fiat–Shamir-derived challenge point `r`.

It is intentionally “verbose”: the code prints the full math trail so you can connect each theoretical step to actual intermediate values and logs.

> Note: This is not production ZK (the generated `proof.json` includes witness values and polynomial coefficients). For learning, that is helpful; in real systems, those values would be hidden behind group commitments/proofs.

---

## Quick Start

1. Generate the constraint/QAP data:
```bash
node setup.js
```

2. Prove for an `Age` in `{0,1,2,3}`:
```bash
node prover.js 1
```

3. Verify:
```bash
node verifier.js
```

Or use npm scripts:
```bash
npm run setup
npm run prove -- 1
npm run verify
```

---

## Files Overview

* `setup.js`: defines the R1CS matrices `A, B, C`, constructs the target polynomial `Z(x) = (x-1)(x-2)(x-3)`, and writes `requirements.json`.
* `prover.js`: given `Age`, derives bits `b0, b1`, builds witness `s = [1, Age, b0, b1]`, interpolates polynomials `A(x), B(x), C(x)`, computes `P(x) = A(x)B(x) - C(x)`, divides by `Z(x)` to get `H(x)`, then checks the identity at a secret challenge point `r`.
* `verifier.js`: re-derives `r` from the prover commitment and checks:
  `A(r) * B(r) - C(r) == H(r) * Z(r)` (all in a finite field).

Artifacts:

* `requirements.json`: circuit definition + QAP target data.
* `proof.json`: prover transcript (includes witness + polynomial evaluations in this demo).

---

## The Circuit Being Proven (2-bit Range)

We use the standard idea: represent `Age` in binary using two bits:

* `Age = b0 + 2*b1`
* and enforce each bit is boolean: `b0 in {0,1}` and `b1 in {0,1}`.

If both are true, then `Age` can only be `0,1,2,3`.

### Witness Vector

The witness is a single vector containing every value used in the constraints:

`s = [1, Age, b0, b1]`

In this implementation (see `setup.js` and `prover.js`):

* index 0: constant `1`
* index 1: `Age`
* index 2: `b0` (LSB)
* index 3: `b1` (MSB)

---

## Finite Field Arithmetic (`F_p`)

All computations happen in a finite field modulo a prime `p`.

This demo hardcodes:
* `p = 97`

So every addition/multiplication/division is done “mod 97”.

When you see numbers like `96`, remember that:
* `96` is actually `-1 mod 97`

---

## Step 1: R1CS (Rank-1 Constraint System)

R1CS represents constraints in the form:

`(A_i · s) * (B_i · s) = (C_i · s)`

for each constraint row `i`.

We choose 3 constraints (because we have 2 bit-constraints + 1 decomposition constraint).

In `setup.js`, the matrices are:

* `A`:
  * row 1: `[0, 0, 1, 0]`   (selects `b0`)
  * row 2: `[0, 0, 0, 1]`   (selects `b1`)
  * row 3: `[0, 1, 0, 0]`   (selects `Age`)
* `B`:
  * row 1: `[-1, 0, 1, 0]`  (selects `b0 - 1`)
  * row 2: `[-1, 0, 0, 1]`  (selects `b1 - 1`)
  * row 3: `[1, 0, 0, 0]`    (selects `1`)
* `C`:
  * row 1: `[0, 0, 0, 0]`    (target `0`)
  * row 2: `[0, 0, 0, 0]`    (target `0`)
  * row 3: `[0, 0, 1, 2]`    (selects `b0 + 2*b1`)

That corresponds exactly to:

1. `b0 * (b0 - 1) = 0`
2. `b1 * (b1 - 1) = 0`
3. `Age * 1 = b0 + 2*b1`

So the constraints force:

* `b0` is 0 or 1
* `b1` is 0 or 1
* `Age` matches the binary combination

---

## Step 2: From R1CS to QAP

### The Target Polynomial `Z(x)`

We pick 3 interpolation points:

`constraintPoints = [1, 2, 3]`

Then we build the target polynomial:

`Z(x) = (x - 1)(x - 2)(x - 3)`

By construction:
* `Z(1) = 0`
* `Z(2) = 0`
* `Z(3) = 0`

### Lagrange Interpolation Polynomials

For each column of the R1CS matrices (`A`-columns, `B`-columns, `C`-columns), we construct polynomials over `F_p` such that:

* for each constraint point `x = 1,2,3`, the polynomial’s value equals the corresponding dot-product value.

Concretely, the prover computes:

* `A_vals[i] = (A_row_i · s) = A(i)`
* `B_vals[i] = (B_row_i · s) = B(i)`
* `C_vals[i] = (C_row_i · s) = C(i)`

Then it uses Lagrange interpolation to get full polynomials:

* `A(x)`, `B(x)`, `C(x)`

### The QAP Identity

Define:

* `P(x) = A(x) * B(x) - C(x)`

If the witness satisfies every R1CS row, then:

* `P(1) = 0`, `P(2) = 0`, `P(3) = 0`
* meaning `Z(x)` divides `P(x)`

So there exists a polynomial `H(x)` such that:

`A(x) * B(x) - C(x) = H(x) * Z(x)`

The prover computes `H(x)` via polynomial long division.

---

## Step 3: Fiat–Shamir (Derive `r` from the transcript)

Real ZK protocols avoid interactive challenges by deriving them from the transcript.

In this demo:

* The prover commits to polynomials by hashing their coefficients:
  `commitment = sha256(A_x || B_x || C_x || H_x)`
* The verifier/prover both deterministically derive a challenge:
  `r = H(commitment, publicSeed, counter) mod p`

Implementation detail:

* `forbiddenPoints = [1,2,3]`
* so we avoid choosing `r` where `Z(r) = 0` (otherwise the check would trivially pass).

---

## Step 4: Single-Point Verification Check

Once `r` is fixed, the verifier checks the identity at that single point:

`A(r) * B(r) - C(r) == H(r) * Z(r)`  (mod `p`)

This works because (with high probability) if the polynomial identity fails, it won’t hold at a random point `r` (Schwartz–Zippel intuition).

---

## Example Run (Age = 1)

Below is an actual run transcript for:
`node setup.js && node prover.js 1 && node verifier.js`

```text
========== SETUP START ==========
[Setup] Prime field selected: F_97
[Setup] Constraint interpolation points: [1,2,3]
[Setup] Witness layout fixed as: [1, age, b0, b1]
[Setup] Constraint 1: b0 * (b0 - 1) = 0
[Setup] Constraint 2: b1 * (b1 - 1) = 0
[Setup] Constraint 3: age * 1 = b0 + 2*b1
[Setup] Matrix A: [[0,0,1,0],[0,0,0,1],[0,1,0,0]]
[Setup] Matrix B: [[-1,0,1,0],[-1,0,0,1],[1,0,0,0]]
[Setup] Matrix C: [[0,0,0,0],[0,0,0,0],[0,0,1,2]]
[Setup] Why Z(x) looks like [91,11,91,1]:
[Setup] We place constraints at x=1, x=2, x=3, so Z(x) must be 0 at each.
[Setup] Z(x) = (x-1)(x-2)(x-3)
[Setup] Step 1: (x-1)(x-2) = x^2 - 3x + 2
[Setup] Step 2: (x^2 - 3x + 2)(x-3) = x^3 - 6x^2 + 11x - 6
[Setup] Convert negatives into F_97: -6 -> 91, 11 -> 11, -6 -> 91, leading 1 -> 1
[Setup] Therefore Z(x) coeffs from x^0..x^3 are [91,11,91,1] in F_97.
[Setup] Computed target polynomial Z(x) coefficients (low->high): [91,11,91,1]
[Setup] Writing requirements.json with R1CS + QAP target data.
requirements.json generated successfully.
R1CS matrices and target polynomial Z(x) are ready.
 =========== SETUP END ===========
 ========== PROVER START ==========
 [Prover] Reading requirements.json
 [Prover] Field prime: 97
 [Prover] Constraint points: [1,2,3]
 [Prover] Input age from CLI: 1
 [Prover] Derived 2-bit decomposition: age=1 -> b0=1, b1=0
 [Prover] Witness vector: [1,1,1,0]
 [Prover] A-values at constraints: [1,0,1]
 [Prover] B-values at constraints: [0,96,1]
 [Prover] C-values at constraints: [0,0,1]
 [Prover] How these are computed (row dot witness) in R1CS:
 [Prover]   A row 1: [0,0,1,0] dot [1,1,1,0] = 1
 [Prover]   A row 2: [0,0,0,1] dot [1,1,1,0] = 0
 [Prover]   A row 3: [0,1,0,0] dot [1,1,1,0] = 1
 [Prover]   B row 1: [-1,0,1,0] dot [1,1,1,0] = 0
 [Prover]   B row 2: [-1,0,0,1] dot [1,1,1,0] = 96
 [Prover]   B row 3: [1,0,0,0] dot [1,1,1,0] = 1
 [Prover]   C row 1: [0,0,0,0] dot [1,1,1,0] = 0
 [Prover]   C row 2: [0,0,0,0] dot [1,1,1,0] = 0
 [Prover]   C row 3: [0,0,1,2] dot [1,1,1,0] = 1
 [Prover] Interpolation idea: build one polynomial that matches each list at x=1,2,3.
 [Prover]   A(1)=1, A(2)=0, A(3)=1
 [Prover]   B(1)=0, B(2)=96, B(3)=1
 [Prover]   C(1)=0, C(2)=0, C(3)=1
 [Prover] Detailed Lagrange explanation for A(x):
 [Prover] Target points: A(1)=1, A(2)=0, A(3)=1
 [Prover] Build Lagrange basis polynomials over points {1,2,3} in F_97:
 [Prover]   L1(x) = ((x-2)(x-3))/((1-2)(1-3)) = ((x-2)(x-3))/2
 [Prover]         = (x^2 - 5x + 6)/2
 [Prover]         divide by 2 in F_97 means multiply by inverse(2)=49, since 2*49=1 mod 97
 [Prover]         = 49*(x^2 - 5x + 6) mod 97
 [Prover]         = 49x^2 + 46x + 3
 [Prover]   L2(x) = ((x-1)(x-3))/((2-1)(2-3)) = ((x-1)(x-3))/(-1)
 [Prover]         = -(x^2 - 4x + 3)
 [Prover]         = 96x^2 + 4x + 94
 [Prover]   L3(x) = ((x-1)(x-2))/((3-1)(3-2)) = ((x-1)(x-2))/2
 [Prover]         = (x^2 - 3x + 2)/2
 [Prover]         divide by 2 in F_97 means multiply by inverse(2)=49
 [Prover]         = 49*(x^2 - 3x + 2) mod 97
 [Prover]         = 49x^2 + 47x + 1
 [Prover] Interpolate:
 [Prover]   A(x) = 1*L1(x) + 0*L2(x) + 1*L3(x) mod 97
 [Prover] Coefficient-by-coefficient:
 [Prover]   x^2: 1*49 + 0*96 + 1*49 = 98 mod 97 = 1
 [Prover]   x^1: 1*46 + 0*4 + 1*47 = 93 mod 97 = 93
 [Prover]   x^0: 1*3 + 0*94 + 1*1 = 4 mod 97 = 4
 [Prover] Therefore A(x) coeffs(low->high) = [4,93,1]
 [Prover] Detailed Lagrange explanation for B(x):
 [Prover] Target points: B(1)=0, B(2)=96, B(3)=1
 [Prover] Build Lagrange basis polynomials over points {1,2,3} in F_97:
 [Prover]   L1(x) = ((x-2)(x-3))/((1-2)(1-3)) = ((x-2)(x-3))/2
 [Prover]         = (x^2 - 5x + 6)/2
 [Prover]         divide by 2 in F_97 means multiply by inverse(2)=49, since 2*49=1 mod 97
 [Prover]         = 49*(x^2 - 5x + 6) mod 97
 [Prover]         = 49x^2 + 46x + 3
 [Prover]   L2(x) = ((x-1)(x-3))/((2-1)(2-3)) = ((x-1)(x-3))/(-1)
 [Prover]         = -(x^2 - 4x + 3)
 [Prover]         = 96x^2 + 4x + 94
 [Prover]   L3(x) = ((x-1)(x-2))/((3-1)(3-2)) = ((x-1)(x-2))/2
 [Prover]         = (x^2 - 3x + 2)/2
 [Prover]         divide by 2 in F_97 means multiply by inverse(2)=49
 [Prover]         = 49*(x^2 - 3x + 2) mod 97
 [Prover]         = 49x^2 + 47x + 1
 [Prover] Interpolate:
 [Prover]   B(x) = 0*L1(x) + 96*L2(x) + 1*L3(x) mod 97
 [Prover] Coefficient-by-coefficient:
 [Prover]   x^2: 0*49 + 96*96 + 1*49 = 9265 mod 97 = 50
 [Prover]   x^1: 0*46 + 96*4 + 1*47 = 431 mod 97 = 43
 [Prover]   x^0: 0*3 + 96*94 + 1*1 = 9025 mod 97 = 4
 [Prover] Therefore B(x) coeffs(low->high) = [4,43,50]
 [Prover] Detailed Lagrange explanation for C(x):
 [Prover] Target points: C(1)=0, C(2)=0, C(3)=1
 [Prover] Build Lagrange basis polynomials over points {1,2,3} in F_97:
 [Prover]   L1(x) = ((x-2)(x-3))/((1-2)(1-3)) = ((x-2)(x-3))/2
 [Prover]         = (x^2 - 5x + 6)/2
 [Prover]         divide by 2 in F_97 means multiply by inverse(2)=49, since 2*49=1 mod 97
 [Prover]         = 49*(x^2 - 5x + 6) mod 97
 [Prover]         = 49x^2 + 46x + 3
 [Prover]   L2(x) = ((x-1)(x-3))/((2-1)(2-3)) = ((x-1)(x-3))/(-1)
 [Prover]         = -(x^2 - 4x + 3)
 [Prover]         = 96x^2 + 4x + 94
 [Prover]   L3(x) = ((x-1)(x-2))/((3-1)(3-2)) = ((x-1)(x-2))/2
 [Prover]         = (x^2 - 3x + 2)/2
 [Prover]         divide by 2 in F_97 means multiply by inverse(2)=49
 [Prover]         = 49*(x^2 - 3x + 2) mod 97
 [Prover]         = 49x^2 + 47x + 1
 [Prover] Interpolate:
 [Prover]   C(x) = 0*L1(x) + 0*L2(x) + 1*L3(x) mod 97
 [Prover] Coefficient-by-coefficient:
 [Prover]   x^2: 0*49 + 0*96 + 1*49 = 49 mod 97 = 49
 [Prover]   x^1: 0*46 + 0*4 + 1*47 = 47 mod 97 = 47
 [Prover]   x^0: 0*3 + 0*94 + 1*1 = 1 mod 97 = 1
 [Prover] Therefore C(x) coeffs(low->high) = [1,47,49]
 [Prover] Interpolated A(x) coeffs (low->high): [4,93,1]
 [Prover] Interpolated B(x) coeffs (low->high): [4,43,50]
 [Prover] Interpolated C(x) coeffs (low->high): [1,47,49]
 [Prover] A(x) readable form in F_97: 1*x^2 + 93*x + 4
 [Prover] B(x) readable form in F_97: 50*x^2 + 43*x + 4
 [Prover] C(x) readable form in F_97: 49*x^2 + 47*x + 1
 [Prover] Check: each polynomial above, when evaluated at x=1,2,3, gives the corresponding values list.
 [Prover] Detailed polynomial multiplication for A(x) * B(x):
 [Prover]   A(x) = 1*x^2 + 93*x + 4
 [Prover]   B(x) = 50*x^2 + 43*x + 4
 [Prover]   term: (4*x^0) * (4*x^0) = 16*x^0; accumulate coeff[x^0] 0 -> 16 (mod 97)
 [Prover]   term: (4*x^0) * (43*x^1) = 172*x^1; accumulate coeff[x^1] 0 -> 75 (mod 97)
 [Prover]   term: (4*x^0) * (50*x^2) = 200*x^2; accumulate coeff[x^2] 0 -> 6 (mod 97)
 [Prover]   term: (93*x^1) * (4*x^0) = 372*x^1; accumulate coeff[x^1] 75 -> 59 (mod 97)
 [Prover]   term: (93*x^1) * (43*x^1) = 3999*x^2; accumulate coeff[x^2] 6 -> 28 (mod 97)
 [Prover]   term: (93*x^1) * (50*x^2) = 4650*x^3; accumulate coeff[x^3] 0 -> 91 (mod 97)
 [Prover]   term: (1*x^2) * (4*x^0) = 4*x^2; accumulate coeff[x^2] 28 -> 32 (mod 97)
 [Prover]   term: (1*x^2) * (43*x^1) = 43*x^3; accumulate coeff[x^3] 91 -> 37 (mod 97)
 [Prover]   term: (1*x^2) * (50*x^2) = 50*x^4; accumulate coeff[x^4] 0 -> 50 (mod 97)
 [Prover]   Result A(x)B(x) coeffs(low->high): [16,59,32,37,50]
 [Prover]   Result A(x)B(x) readable: 50*x^4 + 37*x^3 + 32*x^2 + 59*x + 16
 [Prover] Now subtract C(x) coefficient-by-coefficient:
 [Prover]   C(x) coeffs(low->high): [1,47,49]
 [Prover]   degree x^0: (16) - (1) = 15 -> 15 mod 97
 [Prover]   degree x^1: (59) - (47) = 12 -> 12 mod 97
 [Prover]   degree x^2: (32) - (49) = -17 -> 80 mod 97
 [Prover]   degree x^3: (37) - (0) = 37 -> 37 mod 97
 [Prover]   degree x^4: (50) - (0) = 50 -> 50 mod 97
 [Prover]   Final P(x)=A(x)B(x)-C(x) coeffs(low->high): [15,12,80,37,50]
 [Prover] Detailed target polynomial Z(x) explanation:
 [Prover]   Constraint points are x=1,2,3 so Z(x) must be vanish there.
 [Prover]   Z(x) = (x-1)(x-2)(x-3)
 [Prover]   (x-1)(x-2) = x^2 - 3x + 2
 [Prover]   (x^2 - 3x + 2)(x-3) = x^3 - 6x^2 + 11x - 6
 [Prover]   Convert to F_97: -6 -> 91, 11 -> 11, -6 -> 91
 [Prover]   Therefore Z(x) coeffs(low->high) = [91,11,91,1]
 [Prover] Detailed long division for H(x) = P(x)/Z(x):
 [Prover]   P(x) coeffs(low->high): [15,12,80,37,50]
 [Prover]   Z(x) coeffs(low->high): [91,11,91,1]
 [Prover]   P(x) readable: 50*x^4 + 37*x^3 + 80*x^2 + 12*x + 15
 [Prover]   Z(x) readable: 1*x^3 + 91*x^2 + 11*x + 91
 [Prover]   Step: cancel degree x^4 using (50/1)*x^1
 [Prover]         in F_97: 50 * inv(1) where inv(1)=1, so scale=50
 [Prover]         add 50*x^1 to quotient => current H coeffs(low->high): [0,50]
 [Prover]         expanded raw product (50*x^1)*Z(x): 50x^4 + 4550x^3 + 550x^2 + 4550x^1
 [Prover]         after mod 97: 50x^4 + 88x^3 + 65x^2 + 88x^1
 [Prover]         update degree x^1: 12 - (50*91=88) -> 21 mod 97
 [Prover]         update degree x^2: 80 - (50*11=65) -> 15 mod 97
 [Prover]         update degree x^3: 37 - (50*91=88) -> 46 mod 97
 [Prover]         update degree x^4: 50 - (50*1=50) -> 0 mod 97
 [Prover]         numerator after step (low->high): [15,21,15,46]
 [Prover]   Step: cancel degree x^3 using (46/1)*x^0
 [Prover]         in F_97: 46 * inv(1) where inv(1)=1, so scale=46
 [Prover]         add 46*x^0 to quotient => current H coeffs(low->high): [46,50]
 [Prover]         expanded raw product (46*x^0)*Z(x): 46x^3 + 4186x^2 + 506x^1 + 4186x^0
 [Prover]         after mod 97: 46x^3 + 15x^2 + 21x^1 + 15x^0
 [Prover]         update degree x^0: 15 - (46*91=15) -> 0 mod 97
 [Prover]         update degree x^1: 21 - (46*11=21) -> 0 mod 97
 [Prover]         update degree x^2: 15 - (46*91=15) -> 0 mod 97
 [Prover]         update degree x^3: 46 - (46*1=46) -> 0 mod 97
 [Prover]         numerator after step (low->high): [0]
 [Prover]   Final H(x) coeffs(low->high): [46,50]
 [Prover]   Final remainder coeffs(low->high): [0]
 [Prover]   Since remainder is 0, Z(x) divides P(x) exactly.
 [Prover]   Therefore in QAP form: P(x) = H(x) * Z(x), with H(x) = 50*x + 46
 [Prover] Computed P(x)=A(x)B(x)-C(x) coeffs (low->high): [15,12,80,37,50]
 [Prover] Target Z(x) coeffs (low->high): [91,11,91,1]
 [Prover] Quotient H(x) coeffs (low->high): [46,50]
 [Prover] Division remainder coeffs (must be [0]): [0]
 [Prover] Derived Fiat–Shamir challenge point r=20 from commitment.
 [Prover] ===== Evaluation Handshake (Proof Packaging) =====
 [Prover] We now move from full polynomials to single-point evaluations at secret r=20.
 [Prover] Why: sending full polynomial coefficients can leak structure; sending evaluations is the proof-style check.
 [Prover] Public/derived polynomials: A(x)=1*x^2 + 93*x + 4, B(x)=50*x^2 + 43*x + 4, C(x)=49*x^2 + 47*x + 1, H(x)=50*x + 46
 [Prover] Evaluate at r=20: A(r)=33, B(r)=9, C(r)=74, H(r)=76
 [Prover] Debug note: witness [1,1,1,0] is included only for learning/debugging. Real ZK proofs do NOT reveal witness values.
 [Prover] Verifier-side equation that must hold in F_97:
 [Prover]   (A(r) * B(r) - C(r)) == H(r) * Z(r)
 [Prover]   Z(r) is public-computable from Z(x): Z(20) = 91
 [Prover]   LHS raw: (33 * 9) - 74 = 223; LHS mod 97 = 29
 [Prover]   RHS raw: (76 * 91) = 6916; RHS mod 97 = 29
 [Prover]   Handshake check value: 29 == 29
 [Prover] If this equality fails, the witness does not satisfy the circuit constraints.
 [Prover] ==================================================
 [Prover] Evaluations at r: {"A_r":33,"B_r":9,"C_r":74,"H_r":76}
 Prover is sending [witness.values=[1,1,1,0]] to proof.json
 Prover is sending [A(r), B(r), C(r), H(r)={"A_r":33,"B_r":9,"C_r":74,"H_r":76}] to proof.json
 proof.json generated successfully.
 =========== PROVER END ===========
 ========= VERIFIER START =========
 [Verifier] Reading requirements.json and proof.json
 Verifier is reading [commitment] from proof.json
 Verifier is reading [A(r), B(r), C(r), H(r)] from proof.json
 [Verifier] Field prime: 97
 [Verifier] Derived Fiat–Shamir challenge point r=20 from commitment
 [Verifier] Target Z(x) coeffs (low->high): [91,11,91,1]
 [Verifier] Parsed evaluations from proof: {"A_r":33,"B_r":9,"C_r":74,"H_r":76}
 Verifier computed LHS = A(r)*B(r)-C(r): 29
 Verifier computed RHS = H(r)*Z(r): 29
 Verifier computed Z(r): 91
 Verification SUCCESS: A(r) * B(r) - C(r) == H(r) * Z(r)
 ========== VERIFIER END ===========
```

### How to read the logs (mapping theory -> code)

* `Witness vector: [1,Age,b0,b1]` corresponds to the witness `s`.
* `A-values/B-values/C-values at constraints` are the dot products `(A_i · s)`, `(B_i · s)`, `(C_i · s)`.
* The long interpolation sections compute `A(x)`, `B(x)`, `C(x)` from their values at `x=1,2,3`.
* `P(x)=A(x)B(x)-C(x)` is the QAP polynomial.
* `Division remainder coeffs (must be [0])` is the divisibility test: it confirms `Z(x)` divides `P(x)`.
* The Fiat–Shamir lines compute `r` deterministically from `commitment`.
* The “Evaluation Handshake” is the single-point verifier check.

---

## Extending to 8-bit / 32-bit (What changes?)

The same pattern repeats:

1. Choose enough bits to represent the range.
2. Add constraints that enforce each bit is boolean.
3. Add one constraint that `Age` equals the weighted sum of bits.
4. Everything else (R1CS -> QAP -> single-point identity) is the same algorithmic pipeline.

The main difference is the number of constraints and witness size, which makes the polynomials larger and the logs longer.

