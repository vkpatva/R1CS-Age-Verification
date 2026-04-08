const fs = require("fs");
const crypto = require("crypto");

// 2^61 - 1, a Mersenne prime.
const PRIME = 2305843009213693951n;

// ---------------------------------------------------------------------------
// Parse CLI arguments: node setup.js <lo> <hi>
// ---------------------------------------------------------------------------
const loRaw = process.argv[2];
const hiRaw = process.argv[3];

if (loRaw === undefined || hiRaw === undefined) {
  console.error("Usage: node setup.js <lo> <hi>  (0 ≤ lo < hi ≤ 256)");
  process.exit(1);
}
const lo = parseInt(loRaw, 10);
const hi = parseInt(hiRaw, 10);
if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 0 || hi > 256 || lo >= hi) {
  console.error("Error: need integers with 0 ≤ lo < hi ≤ 256");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Circuit parameters derived from [lo, hi]
//
// PROBLEM: arithmetic circuits cannot directly compare two numbers.
// They can only check equations of the form (linear) * (linear) = (linear).
// So we can't write "lo ≤ age ≤ hi" directly as a constraint.
//
// SOLUTION: two-distance decomposition
// ─────────────────────────────────────
// Introduce two secret witnesses:
//   a = age - lo   (left  distance: how far age sits above lo)
//   b = hi  - age  (right distance: how far age sits below hi)
//
// If we can prove BOTH are non-negative integers AND a + b = gap,
// then:
//   a ≥ 0  →  age - lo ≥ 0  →  age ≥ lo
//   b ≥ 0  →  hi - age ≥ 0  →  age ≤ hi
//
// Circuits prove non-negativity via bit decomposition:
// a number is non-negative iff it can be written as a sum of weighted bits.
//
// HOW MANY BITS k DO WE NEED?
// ─────────────────────────────────────
// Both a and b can be as large as gap (a is maximised when age = hi,
// b is maximised when age = lo).  So k bits must be able to represent
// every integer from 0 up to gap.
//
//   k bits holds values  0 .. 2^k - 1
//   Requirement:         2^k - 1  ≥  gap
//                        2^k      ≥  gap + 1
//                        k        ≥  log₂(gap + 1)
//                        k        =  ⌈log₂(gap + 1)⌉   ← minimum k
//
// The "+1" appears because we need gap+1 distinct values (0,1,...,gap),
// and k bits gives exactly 2^k distinct values.
//
// Example — range [4, 16]:
//   gap = 12,  gap+1 = 13,  log₂(13) ≈ 3.70  →  k = 4
//   Check: 2^4 - 1 = 15 ≥ 12  ✓
//   k=3 would fail: 2^3 - 1 = 7 < 12  ✗
//
// The constraints enforce:
//   1. a_i ∈ {0,1}  for i=0..k-1          (each a-bit is boolean)
//   2. b_i ∈ {0,1}  for i=0..k-1          (each b-bit is boolean)
//   3. age * 1 = lo + Σ 2^i·a_i            (age = lo + a, so age ≥ lo)
//   4. gap * 1 = Σ 2^i·a_i + Σ 2^i·b_i    (a + b = gap, so age ≤ hi)
// ---------------------------------------------------------------------------
const gap = hi - lo;
const k = Math.max(1, Math.ceil(Math.log2(gap + 1)));

// ---------------------------------------------------------------------------
// WITNESS LAYOUT
// ─────────────────────────────────────
// The witness is every value the circuit depends on.  Each value gets an
// index so the R1CS row vectors can "pick" it via a dot product.
//
//   w = [  1,  age,  a0, a1, ..., a_{k-1},  b0, b1, ..., b_{k-1}  ]
//         [0]  [1]   [2 ── k+1]              [k+2 ── 2k+1]
//          ↑    ↑    └── k bits of a ──┘      └── k bits of b ──┘
//        const  secret  a = age − lo           b = hi − age
//
// Length = 2 + 2k.
//
// PATH FROM CONSTRAINTS TO THE VERIFICATION EQUATION
// ─────────────────────────────────────────────────────
//
// Step 1 — R1CS
//   Each constraint is written as: (A_row · w) * (B_row · w) = (C_row · w)
//   A_row, B_row, C_row are sparse vectors that select the right witness values.
//   We have numConstraints = 2k+2 such rows → matrices A, B, C of size (2k+2) × (2+2k).
//
// Step 2 — Assign constraint points
//   Each constraint row i is "evaluated" at a distinct field point x = i+1.
//   So constraint 1 lives at x=1, constraint 2 at x=2, ..., constraint 2k+2 at x=2k+2.
//
// Step 3 — Evaluate R1CS at the witness
//   For each constraint point x=j, compute the three scalar values:
//     aVals[j] = A_row_j · w      (a scalar)
//     bVals[j] = B_row_j · w
//     cVals[j] = C_row_j · w
//   If the constraint is satisfied:  aVals[j] * bVals[j] = cVals[j]
//
// Step 4 — Lagrange interpolation
//   Build polynomials A(x), B(x), C(x) of degree ≤ 2k+1 such that:
//     A(j) = aVals[j],   B(j) = bVals[j],   C(j) = cVals[j]   for j = 1..2k+2
//   These polynomials encode all constraint values at once.
//
// Step 5 — QAP polynomial P(x)
//   Define  P(x) = A(x)·B(x) − C(x)
//   If all constraints are satisfied, then P(j) = 0 at every j ∈ {1..2k+2}.
//
// Step 6 — Divisibility by Z(x)
//   Z(x) = (x−1)(x−2)···(x−(2k+2))  vanishes at exactly those points.
//   P(j)=0 for all j means Z(x) divides P(x) with no remainder:
//     P(x) = H(x) · Z(x)
//   The prover computes H(x) = P(x)/Z(x) via polynomial long division.
//   A non-zero remainder would mean at least one constraint was violated.
//
// Step 7 — Fiat–Shamir single-point check
//   The verifier picks a random field point r (derived from a hash of the
//   committed polynomial coefficients — this is the Fiat–Shamir transform).
//   By the Schwartz–Zippel lemma: if P(x) ≠ H(x)·Z(x) as polynomials,
//   the probability they agree at a random r is at most deg(P)/|F| ≈ 2^−55.
//   So checking the identity at one point is almost as good as checking everywhere.
//
//   Final verification equation:
//     A(r)·B(r) − C(r)  ≡  H(r)·Z(r)   (mod 2^61−1)
//
//   This single equation simultaneously verifies all 2k+2 constraints.
// ---------------------------------------------------------------------------
const witnessLen = 2 + 2 * k;
const numConstraints = 2 * k + 2;
const CONSTRAINT_POINTS = Array.from({ length: numConstraints }, (_, i) => BigInt(i + 1));

function zeroRow() {
  return Array(witnessLen).fill(0);
}

// ---------------------------------------------------------------------------
// Build R1CS matrices (numConstraints rows × witnessLen cols)
//
// Each row is a sparse vector.  The dot product (row · w) picks out whatever
// combination of witness values is needed for that side of the constraint.
// ---------------------------------------------------------------------------
const A = [];
const B = [];
const C = [];

// Constraints 1..k: a_i * (a_i - 1) = 0
// ─────────────────────────────────────
// We want to force a_i ∈ {0, 1}.
// The only values that satisfy x*(x−1)=0 are x=0 and x=1.
// R1CS encoding:
//   A_row picks a_i   →  only entry 1 at index (2+i)
//   B_row picks a_i−1 →  entry −1 at index 0 (the constant slot) + 1 at index (2+i)
//                        because (−1)·w[0] + 1·w[2+i] = −1 + a_i = a_i − 1
//   C_row is all zeros →  result must be 0
for (let i = 0; i < k; i++) {
  const aRow = zeroRow(), bRow = zeroRow(), cRow = zeroRow();
  aRow[2 + i] = 1;
  bRow[0] = -1; bRow[2 + i] = 1;
  A.push(aRow); B.push(bRow); C.push(cRow);
}

// Constraints k+1..2k: b_i * (b_i - 1) = 0  — same pattern for b-bits
for (let i = 0; i < k; i++) {
  const aRow = zeroRow(), bRow = zeroRow(), cRow = zeroRow();
  aRow[2 + k + i] = 1;
  bRow[0] = -1; bRow[2 + k + i] = 1;
  A.push(aRow); B.push(bRow); C.push(cRow);
}

// Constraint 2k+1: age * 1 = lo + a0 + 2·a1 + 4·a2 + ... + 2^(k-1)·a_{k-1}
// ─────────────────────────────────────
// This encodes:  age = lo + a   →   age ≥ lo
// R1CS encoding:
//   A_row picks age                  →  entry 1 at index 1
//   B_row picks the constant 1       →  entry 1 at index 0
//   C_row picks lo + Σ(2^i · a_i)   →  lo at index 0, then 1,2,4,... at a-bit indices
//   Because (A·w)*(B·w) = age*1 = age  and  (C·w) = lo + a,  the constraint is age = lo + a
{
  const aRow = zeroRow(), bRow = zeroRow(), cRow = zeroRow();
  aRow[1] = 1;
  bRow[0] = 1;
  cRow[0] = lo;
  for (let i = 0; i < k; i++) cRow[2 + i] = 2 ** i;
  A.push(aRow); B.push(bRow); C.push(cRow);
}

// Constraint 2k+2: gap * 1 = (a0 + 2·a1 + ...) + (b0 + 2·b1 + ...)
// ─────────────────────────────────────
// This encodes:  a + b = gap   →   combined with the above, age ≤ hi
// Proof:  a + b = gap = hi − lo,  a = age − lo  →  b = hi − age  ≥ 0  →  age ≤ hi
// R1CS encoding:
//   A_row picks gap (a constant)     →  entry 'gap' at index 0  (gap * w[0] = gap * 1)
//   B_row picks the constant 1       →  entry 1 at index 0
//   C_row picks Σ(2^i·a_i) + Σ(2^i·b_i) →  powers of 2 at both a-bit and b-bit indices
{
  const aRow = zeroRow(), bRow = zeroRow(), cRow = zeroRow();
  aRow[0] = gap;
  bRow[0] = 1;
  for (let i = 0; i < k; i++) cRow[2 + i] = 2 ** i;
  for (let i = 0; i < k; i++) cRow[2 + k + i] = 2 ** i;
  A.push(aRow); B.push(bRow); C.push(cRow);
}

// ---------------------------------------------------------------------------
// Field / polynomial helpers
// ---------------------------------------------------------------------------
function mod(n, p) {
  return ((n % p) + p) % p;
}

function mulPoly(a, b, p) {
  const out = Array(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i += 1) {
    for (let j = 0; j < b.length; j += 1) {
      out[i + j] = mod(out[i + j] + a[i] * b[j], p);
    }
  }
  return out;
}

function polyFromRoots(roots, p) {
  let poly = [1n];
  for (const r of roots) {
    poly = mulPoly(poly, [mod(-r, p), 1n], p);
  }
  return poly;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

// ---------------------------------------------------------------------------
// Target polynomial Z(x) = ∏_{i=1}^{numConstraints} (x - i)
// ---------------------------------------------------------------------------
const Z = polyFromRoots(CONSTRAINT_POINTS, PRIME);

// ---------------------------------------------------------------------------
// Circuit digest — binds proofs to THIS exact circuit (range + R1CS)
// ---------------------------------------------------------------------------
const circuitData = JSON.stringify({
  prime: PRIME.toString(),
  lo,
  hi,
  constraintPoints: CONSTRAINT_POINTS.map(String),
  r1cs: { A, B, C },
});
const circuitDigest = sha256Hex(circuitData);

// ---------------------------------------------------------------------------
// Proving key / Verification key
// ---------------------------------------------------------------------------
const witnessLayout = ["1", "age"];
for (let i = 0; i < k; i++) witnessLayout.push(`a${i}`);
for (let i = 0; i < k; i++) witnessLayout.push(`b${i}`);

const constraintsDescription = [];
for (let i = 0; i < k; i++) constraintsDescription.push(`a${i} * (a${i} - 1) = 0  [a-bit ${i} boolean]`);
for (let i = 0; i < k; i++) constraintsDescription.push(`b${i} * (b${i} - 1) = 0  [b-bit ${i} boolean]`);
constraintsDescription.push(`age * 1 = ${lo} + ${Array.from({length:k},(_,i)=>`${2**i}*a${i}`).join(" + ")}  [age = lo + a]`);
constraintsDescription.push(`${gap} * 1 = ${[...Array.from({length:k},(_,i)=>`${2**i}*a${i}`),...Array.from({length:k},(_,i)=>`${2**i}*b${i}`)].join(" + ")}  [a + b = gap]`);

const provingKey = {
  prime: PRIME.toString(),
  range: { lo, hi },
  k,
  witnessLayout,
  constraintsDescription,
  constraintPoints: CONSTRAINT_POINTS.map(String),
  r1cs: { A, B, C },
  targetPolynomial: {
    name: "Z(x)",
    coeffsLowToHighDegree: Z.map(String),
    display: CONSTRAINT_POINTS.map((pt) => `(x-${pt})`).join(""),
  },
  circuitDigest,
};

const verificationKey = {
  prime: PRIME.toString(),
  range: { lo, hi },
  constraintPoints: CONSTRAINT_POINTS.map(String),
  targetPolynomial: {
    name: "Z(x)",
    coeffsLowToHighDegree: Z.map(String),
    display: CONSTRAINT_POINTS.map((pt) => `(x-${pt})`).join(""),
  },
  circuitDigest,
};

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
console.log("========== SETUP START ==========");

console.log(`\n[Setup] ===== Range & Circuit Parameters =====`);
console.log(`[Setup] Proving range: age ∈ [${lo}, ${hi}]`);
console.log(`[Setup] gap = hi - lo = ${gap}`);
console.log(`[Setup] k = ⌈log₂(gap+1)⌉ = ${k}  bits needed to represent a and b`);
console.log(`[Setup] Witness layout (length ${witnessLen}):`);
console.log(`[Setup]   w[0]        = 1 (constant)`);
console.log(`[Setup]   w[1]        = age (secret)`);
console.log(`[Setup]   w[2..${k+1}]  = a-bits (a = age - lo, encodes left  distance)`);
console.log(`[Setup]   w[${k+2}..${2*k+1}] = b-bits (b = hi  - age, encodes right distance)`);
console.log(`[Setup]`);
console.log(`[Setup] Soundness: the prover must produce k-bit witnesses a and b`);
console.log(`[Setup] such that a + b = gap.  Since a,b ≥ 0 and a + b = hi-lo,`);
console.log(`[Setup] we get  lo ≤ age ≤ hi.`);

console.log(`\n[Setup] ===== Prime Field =====`);
console.log(`[Setup] p = ${PRIME}  (2^61 - 1, Mersenne prime)`);
console.log(`[Setup] Schwartz-Zippel soundness error = deg(P) / |F|`);
console.log(`[Setup]   deg(P) ≈ 2*(${numConstraints}-1) = ${2*(numConstraints-1)}`);
console.log(`[Setup]   error  ≈ ${2*(numConstraints-1)} / 2^61  (negligible)`);

console.log(`\n[Setup] ===== Constraints (${numConstraints} total) =====`);
constraintsDescription.forEach((d, i) => console.log(`[Setup]   ${i+1}. ${d}`));

console.log(`\n[Setup] ===== R1CS Matrices (${numConstraints} rows × ${witnessLen} cols) =====`);
console.log(`[Setup] Matrix A:`);
A.forEach((row, i) => console.log(`[Setup]   row ${i+1}: [${row.join(", ")}]`));
console.log(`[Setup] Matrix B:`);
B.forEach((row, i) => console.log(`[Setup]   row ${i+1}: [${row.join(", ")}]`));
console.log(`[Setup] Matrix C:`);
C.forEach((row, i) => console.log(`[Setup]   row ${i+1}: [${row.join(", ")}]`));

console.log(`\n[Setup] ===== Target Polynomial Z(x) =====`);
console.log(`[Setup] Z(x) = ∏_{i=1}^{${numConstraints}} (x-i) — vanishes at each constraint point.`);
console.log(`[Setup] Z(x) coefficients (low->high): [${Z.map(String).join(", ")}]`);
console.log(`[Setup] Verify Z vanishes at constraint points:`);
for (const pt of CONSTRAINT_POINTS) {
  const val = mod(Z.reduce((acc, c, i) => acc + c * pt**BigInt(i), 0n), PRIME);
  console.log(`[Setup]   Z(${pt}) = ${val}  (expected 0)`);
}

console.log(`\n[Setup] ===== Circuit Digest =====`);
console.log(`[Setup] circuitDigest = sha256(JSON({prime, lo, hi, constraintPoints, r1cs}))`);
console.log(`[Setup] circuitDigest = ${circuitDigest}`);
console.log(`[Setup] Embeds the range [${lo},${hi}] — a proof for a different range will fail.`);

fs.writeFileSync("proving_key.json", JSON.stringify(provingKey, null, 2), "utf8");
fs.writeFileSync("verification_key.json", JSON.stringify(verificationKey, null, 2), "utf8");

console.log(`\n[Setup] proving_key.json written.`);
console.log(`[Setup] verification_key.json written.`);
console.log("=========== SETUP END ===========");
