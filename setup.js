const fs = require("fs");
const crypto = require("crypto");

// 2^61 - 1, a Mersenne prime.
// Why choose this prime?
//   - Soundness: the Schwartz-Zippel lemma says a false proof passes the
//     single-point check with probability at most deg(P)/|F|.
//     With |F| = 97 (original) that was ~4%.
//     With |F| = 2^61-1 that is ~4 / 2^61 ≈ 2^-59, negligible.
//   - Efficiency: 2^61-1 is a Mersenne prime, so reduction mod p can be
//     implemented efficiently (though we use plain BigInt here for clarity).
//   - Safety: all intermediate products a*b where a,b < p fit in a BigInt
//     without overflow (JS BigInt has arbitrary precision).
const PRIME = 2305843009213693951n; // 2^61 - 1
const CONSTRAINT_POINTS = [1n, 2n, 3n, 4n, 5n];

// R1CS matrices — small integer entries, stored as plain Numbers in JSON.
// Witness layout: [1, age, b0, b1, b2, b3]
//
// Each constraint has the form  (A_i · w) * (B_i · w) = (C_i · w)
// where · is the dot product and w is the witness vector.
//
// Constraint 1: b0 * (b0 - 1) = 0
//   A row: picks b0        → [0, 0, 1, 0, 0, 0]
//   B row: picks (b0 - 1)  → [-1, 0, 1, 0, 0, 0]
//   C row: equals 0        → [0, 0, 0, 0, 0, 0]
//
// Constraint 2: b1 * (b1 - 1) = 0
//   A row: picks b1        → [0, 0, 0, 1, 0, 0]
//   B row: picks (b1 - 1)  → [-1, 0, 0, 1, 0, 0]
//   C row: equals 0        → [0, 0, 0, 0, 0, 0]
//
// Constraint 3: b2 * (b2 - 1) = 0
//   A row: picks b2        → [0, 0, 0, 0, 1, 0]
//   B row: picks (b2 - 1)  → [-1, 0, 0, 0, 1, 0]
//   C row: equals 0        → [0, 0, 0, 0, 0, 0]
//
// Constraint 4: b3 * (b3 - 1) = 0
//   A row: picks b3        → [0, 0, 0, 0, 0, 1]
//   B row: picks (b3 - 1)  → [-1, 0, 0, 0, 0, 1]
//   C row: equals 0        → [0, 0, 0, 0, 0, 0]
//
// Constraint 5: age * 1 = b0 + 2*b1 + 4*b2 + 8*b3
//   A row: picks age              → [0, 1, 0, 0, 0, 0]
//   B row: picks 1                → [1, 0, 0, 0, 0, 0]
//   C row: picks b0+2*b1+4*b2+8*b3 → [0, 0, 1, 2, 4, 8]
const A = [
  [0, 0, 1, 0, 0, 0],
  [0, 0, 0, 1, 0, 0],
  [0, 0, 0, 0, 1, 0],
  [0, 0, 0, 0, 0, 1],
  [0, 1, 0, 0, 0, 0],
];

const B = [
  [-1, 0, 1, 0, 0, 0],
  [-1, 0, 0, 1, 0, 0],
  [-1, 0, 0, 0, 1, 0],
  [-1, 0, 0, 0, 0, 1],
  [1, 0, 0, 0, 0, 0],
];

const C = [
  [0, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0],
  [0, 0, 1, 2, 4, 8],
];

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

const Z = polyFromRoots(CONSTRAINT_POINTS, PRIME);

// -------------------------------------------------------------------------
// Circuit digest
//
// The circuit digest is sha256 of the canonical circuit description:
// prime + constraint points + R1CS matrices.
//
// Purpose: the digest is embedded in both keys. The prover includes it in
// the Fiat-Shamir commitment. The verifier re-derives the commitment using
// the digest from its verification key. Therefore:
//   - If the R1CS is tampered after setup, the digest won't match → proof fails.
//   - If a proof from a different circuit is presented, the digest won't match.
//
// This closes the "mutable requirements.json" gap where the verifier was
// previously trusting a file it had no integrity check over.
// -------------------------------------------------------------------------
const circuitData = JSON.stringify({
  prime: PRIME.toString(),
  constraintPoints: CONSTRAINT_POINTS.map(String),
  r1cs: { A, B, C },
});
const circuitDigest = sha256Hex(circuitData);

// -------------------------------------------------------------------------
// Proving key vs Verification key split
//
// In a real SNARK (Groth16, PLONK) the trusted setup produces two artifacts:
//
//   Proving key (pk)  — used by the prover; contains the full circuit encoding
//                       and large structured reference string (SRS).
//
//   Verification key (vk) — used by the verifier; a small digest of the
//                            circuit. The verifier never needs the full R1CS.
//
// Here we model that split:
//   proving_key.json      → full R1CS + Z(x) + circuit digest
//   verification_key.json → Z(x) + circuit digest only
//
// The verifier reads ONLY verification_key.json. It never has access to the
// R1CS matrices, which is the correct separation of concerns.
// -------------------------------------------------------------------------
const provingKey = {
  prime: PRIME.toString(),
  witnessLayout: ["1", "age", "b0", "b1", "b2", "b3"],
  constraintsDescription: [
    "b0 * (b0 - 1) = 0",
    "b1 * (b1 - 1) = 0",
    "b2 * (b2 - 1) = 0",
    "b3 * (b3 - 1) = 0",
    "age * 1 = b0 + 2*b1 + 4*b2 + 8*b3",
  ],
  constraintPoints: CONSTRAINT_POINTS.map(String),
  r1cs: { A, B, C },
  targetPolynomial: {
    name: "Z(x)",
    coeffsLowToHighDegree: Z.map(String),
    display: "(x-1)(x-2)(x-3)(x-4)(x-5)",
  },
  circuitDigest,
};

const verificationKey = {
  prime: PRIME.toString(),
  constraintPoints: CONSTRAINT_POINTS.map(String),
  targetPolynomial: {
    name: "Z(x)",
    coeffsLowToHighDegree: Z.map(String),
    display: "(x-1)(x-2)(x-3)(x-4)(x-5)",
  },
  circuitDigest,
};

// -------------------------------------------------------------------------
// Logging
// -------------------------------------------------------------------------
console.log("========== SETUP START ==========");

console.log("\n[Setup] ===== Prime Field =====");
console.log(`[Setup] Using F_p where p = ${PRIME}  (2^61 - 1, Mersenne prime)`);
console.log(`[Setup] Why a large prime?`);
console.log(`[Setup]   Schwartz-Zippel soundness error = deg(P) / |F|`);
console.log(`[Setup]   With F_97 (original): error ≈ 4/97 ≈ 4.1%  — unacceptably high`);
console.log(`[Setup]   With F_(2^61-1):      error ≈ 4/2^61 ≈ 2^-59 — negligible`);
console.log(`[Setup] All arithmetic uses JS BigInt so intermediate products never overflow.`);

console.log("\n[Setup] ===== Witness & Constraints =====");
console.log(`[Setup] Witness layout: w = [1, age, b0, b1, b2, b3]`);
console.log(`[Setup]   Index 0: constant 1 (allows encoding constants in linear combinations)`);
console.log(`[Setup]   Index 1: age       (the secret value we are proving is in [0,15])`);
console.log(`[Setup]   Index 2: b0        (bit 0, weight 1)`);
console.log(`[Setup]   Index 3: b1        (bit 1, weight 2)`);
console.log(`[Setup]   Index 4: b2        (bit 2, weight 4)`);
console.log(`[Setup]   Index 5: b3        (bit 3, weight 8)`);
console.log(`[Setup] Constraints:`);
console.log(`[Setup]   1. b0 * (b0 - 1) = 0                    — forces b0 ∈ {0, 1} (boolean bit)`);
console.log(`[Setup]   2. b1 * (b1 - 1) = 0                    — forces b1 ∈ {0, 1} (boolean bit)`);
console.log(`[Setup]   3. b2 * (b2 - 1) = 0                    — forces b2 ∈ {0, 1} (boolean bit)`);
console.log(`[Setup]   4. b3 * (b3 - 1) = 0                    — forces b3 ∈ {0, 1} (boolean bit)`);
console.log(`[Setup]   5. age * 1 = b0 + 2*b1 + 4*b2 + 8*b3  — 4-bit binary decomposition`);
console.log(`[Setup] Together these imply: age ∈ {0, 1, ..., 15}`);

console.log("\n[Setup] ===== R1CS Matrices =====");
console.log(`[Setup] R1CS encodes each constraint i as: (A_i·w) * (B_i·w) = (C_i·w)`);
console.log(`[Setup] Matrix A (left operand of each constraint):`);
A.forEach((row, i) => console.log(`[Setup]   row ${i + 1}: ${JSON.stringify(row)}`));
console.log(`[Setup] Matrix B (right operand):`);
B.forEach((row, i) => console.log(`[Setup]   row ${i + 1}: ${JSON.stringify(row)}`));
console.log(`[Setup] Matrix C (result):`);
C.forEach((row, i) => console.log(`[Setup]   row ${i + 1}: ${JSON.stringify(row)}`));

console.log("\n[Setup] ===== Target Polynomial Z(x) =====");
console.log(`[Setup] Constraints are evaluated at points x = 1, 2, 3, 4, 5.`);
console.log(`[Setup] Z(x) must equal zero at each constraint point so that`);
console.log(`[Setup] the QAP divisibility check  P(x) = H(x)*Z(x)  makes sense.`);
console.log(`[Setup] Z(x) = (x-1)(x-2)(x-3)(x-4)(x-5)`);
console.log(`[Setup] Z(x) coefficients (low->high): [${Z.map(String).join(", ")}]`);
console.log(`[Setup] Verify Z vanishes at each constraint point:`);
for (const pt of CONSTRAINT_POINTS) {
  const val = mod(Z.reduce((acc, c, i) => acc + c * pt**BigInt(i), 0n), PRIME);
  console.log(`[Setup]   Z(${pt}) = ${val} (expected 0)`);
}

console.log("\n[Setup] ===== Circuit Digest =====");
console.log(`[Setup] The circuit digest is sha256 of the canonical circuit description:`);
console.log(`[Setup]   input = JSON({prime, constraintPoints, r1cs:{A,B,C}})`);
console.log(`[Setup] Purpose: binds every proof to THIS exact circuit.`);
console.log(`[Setup]   - Prover embeds circuitDigest in the Fiat-Shamir commitment.`);
console.log(`[Setup]   - Verifier re-derives commitment using circuitDigest from its vk.`);
console.log(`[Setup]   - Tampering with R1CS after setup → different digest → commitment mismatch.`);
console.log(`[Setup] circuitDigest = ${circuitDigest}`);

console.log("\n[Setup] ===== Proving Key / Verification Key Split =====");
console.log(`[Setup] proving_key.json    — for the prover; contains full R1CS + Z(x) + digest`);
console.log(`[Setup] verification_key.json — for the verifier; contains Z(x) + digest ONLY`);
console.log(`[Setup] The verifier never needs the R1CS matrices. Keeping them out of the vk`);
console.log(`[Setup] models the pk/vk separation used in production SNARKs (Groth16, PLONK).`);

fs.writeFileSync("proving_key.json", JSON.stringify(provingKey, null, 2), "utf8");
fs.writeFileSync("verification_key.json", JSON.stringify(verificationKey, null, 2), "utf8");

console.log(`\n[Setup] proving_key.json written.`);
console.log(`[Setup] verification_key.json written.`);
console.log("=========== SETUP END ===========");
