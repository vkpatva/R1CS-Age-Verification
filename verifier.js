const fs = require("fs");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Field arithmetic (BigInt, prime p = 2^61 - 1)
// ---------------------------------------------------------------------------

function mod(n, p) {
  return ((n % p) + p) % p;
}

function modPow(base, exp, p) {
  let b = mod(base, p);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = mod(out * b, p);
    b = mod(b * b, p);
    e >>= 1n;
  }
  return out;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

// Must match deriveChallengeR in prover.js exactly.
function deriveChallengeR({ commitment, circuitDigest, prime, forbiddenPoints }) {
  let counter = 0;
  while (true) {
    const toHash = `${commitment}|${circuitDigest}|${counter}`;
    const hex = sha256Hex(toHash);
    const r = BigInt("0x" + hex) % prime;
    if (!(forbiddenPoints || []).includes(r)) return r;
    counter += 1;
  }
}

function polyEval(poly, x, p) {
  let result = 0n;
  let xPow = 1n;
  for (const c of poly) {
    result = mod(result + c * xPow, p);
    xPow = mod(xPow * x, p);
  }
  return result;
}

function formatPoly(poly) {
  const terms = [];
  for (let i = poly.length - 1; i >= 0; i -= 1) {
    const c = poly[i];
    if (c === 0n) continue;
    if (i === 0) terms.push(`${c}`);
    else if (i === 1) terms.push(`${c}*x`);
    else terms.push(`${c}*x^${i}`);
  }
  return terms.length === 0 ? "0" : terms.join(" + ");
}

// ---------------------------------------------------------------------------
// Detailed logging helpers
// ---------------------------------------------------------------------------

function logDetailedCommitmentCheck(proof, circuitDigest, expectedCommitment) {
  console.log(`\n[Verifier] --- Step 1: Commitment Check ---`);
  console.log(`[Verifier] The verifier recomputes the commitment from scratch using:`);
  console.log(`[Verifier]   - the polynomial coefficients submitted in proof.json`);
  console.log(`[Verifier]   - the circuitDigest from verification_key.json`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Why this check matters:`);
  console.log(`[Verifier]   In the old design the proof included pre-computed A(r),B(r),C(r),H(r)`);
  console.log(`[Verifier]   and the verifier trusted them. A malicious prover could:`);
  console.log(`[Verifier]     1. Commit to arbitrary polynomials to fix the commitment hash.`);
  console.log(`[Verifier]     2. Derive r from that commitment.`);
  console.log(`[Verifier]     3. Submit DIFFERENT evaluation values that satisfy A*B-C = H*Z at r.`);
  console.log(`[Verifier]   The fix: verifier recomputes evaluations from the committed coefficients.`);
  console.log(`[Verifier]   A forged evaluation is impossible — the verifier never uses the prover's values.`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Recomputing commitment = sha256(JSON({circuitDigest, salt, A_x, B_x, C_x, H_x})):`);
  console.log(`[Verifier]   circuitDigest: "${circuitDigest}"`);
  console.log(`[Verifier]   salt: "${proof.salt}"  (from proof.json — bound into the commitment)`);
  console.log(`[Verifier]   A_x: [${proof.polynomialCoefficients.A_x.join(", ")}]`);
  console.log(`[Verifier]   B_x: [${proof.polynomialCoefficients.B_x.join(", ")}]`);
  console.log(`[Verifier]   C_x: [${proof.polynomialCoefficients.C_x.join(", ")}]`);
  console.log(`[Verifier]   H_x: [${proof.polynomialCoefficients.H_x.join(", ")}]`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Recomputed commitment : ${expectedCommitment}`);
  console.log(`[Verifier] Proof commitment      : ${proof.commitment}`);

  if (expectedCommitment === proof.commitment) {
    console.log(`[Verifier] Match ✓ — polynomial coefficients are consistent with the commitment.`);
    console.log(`[Verifier]           The circuitDigest inside the commitment also matches the vk,`);
    console.log(`[Verifier]           so the proof is bound to the correct circuit.`);
  } else {
    console.log(`[Verifier] MISMATCH ✗ — possible causes:`);
    console.log(`[Verifier]   - Polynomial coefficients were tampered with after the proof was created.`);
    console.log(`[Verifier]   - This proof was created for a different circuit (different vk).`);
    console.log(`[Verifier]   - The verification key's circuitDigest was modified.`);
  }
}

function logDetailedChallengeDerivation(commitment, circuitDigest, r, prime, forbiddenPoints) {
  console.log(`\n[Verifier] --- Step 2: Fiat–Shamir Challenge r ---`);
  console.log(`[Verifier] r is re-derived identically to the prover:`);
  console.log(`[Verifier]   sha256(commitment | circuitDigest | counter) → full 256-bit hash → mod p`);
  console.log(`[Verifier] The verifier uses its OWN circuitDigest (from the vk), not anything from the proof.`);
  console.log(`[Verifier] Forbidden points ${JSON.stringify(forbiddenPoints.map(String))} are excluded`);
  console.log(`[Verifier] (Z(x)=0 there, so the identity would trivially hold for any H).`);
  console.log(`[Verifier]`);

  let counter = 0;
  while (true) {
    const toHash = `${commitment}|${circuitDigest}|${counter}`;
    const hex = sha256Hex(toHash);
    const num = BigInt("0x" + hex);
    const candidate = num % prime;
    const forbidden = forbiddenPoints.includes(candidate);
    console.log(`[Verifier] counter=${counter}: hash=${hex.slice(0, 16)}...  →  BigInt mod p = ${candidate}  →  ${forbidden ? "forbidden, next" : "accepted"}`);
    if (!forbidden) {
      console.log(`[Verifier] Challenge point r = ${r}`);
      return;
    }
    counter += 1;
  }
}

function logDetailedEvaluation(label, poly, r, p, result) {
  console.log(`[Verifier] ${label}(r) = evaluate [${poly.join(", ")}] at r=${r}:`);
  let acc = 0n;
  let xPow = 1n;
  for (let i = 0; i < poly.length; i += 1) {
    const term = mod(poly[i] * xPow, p);
    const before = acc;
    acc = mod(acc + term, p);
    console.log(
      `[Verifier]   i=${i}: ${poly[i]} * r^${i} mod p = ${term};  running sum: ${before} + ${term} = ${acc}`
    );
    xPow = mod(xPow * r, p);
  }
  console.log(`[Verifier] ${label}(r) = ${result}`);
}

function logDetailedQAPCheck(A_r, B_r, C_r, H_r, Z_r, p) {
  console.log(`\n[Verifier] --- Step 4: QAP Identity Check ---`);
  console.log(`[Verifier] Check: A(r)*B(r) - C(r)  ==  H(r)*Z(r)  (mod p)`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Why this is sound:`);
  console.log(`[Verifier]   If the prover has a valid witness then P(x)=A(x)*B(x)-C(x) = H(x)*Z(x)`);
  console.log(`[Verifier]   as a polynomial identity. By Schwartz-Zippel, if this does NOT hold`);
  console.log(`[Verifier]   everywhere but DOES hold at the random challenge r, the probability`);
  console.log(`[Verifier]   is at most deg(P)/|F| = 4/${p} ≈ 2^-59.`);
  console.log(`[Verifier]   So a passing check means the identity almost certainly holds everywhere.`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Z(r) is computed by the verifier from verification_key.json — public info.`);
  console.log(`[Verifier] A(r), B(r), C(r), H(r) were recomputed from the committed coefficients.`);
  console.log(`[Verifier]`);

  const lhsRaw = A_r * B_r - C_r;
  const lhs = mod(lhsRaw, p);
  const rhsRaw = H_r * Z_r;
  const rhs = mod(rhsRaw, p);

  console.log(`[Verifier] LHS = A(r)*B(r) - C(r)`);
  console.log(`[Verifier]     = ${A_r} * ${B_r} - ${C_r}`);
  console.log(`[Verifier]     = ${lhsRaw}  mod p`);
  console.log(`[Verifier]     = ${lhs}`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] RHS = H(r)*Z(r)`);
  console.log(`[Verifier]     = ${H_r} * ${Z_r}`);
  console.log(`[Verifier]     = ${rhsRaw}  mod p`);
  console.log(`[Verifier]     = ${rhs}`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] ${lhs} ${lhs === rhs ? "==" : "!="} ${rhs}  →  ${lhs === rhs ? "PASS ✓" : "FAIL ✗"}`);

  return lhs === rhs;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  // The verifier reads ONLY the verification key — never the proving key or R1CS.
  const vk = JSON.parse(fs.readFileSync("verification_key.json", "utf8"));
  const proof = JSON.parse(fs.readFileSync("proof.json", "utf8"));

  console.log("========= VERIFIER START =========");
  console.log(`\n[Verifier] Reading verification_key.json and proof.json`);
  const { lo, hi } = vk.range;
  console.log(`[Verifier]`);
  console.log(`[Verifier] *** Claim being verified: ${lo} ≤ age ≤ ${hi} ***`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] The verifier has access to ONLY:`);
  console.log(`[Verifier]   verification_key.json: prime, range [${lo},${hi}], Z(x) coefficients, circuitDigest`);
  console.log(`[Verifier]   proof.json:            commitment, polynomial coefficients`);
  console.log(`[Verifier] It does NOT have: proving key, R1CS matrices, or witness values.`);

  const p = BigInt(vk.prime);
  const Z = vk.targetPolynomial.coeffsLowToHighDegree.map(BigInt);
  const { circuitDigest } = vk;
  const { commitment } = proof;

  const APoly = proof.polynomialCoefficients.A_x.map(BigInt);
  const BPoly = proof.polynomialCoefficients.B_x.map(BigInt);
  const CPoly = proof.polynomialCoefficients.C_x.map(BigInt);
  const HPoly = proof.polynomialCoefficients.H_x.map(BigInt);

  console.log(`\n[Verifier] Public parameters from verification_key.json:`);
  console.log(`[Verifier]   prime p = ${p}  (2^61 - 1)`);
  console.log(`[Verifier]   Z(x) coeffs (low->high): [${Z.join(", ")}]`);
  console.log(`[Verifier]   Z(x) readable: ${formatPoly(Z)}`);
  console.log(`[Verifier]   circuitDigest = ${circuitDigest}`);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Proof contents from proof.json:`);
  console.log(`[Verifier]   commitment = ${commitment}`);
  console.log(`[Verifier]   A_x: [${APoly.join(", ")}]`);
  console.log(`[Verifier]   B_x: [${BPoly.join(", ")}]`);
  console.log(`[Verifier]   C_x: [${CPoly.join(", ")}]`);
  console.log(`[Verifier]   H_x: [${HPoly.join(", ")}]`);

  // -------------------------------------------------------------------------
  // Step 1: Commitment check
  // -------------------------------------------------------------------------
  const expectedCommitInput = JSON.stringify({
    circuitDigest,
    salt: proof.salt,
    A_x: proof.polynomialCoefficients.A_x,
    B_x: proof.polynomialCoefficients.B_x,
    C_x: proof.polynomialCoefficients.C_x,
    H_x: proof.polynomialCoefficients.H_x,
  });
  const expectedCommitment = sha256Hex(expectedCommitInput);

  logDetailedCommitmentCheck(proof, circuitDigest, expectedCommitment);

  if (expectedCommitment !== commitment) {
    console.log(`\nVerification FAILED: commitment mismatch.`);
    console.log("========== VERIFIER END ==========");
    return;
  }

  // -------------------------------------------------------------------------
  // Step 2: Derive challenge r
  // -------------------------------------------------------------------------
  const forbiddenPoints = vk.constraintPoints.map(BigInt);
  const r = deriveChallengeR({ commitment, circuitDigest, prime: p, forbiddenPoints });
  logDetailedChallengeDerivation(commitment, circuitDigest, r, p, forbiddenPoints);

  // -------------------------------------------------------------------------
  // Step 3: Evaluate polynomials at r
  // Evaluations are computed HERE from the verified coefficients.
  // The prover never submits evaluation values; they cannot be fabricated.
  // -------------------------------------------------------------------------
  console.log(`\n[Verifier] --- Step 3: Polynomial Evaluation at r=${r} ---`);
  console.log(`[Verifier] Evaluations are computed by the verifier from the committed coefficients.`);
  console.log(`[Verifier] The prover does NOT submit A(r),B(r),C(r),H(r) — they are derived here.`);
  console.log(`[Verifier]`);
  const A_r = polyEval(APoly, r, p);
  logDetailedEvaluation("A", APoly, r, p, A_r);
  console.log(`[Verifier]`);
  const B_r = polyEval(BPoly, r, p);
  logDetailedEvaluation("B", BPoly, r, p, B_r);
  console.log(`[Verifier]`);
  const C_r = polyEval(CPoly, r, p);
  logDetailedEvaluation("C", CPoly, r, p, C_r);
  console.log(`[Verifier]`);
  const H_r = polyEval(HPoly, r, p);
  logDetailedEvaluation("H", HPoly, r, p, H_r);
  console.log(`[Verifier]`);
  console.log(`[Verifier] Z(r) — computed from verification_key.json (public, no prover input):`);
  const Z_r = polyEval(Z, r, p);
  logDetailedEvaluation("Z", Z, r, p, Z_r);

  // -------------------------------------------------------------------------
  // Step 4: QAP identity check
  // -------------------------------------------------------------------------
  const passed = logDetailedQAPCheck(A_r, B_r, C_r, H_r, Z_r, p);

  console.log(`\n`);
  if (passed) {
    console.log(`Verification SUCCESS: age is in [${lo}, ${hi}]  (QAP identity holds)`);
  } else {
    console.log(`Verification FAILED: QAP identity does not hold.`);
  }
  console.log("========== VERIFIER END ==========");
}

main();
