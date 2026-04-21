const fs = require("fs");
const crypto = require("crypto");
const kzg = require("./kzg");

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

function modInv(n, p) {
  if (mod(n, p) === 0n) throw new Error("Attempted inversion of 0 in finite field.");
  // Fermat's little theorem: n^(p-2) ≡ n^(-1)  (mod p)  when p is prime.
  return modPow(n, p - 2n, p);
}

// ---------------------------------------------------------------------------
// Polynomial arithmetic (coefficients are BigInt, ordered low→high degree)
// ---------------------------------------------------------------------------

function polyTrim(poly) {
  const out = poly.slice();
  while (out.length > 1 && out[out.length - 1] === 0n) out.pop();
  return out;
}

function polyAdd(a, b, p) {
  const len = Math.max(a.length, b.length);
  const out = Array(len).fill(0n);
  for (let i = 0; i < len; i += 1) out[i] = mod((a[i] || 0n) + (b[i] || 0n), p);
  return polyTrim(out);
}

function polySub(a, b, p) {
  const len = Math.max(a.length, b.length);
  const out = Array(len).fill(0n);
  for (let i = 0; i < len; i += 1) out[i] = mod((a[i] || 0n) - (b[i] || 0n), p);
  return polyTrim(out);
}

function polyMul(a, b, p) {
  const out = Array(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i += 1) {
    for (let j = 0; j < b.length; j += 1) {
      out[i + j] = mod(out[i + j] + a[i] * b[j], p);
    }
  }
  return polyTrim(out);
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

function polyDiv(numerator, denominator, p) {
  const num = numerator.slice();
  const den = polyTrim(denominator);
  const denDeg = den.length - 1;
  if (denDeg < 0 || (denDeg === 0 && den[0] === 0n)) {
    throw new Error("Division by zero polynomial.");
  }
  const quotient = Array(Math.max(0, num.length - den.length + 1)).fill(0n);
  while (polyTrim(num).length - 1 >= denDeg) {
    const curDeg = polyTrim(num).length - 1;
    const scale = mod(num[curDeg] * modInv(den[denDeg], p), p);
    const shift = curDeg - denDeg;
    quotient[shift] = scale;
    for (let i = 0; i <= denDeg; i += 1) {
      num[i + shift] = mod(num[i + shift] - scale * den[i], p);
    }
  }
  return { quotient: polyTrim(quotient), remainder: polyTrim(num) };
}

function dot(row, witness, p) {
  let s = 0n;
  for (let i = 0; i < row.length; i += 1) s = mod(s + row[i] * witness[i], p);
  return s;
}

function lagrangeInterpolate(xs, ys, p) {
  let result = [0n];
  for (let i = 0; i < xs.length; i += 1) {
    let basis = [1n];
    let denom = 1n;
    for (let j = 0; j < xs.length; j += 1) {
      if (i === j) continue;
      basis = polyMul(basis, [mod(-xs[j], p), 1n], p);
      denom = mod(denom * mod(xs[i] - xs[j], p), p);
    }
    const scale = mod(ys[i] * modInv(denom, p), p);
    basis = basis.map((c) => mod(c * scale, p));
    result = polyAdd(result, basis, p);
  }
  return polyTrim(result);
}

// ---------------------------------------------------------------------------
// Fiat–Shamir challenge derivation
// ---------------------------------------------------------------------------

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

function deriveChallengeR({ commitment, circuitDigest, prime, forbiddenPoints }) {
  let counter = 0;
  while (true) {
    const toHash = `${commitment}|${circuitDigest}|${counter}`;
    const hex = sha256Hex(toHash);
    // Use the full 256-bit hash as a BigInt before reducing mod p.
    // This minimises modular bias: bias = (2^256 mod p) / p < 2^-195 for a 61-bit p.
    const r = BigInt("0x" + hex) % prime;
    if (!(forbiddenPoints || []).includes(r)) return r;
    counter += 1;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toBits(value, k) {
  return Array.from({ length: k }, (_, i) => BigInt((value >> i) & 1));
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
// Detailed logging functions
// ---------------------------------------------------------------------------

// Explains the Lagrange interpolation for one of A(x), B(x), or C(x).
// The basis polynomials are computed dynamically (not hardcoded) so the
// explanation is always correct regardless of which prime or constraint
// points are in use.
function logDetailedLagrangeForLabel(label, xs, vals, p) {
  const n = xs.length;

  // Compute all n basis polynomials L_i(x).
  //   L_i(x) = 1 at x=xs[i], 0 at all other xs[j].
  //   Formula: L_i(x) = ∏_{j≠i} (x - xs[j]) / ∏_{j≠i} (xs[i] - xs[j])
  const bases = xs.map((xi, i) => {
    let num = [1n];
    let denom = 1n;
    for (let j = 0; j < xs.length; j += 1) {
      if (i === j) continue;
      num = polyMul(num, [mod(-xs[j], p), 1n], p);
      denom = mod(denom * mod(xi - xs[j], p), p);
    }
    const invDenom = modInv(denom, p);
    return { poly: num.map((c) => mod(c * invDenom, p)), denom, invDenom };
  });

  console.log(`\n[Prover] --- Detailed Lagrange interpolation for ${label}(x) ---`);
  console.log(`[Prover] Goal: find a degree-≤${n-1} polynomial passing through ${n} points:`);
  const pointsStr = xs.map((x, i) => `${label}(${x})=${vals[i]}`).join(",  ");
  console.log(`[Prover]   ${pointsStr}`);
  const basisNames = xs.map((_, i) => `L${i+1}(x)`).join(" + ... + ");
  console.log(`[Prover] Method: ${label}(x) = Σ vals[i]*L_i(x)  where each L_i(x) = 1 at xs[i], 0 elsewhere.`);

  for (let i = 0; i < n; i += 1) {
    const xi = xs[i];
    const roots = xs.filter((_, j) => j !== i);
    const rootsStr = roots.map((r) => `(x-${r})`).join("");
    const denomTerms = roots.map((r) => `(${xi}-${r})`).join("*");
    console.log(`\n[Prover] L${i+1}(x) = ${rootsStr} / (${denomTerms})`);
    console.log(`[Prover]   numerator degree: ${roots.length}`);
    console.log(`[Prover]   denominator (field element): ${bases[i].denom}  →  inv = ${bases[i].invDenom}`);
    console.log(`[Prover]   L${i+1}(x) coeffs (low->high): [${bases[i].poly.join(", ")}]`);
    console.log(`[Prover]   L${i+1}(x) readable: ${formatPoly(bases[i].poly)}`);
    const verifyStr = xs.map((xv, j) => `L${i+1}(${xv})=${polyEval(bases[i].poly, xv, p)}`).join(", ");
    const expectedStr = xs.map((_, j) => j === i ? 1 : 0).join(", ");
    console.log(`[Prover]   Verify: ${verifyStr}  (expected: ${expectedStr})`);
  }

  // Combination
  console.log(`\n[Prover] Combine: ${label}(x) = ${vals.map((v, i) => `${v}*L${i+1}(x)`).join(" + ")}`);
  const maxDeg = n - 1;
  console.log(`[Prover] Compute each coefficient by summing the scaled basis coefficients:`);
  for (let deg = maxDeg; deg >= 0; deg -= 1) {
    const terms = bases.map((b, i) => `${vals[i]}*${b.poly[deg] || 0n}`).join(" + ");
    const result = mod(bases.reduce((acc, b, i) => acc + vals[i] * (b.poly[deg] || 0n), 0n), p);
    console.log(`[Prover]   x^${deg}: ${terms}  mod p  =  ${result}`);
  }
  const finalPoly = lagrangeInterpolate(xs, vals, p);
  console.log(`[Prover] ${label}(x) coeffs (low->high): [${finalPoly.join(", ")}]`);
  console.log(`[Prover] ${label}(x) readable: ${formatPoly(finalPoly)}`);
  const verifyStr = xs.map((x, i) => `${label}(${x})=${polyEval(finalPoly, x, p)}`).join(", ");
  const expectedStr = vals.join(", ");
  console.log(`[Prover] Verify: ${verifyStr}  (expected ${expectedStr})`);
}

// Explains the step-by-step multiplication A(x)*B(x) and subtraction of C(x)
// to form P(x) = A(x)*B(x) - C(x).
function logDetailedPComputation(APoly, BPoly, CPoly, p) {
  console.log(`\n[Prover] --- Detailed computation of P(x) = A(x)*B(x) - C(x) ---`);
  console.log(`[Prover] A(x) = ${formatPoly(APoly)}`);
  console.log(`[Prover] B(x) = ${formatPoly(BPoly)}`);
  console.log(`[Prover]`);
  console.log(`[Prover] Multiplying A(x) * B(x) term-by-term (each coeff*coeff contributes to degree i+j):`);
  console.log(`[Prover] We reduce mod p = ${p} after each accumulation.`);

  const mult = Array(APoly.length + BPoly.length - 1).fill(0n);
  for (let i = 0; i < APoly.length; i += 1) {
    for (let j = 0; j < BPoly.length; j += 1) {
      const deg = i + j;
      const before = mult[deg];
      mult[deg] = mod(mult[deg] + APoly[i] * BPoly[j], p);
      console.log(
        `[Prover]   (${APoly[i]}*x^${i}) * (${BPoly[j]}*x^${j})  →  adds to x^${deg}:  ${before} + (${APoly[i]}*${BPoly[j]} mod p) = ${mult[deg]} mod p`
      );
    }
  }
  console.log(`[Prover] A(x)*B(x) coeffs (low->high): [${mult.join(", ")}]`);
  console.log(`[Prover] A(x)*B(x) readable: ${formatPoly(mult)}`);

  console.log(`\n[Prover] Now subtract C(x) coefficient-by-coefficient:`);
  console.log(`[Prover] C(x) coeffs (low->high): [${CPoly.join(", ")}]`);
  const len = Math.max(mult.length, CPoly.length);
  const pCoeffs = Array(len).fill(0n);
  for (let d = 0; d < len; d += 1) {
    const left = mult[d] || 0n;
    const right = CPoly[d] || 0n;
    pCoeffs[d] = mod(left - right, p);
    console.log(
      `[Prover]   x^${d}: (${left}) - (${right}) mod p = ${pCoeffs[d]}`
    );
  }
  console.log(`[Prover] P(x) = A(x)*B(x) - C(x) coeffs (low->high): [${pCoeffs.join(", ")}]`);
  console.log(`[Prover] P(x) readable: ${formatPoly(pCoeffs)}`);
}

// Explains the target polynomial Z(x) and why it has the form it does.
function logDetailedZExplanation(Z, constraintPoints, p) {
  const ptStr = constraintPoints.map(String).join(", ");
  const factors = constraintPoints.map((pt) => `(x-${pt})`).join("");
  console.log(`\n[Prover] --- Target polynomial Z(x) explained ---`);
  console.log(`[Prover] Constraint points are x = ${ptStr}.`);
  console.log(`[Prover] Z(x) must vanish at each constraint point: ${constraintPoints.map((pt) => `Z(${pt})=0`).join(", ")}.`);
  console.log(`[Prover] We construct Z(x) = ${factors}.`);
  console.log(`[Prover] Z(x) coeffs (low->high): [${Z.join(", ")}]`);
  console.log(`[Prover] Z(x) readable: ${formatPoly(Z)}`);
  console.log(`[Prover] Verify Z vanishes at each constraint point:`);
  for (const pt of constraintPoints) {
    const val = mod(Z.reduce((acc, c, i) => acc + c * pt**BigInt(i), 0n), p);
    console.log(`[Prover]   Z(${pt}) = ${val}  (expected 0)`);
  }
  console.log(`[Prover] Why this matters: if the witness satisfies all constraints,`);
  console.log(`[Prover]   then P(x) = A(x)*B(x) - C(x) evaluates to 0 at x=${ptStr},`);
  console.log(`[Prover]   so Z(x) divides P(x) exactly — remainder = 0.`);
  console.log(`[Prover] An invalid witness will leave a non-zero remainder.`);
}

// Shows the long division P(x) / Z(x) step-by-step, yielding H(x).
function detailedPolyDiv(numerator, denominator, p) {
  const num = numerator.slice();
  const den = polyTrim(denominator);
  const quotient = Array(Math.max(0, num.length - den.length + 1)).fill(0n);

  console.log(`\n[Prover] --- Detailed long division: H(x) = P(x) / Z(x) ---`);
  console.log(`[Prover] P(x) coeffs (low->high): [${num.join(", ")}]`);
  console.log(`[Prover] Z(x) coeffs (low->high): [${den.join(", ")}]`);
  console.log(`[Prover] P(x) readable: ${formatPoly(num)}`);
  console.log(`[Prover] Z(x) readable: ${formatPoly(den)}`);
  console.log(`[Prover] Method: polynomial long division in F_p.`);
  console.log(`[Prover]   At each step, cancel the current leading term of the remainder`);
  console.log(`[Prover]   by computing  scale = leadCoeff(remainder) * modInv(leadCoeff(Z), p)`);
  console.log(`[Prover]   then subtract scale*x^shift * Z(x) from the remainder.`);

  while (polyTrim(num).length - 1 >= den.length - 1) {
    const curDeg = polyTrim(num).length - 1;
    const denDeg = den.length - 1;
    const leadNum = num[curDeg];
    const leadDen = den[denDeg];
    const invLeadDen = modInv(leadDen, p);
    const scale = mod(leadNum * invLeadDen, p);
    const shift = curDeg - denDeg;
    quotient[shift] = scale;

    console.log(`\n[Prover] Step: cancel x^${curDeg} term`);
    console.log(
      `[Prover]   Leading coeff of remainder: ${leadNum}`
    );
    console.log(
      `[Prover]   Leading coeff of Z(x):      ${leadDen}`
    );
    console.log(
      `[Prover]   scale = ${leadNum} * modInv(${leadDen}, p) = ${leadNum} * ${invLeadDen} mod p = ${scale}`
    );
    console.log(`[Prover]   shift = ${curDeg} - ${denDeg} = ${shift}`);
    console.log(
      `[Prover]   Add ${scale}*x^${shift} to quotient → H coeffs so far (low->high): [${polyTrim(quotient).join(", ")}]`
    );
    console.log(`[Prover]   Subtract (${scale}*x^${shift}) * Z(x) from remainder:`);

    for (let i = 0; i <= denDeg; i += 1) {
      const idx = i + shift;
      const subTerm = mod(scale * den[i], p);
      const before = num[idx];
      num[idx] = mod(num[idx] - subTerm, p);
      console.log(
        `[Prover]     x^${idx}: ${before} - (${scale}*${den[i]} mod p = ${subTerm}) → ${num[idx]}`
      );
    }
    console.log(
      `[Prover]   Remainder after step (low->high): [${polyTrim(num).join(", ")}]`
    );
  }

  const remainder = polyTrim(num);
  console.log(`\n[Prover] Final H(x) coeffs (low->high): [${polyTrim(quotient).join(", ")}]`);
  console.log(`[Prover] Final H(x) readable: ${formatPoly(polyTrim(quotient))}`);
  console.log(`[Prover] Remainder (low->high): [${remainder.join(", ")}]`);
  if (remainder.length === 1 && remainder[0] === 0n) {
    console.log(`[Prover] Remainder = 0 ✓  Z(x) divides P(x) exactly.`);
    console.log(`[Prover] QAP form: P(x) = H(x) * Z(x)  holds as a polynomial identity.`);
  } else {
    console.log(`[Prover] Remainder ≠ 0 ✗  Witness does not satisfy all constraints.`);
  }
  return { quotient: polyTrim(quotient), remainder };
}

// Explains how the commitment is built and what each field contributes.
function logDetailedCommitment(circuitDigest, salt, APoly, BPoly, CPoly, HPoly, commitment) {
  console.log(`\n[Prover] ===== Fiat–Shamir Commitment =====`);
  console.log(`[Prover] A commitment is a hash that:`);
  console.log(`[Prover]   1. Fixes the polynomials BEFORE the challenge r is derived.`);
  console.log(`[Prover]      The prover cannot choose r freely; it is determined by this hash.`);
  console.log(`[Prover]   2. Includes a fresh random salt so every proof run produces a`);
  console.log(`[Prover]      unique commitment, even for the same witness. Without this, an`);
  console.log(`[Prover]      adversary could precompute the 4 possible proofs (age 0-3) and`);
  console.log(`[Prover]      match against the submitted proof to learn the exact age.`);
  console.log(`[Prover]   3. Includes the circuitDigest, binding the proof to the exact circuit.`);
  console.log(`[Prover]      If the verifier has a different circuit digest in its vk, the`);
  console.log(`[Prover]      re-derived commitment won't match → proof rejected.`);
  console.log(`[Prover]`);
  console.log(`[Prover] Commitment input (JSON-serialised):`);
  console.log(`[Prover]   circuitDigest: "${circuitDigest}"`);
  console.log(`[Prover]   salt: "${salt}"  (freshly generated for this proof run)`);
  console.log(`[Prover]   A_x: [${APoly.map(String).join(", ")}]`);
  console.log(`[Prover]   B_x: [${BPoly.map(String).join(", ")}]`);
  console.log(`[Prover]   C_x: [${CPoly.map(String).join(", ")}]`);
  console.log(`[Prover]   H_x: [${HPoly.map(String).join(", ")}]`);
  console.log(`[Prover] commitment = sha256(above) = ${commitment}`);
  console.log(`[Prover] ============================================`);
}

// Explains the Fiat–Shamir r derivation step-by-step, including the counter loop.
function logDetailedChallengeDerivation(commitment, circuitDigest, r, prime, forbiddenPoints) {
  console.log(`\n[Prover] ===== Fiat–Shamir Challenge Point r =====`);
  console.log(`[Prover] r is derived deterministically from: sha256(commitment | circuitDigest | counter)`);
  console.log(`[Prover] Using the full 256-bit hash output as a BigInt before reducing mod p.`);
  console.log(`[Prover] This minimises modular bias vs truncating to 32 bits (original approach).`);
  console.log(`[Prover]   Old bias: 2^32 mod 97 / 97 ≈ 1.3%`);
  console.log(`[Prover]   New bias: 2^256 mod p / p < 2^-195  (negligible)`);
  console.log(`[Prover] Forbidden points ${JSON.stringify(forbiddenPoints.map(String))} are excluded`);
  console.log(`[Prover] because Z(x) = 0 at those points — checking the identity there would`);
  console.log(`[Prover] trivially pass for any H(x) since both sides would be 0.`);
  console.log(`[Prover]`);

  let counter = 0;
  while (true) {
    const toHash = `${commitment}|${circuitDigest}|${counter}`;
    const hex = sha256Hex(toHash);
    const num = BigInt("0x" + hex);
    const candidate = num % prime;
    const forbidden = forbiddenPoints.includes(candidate);
    console.log(`[Prover] counter=${counter}: sha256("${toHash.slice(0, 40)}...") = ${hex.slice(0, 16)}...`);
    console.log(`[Prover]   BigInt(hash) mod p = ${candidate}  →  ${forbidden ? "FORBIDDEN, try next" : "ACCEPTED"}`);
    if (!forbidden) {
      console.log(`[Prover] Challenge r = ${r}`);
      console.log(`[Prover] ============================================`);
      return;
    }
    counter += 1;
  }
}

// Explains the QAP identity check at r and previews what the verifier will do.
function logEvaluationHandshake(APoly, BPoly, CPoly, HPoly, Z, r, p) {
  const A_r = polyEval(APoly, r, p);
  const B_r = polyEval(BPoly, r, p);
  const C_r = polyEval(CPoly, r, p);
  const H_r = polyEval(HPoly, r, p);
  const Z_r = polyEval(Z, r, p);
  const lhs = mod(A_r * B_r - C_r, p);
  const rhs = mod(H_r * Z_r, p);

  console.log(`\n[Prover] ===== QAP Identity Check at r (Evaluation Handshake) =====`);
  console.log(`[Prover] The QAP identity  A(x)*B(x) - C(x) = H(x)*Z(x)  holds as a`);
  console.log(`[Prover] polynomial identity. By Schwartz-Zippel, if this identity holds`);
  console.log(`[Prover] at a random point r, it holds everywhere with probability 1 - deg/|F|.`);
  console.log(`[Prover]`);
  console.log(`[Prover] Evaluating each polynomial at r = ${r}:`);
  console.log(`[Prover]   A(r): evaluate [${APoly.join(",")}] at r=${r}  =  ${A_r}`);
  console.log(`[Prover]   B(r): evaluate [${BPoly.join(",")}] at r=${r}  =  ${B_r}`);
  console.log(`[Prover]   C(r): evaluate [${CPoly.join(",")}] at r=${r}  =  ${C_r}`);
  console.log(`[Prover]   H(r): evaluate [${HPoly.join(",")}] at r=${r}  =  ${H_r}`);
  console.log(`[Prover]   Z(r): evaluate [${Z.join(",")}] at r=${r}      =  ${Z_r}`);
  console.log(`[Prover]         (Z(r) can be computed by anyone from the public verification key.)`);
  console.log(`[Prover]`);
  console.log(`[Prover] LHS = A(r)*B(r) - C(r)  =  ${A_r} * ${B_r} - ${C_r}  mod p  =  ${lhs}`);
  console.log(`[Prover] RHS = H(r)*Z(r)          =  ${H_r} * ${Z_r}            mod p  =  ${rhs}`);
  console.log(`[Prover] LHS ${lhs === rhs ? "==" : "!="} RHS  →  ${lhs === rhs ? "MATCH ✓" : "MISMATCH ✗"}`);
  console.log(`[Prover]`);
  console.log(`[Prover] What the verifier will do (without knowing the witness):`);
  console.log(`[Prover]   1. Verify the commitment matches sha256(circuitDigest || poly coefficients).`);
  console.log(`[Prover]      This ensures the evaluations are tied to the committed polynomials,`);
  console.log(`[Prover]      preventing a prover from fabricating evaluations after seeing r.`);
  console.log(`[Prover]   2. Re-derive r from the verified commitment.`);
  console.log(`[Prover]   3. Re-evaluate A(r), B(r), C(r), H(r) from the proof's poly coefficients.`);
  console.log(`[Prover]      (NOT trusting prover-supplied evaluation values.)`);
  console.log(`[Prover]   4. Compute Z(r) from the public verification key.`);
  console.log(`[Prover]   5. Check A(r)*B(r) - C(r) == H(r)*Z(r).`);
  console.log(`[Prover] ============================================`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const pk = JSON.parse(fs.readFileSync("proving_key.json", "utf8"));
  const p = BigInt(pk.prime);
  const points = pk.constraintPoints.map(BigInt);
  const Z = pk.targetPolynomial.coeffsLowToHighDegree.map(BigInt);
  const A = pk.r1cs.A.map((row) => row.map(BigInt));
  const B = pk.r1cs.B.map((row) => row.map(BigInt));
  const C = pk.r1cs.C.map((row) => row.map(BigInt));
  const { circuitDigest } = pk;
  const { lo, hi } = pk.range;
  const k = pk.k;

  const ageRaw = process.argv[2];
  const age = ageRaw === undefined ? lo : Number(ageRaw);

  console.log("========== PROVER START ==========");
  console.log(`\n[Prover] Reading proving_key.json`);
  console.log(`[Prover] Proving range: age ∈ [${lo}, ${hi}]  (gap=${hi-lo}, k=${k} bits)`);
  console.log(`[Prover] Field prime p = ${p}  (2^61 - 1)`);
  console.log(`[Prover] Constraint points: [${points.join(", ")}]`);
  console.log(`[Prover] Circuit digest: ${circuitDigest}`);
  console.log(
    `[Prover] Input age from CLI: ${ageRaw === undefined ? `(not provided, defaulting to lo=${lo})` : ageRaw}`
  );

  if (!Number.isInteger(age) || age < lo || age > hi) {
    console.error(`Error: age must be an integer in [${lo}, ${hi}].`);
    process.exit(1);
  }

  // a = age - lo  (left distance, proves age ≥ lo)
  // b = hi - age  (right distance, proves age ≤ hi)
  // Both are decomposed into k bits; the constraints enforce a + b = gap.
  const a = age - lo;
  const b = hi - age;
  const aBits = toBits(a, k);
  const bBits = toBits(b, k);

  // The witness is private — it will NOT be written to proof.json.
  const witness = [1n, BigInt(age), ...aBits, ...bBits];

  console.log(`\n[Prover] ===== Witness Construction =====`);
  console.log(`[Prover] Witness w = [1, age, a0..a${k-1}, b0..b${k-1}]  (PRIVATE — not written to proof.json)`);
  console.log(`[Prover] age = ${age}`);
  console.log(`[Prover] a = age - lo = ${age} - ${lo} = ${a}  (left  distance)`);
  console.log(`[Prover] b = hi - age = ${hi} - ${age} = ${b}  (right distance)`);
  console.log(`[Prover] ${k}-bit decomposition of a=${a}:`);
  aBits.forEach((bit, i) => console.log(`[Prover]   a${i} = (${a} >> ${i}) & 1 = ${bit}  (weight ${2**i})`));
  console.log(`[Prover]   Verify: ${aBits.map((bit,i)=>`${2**i}*${bit}`).join(" + ")} = ${aBits.reduce((s,bit,i)=>s+BigInt(2**i)*bit,0n)}  (expected a=${a})`);
  console.log(`[Prover] ${k}-bit decomposition of b=${b}:`);
  bBits.forEach((bit, i) => console.log(`[Prover]   b${i} = (${b} >> ${i}) & 1 = ${bit}  (weight ${2**i})`));
  console.log(`[Prover]   Verify: ${bBits.map((bit,i)=>`${2**i}*${bit}`).join(" + ")} = ${bBits.reduce((s,bit,i)=>s+BigInt(2**i)*bit,0n)}  (expected b=${b})`);
  console.log(`[Prover]   a + b = ${a} + ${b} = ${a+b}  (expected gap=${hi-lo}) ✓`);
  console.log(`[Prover] w = [${witness.join(", ")}]`);
  console.log(`[Prover] ============================================`);

  // -------------------------------------------------------------------------
  // R1CS evaluation
  // -------------------------------------------------------------------------
  console.log(`\n[Prover] ===== R1CS Evaluation =====`);
  console.log(`[Prover] For each constraint i, compute (A_i·w), (B_i·w), (C_i·w)`);
  console.log(`[Prover] These are the values the polynomials A(x),B(x),C(x) must take at x=i+1.`);
  console.log(`[Prover]`);

  const aVals = A.map((row, i) => {
    const v = dot(row, witness, p);
    console.log(`[Prover] A row ${i + 1}: ${JSON.stringify(row.map(String))} · [${witness.join(",")}] = ${v}  (at x=${points[i]})`);
    return v;
  });
  console.log(`[Prover]`);
  const bVals = B.map((row, i) => {
    const v = dot(row, witness, p);
    console.log(`[Prover] B row ${i + 1}: ${JSON.stringify(row.map(String))} · [${witness.join(",")}] = ${v}  (at x=${points[i]})`);
    return v;
  });
  console.log(`[Prover]`);
  const cVals = C.map((row, i) => {
    const v = dot(row, witness, p);
    console.log(`[Prover] C row ${i + 1}: ${JSON.stringify(row.map(String))} · [${witness.join(",")}] = ${v}  (at x=${points[i]})`);
    return v;
  });
  console.log(`[Prover]`);
  console.log(`[Prover] Summary — values that must be interpolated:`);
  console.log(`[Prover]   A: [${aVals.map((v, i) => `A(${points[i]})=${v}`).join(", ")}]`);
  console.log(`[Prover]   B: [${bVals.map((v, i) => `B(${points[i]})=${v}`).join(", ")}]`);
  console.log(`[Prover]   C: [${cVals.map((v, i) => `C(${points[i]})=${v}`).join(", ")}]`);
  console.log(`[Prover] Constraint check at each point:`);
  for (let i = 0; i < points.length; i++) {
    const lhs = mod(aVals[i] * bVals[i], p);
    const rhs = cVals[i];
    console.log(`[Prover]   x=${points[i]}: A*B = ${aVals[i]}*${bVals[i]} mod p = ${lhs},  C = ${rhs}  →  ${lhs === rhs ? "✓" : "✗"}`);
  }
  console.log(`[Prover] ============================================`);

  // -------------------------------------------------------------------------
  // Lagrange interpolation
  // -------------------------------------------------------------------------
  console.log(`\n[Prover] ===== Lagrange Interpolation =====`);
  const numConstraints = points.length;
  console.log(`[Prover] Build degree-≤${numConstraints-1} polynomials A(x), B(x), C(x) that pass through the`);
  console.log(`[Prover] R1CS values at all ${numConstraints} constraint points.`);

  logDetailedLagrangeForLabel("A", points, aVals, p);
  logDetailedLagrangeForLabel("B", points, bVals, p);
  logDetailedLagrangeForLabel("C", points, cVals, p);

  const APoly = lagrangeInterpolate(points, aVals, p);
  const BPoly = lagrangeInterpolate(points, bVals, p);
  const CPoly = lagrangeInterpolate(points, cVals, p);

  // -------------------------------------------------------------------------
  // P(x) = A(x)*B(x) - C(x)
  // -------------------------------------------------------------------------
  console.log(`\n[Prover] ===== Computing P(x) = A(x)*B(x) - C(x) =====`);
  logDetailedPComputation(APoly, BPoly, CPoly, p);

  // -------------------------------------------------------------------------
  // Z(x) explanation and H(x) = P(x)/Z(x)
  // -------------------------------------------------------------------------
  logDetailedZExplanation(Z, points, p);

  const P = polySub(polyMul(APoly, BPoly, p), CPoly, p);
  const { quotient: HPoly, remainder } = detailedPolyDiv(P, Z, p);

  if (!(remainder.length === 1 && remainder[0] === 0n)) {
    throw new Error("Remainder is non-zero: witness does not satisfy the constraints.");
  }

  // -------------------------------------------------------------------------
  // Fiat–Shamir commitment
  // -------------------------------------------------------------------------
  // Generate a fresh random salt so every proof run produces a unique commitment,
  // even for the same witness.  Without this, an adversary could precompute all
  // (hi-lo+1) possible proofs and match against the submitted proof to learn age.
  const salt = crypto.randomBytes(32).toString("hex");

  const commitInput = JSON.stringify({
    circuitDigest,
    salt,
    A_x: APoly.map(String),
    B_x: BPoly.map(String),
    C_x: CPoly.map(String),
    H_x: HPoly.map(String),
  });
  const commitment = sha256Hex(commitInput);
  logDetailedCommitment(circuitDigest, salt, APoly, BPoly, CPoly, HPoly, commitment);

  // -------------------------------------------------------------------------
  // Fiat–Shamir challenge r
  // -------------------------------------------------------------------------
  const forbiddenPoints = points; // exclude constraint points {1,2,3}
  const r = deriveChallengeR({ commitment, circuitDigest, prime: p, forbiddenPoints });
  logDetailedChallengeDerivation(commitment, circuitDigest, r, p, forbiddenPoints);

  // -------------------------------------------------------------------------
  // QAP identity preview
  // -------------------------------------------------------------------------
  logEvaluationHandshake(APoly, BPoly, CPoly, HPoly, Z, r, p);

  // -------------------------------------------------------------------------
  // KZG polynomial commitments and opening proofs
  // -------------------------------------------------------------------------
  console.log(`\n[KZG] ========== KZG COMMITMENTS & OPENING PROOFS ==========`);
  console.log(`[KZG] Loading SRS from proving_key.json (generated during setup with τ=${kzg.TAU})`);

  const srs = pk.kzg.srs.map(BigInt);

  // --- Commitments ---
  // C_A = g^A(τ),  C_B = g^B(τ),  C_C = g^C(τ),  C_H = g^H(τ)
  // In real KZG these are G1 elliptic-curve points.
  const C_A = kzg.commit(APoly, srs);
  kzg.logCommit("A", APoly, srs, C_A);

  const C_B = kzg.commit(BPoly, srs);
  kzg.logCommit("B", BPoly, srs, C_B);

  const C_C = kzg.commit(CPoly, srs);
  kzg.logCommit("C", CPoly, srs, C_C);

  const C_H = kzg.commit(HPoly, srs);
  kzg.logCommit("H", HPoly, srs, C_H);

  console.log(`\n[KZG] ===== Summary of KZG Commitments =====`);
  console.log(`[KZG]   C_A = ${C_A}   (commitment to A(x))`);
  console.log(`[KZG]   C_B = ${C_B}   (commitment to B(x))`);
  console.log(`[KZG]   C_C = ${C_C}   (commitment to C(x))`);
  console.log(`[KZG]   C_H = ${C_H}   (commitment to H(x))`);
  console.log(`[KZG] Each commitment is a single field element g^f(τ).`);
  console.log(`[KZG] In real KZG each would be a single G1 elliptic-curve point.`);

  // --- Opening proofs at challenge r ---
  // π_A proves A(r) = y_A,  etc.
  // π_f = commit( (f(x) − f(r)) / (x − r) ) = g^q_f(τ)
  const { y: y_A, pi: pi_A, q: q_A } = kzg.open(APoly, r, srs);
  kzg.logOpen("A", APoly, r, y_A, q_A, pi_A, srs);

  const { y: y_B, pi: pi_B, q: q_B } = kzg.open(BPoly, r, srs);
  kzg.logOpen("B", BPoly, r, y_B, q_B, pi_B, srs);

  const { y: y_C, pi: pi_C, q: q_C } = kzg.open(CPoly, r, srs);
  kzg.logOpen("C", CPoly, r, y_C, q_C, pi_C, srs);

  const { y: y_H, pi: pi_H, q: q_H } = kzg.open(HPoly, r, srs);
  kzg.logOpen("H", HPoly, r, y_H, q_H, pi_H, srs);

  console.log(`\n[KZG] ===== Summary of Opening Proofs (at r = ${r}) =====`);
  console.log(`[KZG]   π_A = ${pi_A}   proves A(${r}) = ${y_A}`);
  console.log(`[KZG]   π_B = ${pi_B}   proves B(${r}) = ${y_B}`);
  console.log(`[KZG]   π_C = ${pi_C}   proves C(${r}) = ${y_C}`);
  console.log(`[KZG]   π_H = ${pi_H}   proves H(${r}) = ${y_H}`);
  console.log(`[KZG] Each π is a single field element g^q(τ) (quotient poly evaluated at τ).`);
  console.log(`[KZG] In real KZG each would be a single G1 elliptic-curve point.`);
  console.log(`[KZG] ==========================================================`);

  // -------------------------------------------------------------------------
  // Build proof
  //
  // Now includes KZG commitments and opening proofs in addition to the
  // Fiat-Shamir hash commitment.  The verifier uses the KZG proofs to confirm
  // each evaluation without needing to see the full polynomial coefficients.
  // -------------------------------------------------------------------------
  const proof = {
    commitment,
    salt,
    polynomialCoefficients: {
      A_x: APoly.map(String),
      B_x: BPoly.map(String),
      C_x: CPoly.map(String),
      H_x: HPoly.map(String),
    },
    kzg: {
      // Commitments (one per polynomial)
      C_A: C_A.toString(),
      C_B: C_B.toString(),
      C_C: C_C.toString(),
      C_H: C_H.toString(),
      // Evaluation point used for openings
      evalPoint: r.toString(),
      // Claimed evaluations
      y_A: y_A.toString(),
      y_B: y_B.toString(),
      y_C: y_C.toString(),
      y_H: y_H.toString(),
      // Opening proofs
      pi_A: pi_A.toString(),
      pi_B: pi_B.toString(),
      pi_C: pi_C.toString(),
      pi_H: pi_H.toString(),
    },
  };

  fs.writeFileSync("proof.json", JSON.stringify(proof, null, 2), "utf8");

  console.log(`\n[Prover] ===== Proof Written =====`);
  console.log(`[Prover] proof.json contains:`);
  console.log(`[Prover]   commitment           : ${commitment}`);
  console.log(`[Prover]   polynomialCoefficients:`);
  console.log(`[Prover]     A_x: [${APoly.map(String).join(", ")}]`);
  console.log(`[Prover]     B_x: [${BPoly.map(String).join(", ")}]`);
  console.log(`[Prover]     C_x: [${CPoly.map(String).join(", ")}]`);
  console.log(`[Prover]     H_x: [${HPoly.map(String).join(", ")}]`);
  console.log(`[Prover]   kzg:`);
  console.log(`[Prover]     C_A  = ${C_A}  (KZG commitment to A(x))`);
  console.log(`[Prover]     C_B  = ${C_B}  (KZG commitment to B(x))`);
  console.log(`[Prover]     C_C  = ${C_C}  (KZG commitment to C(x))`);
  console.log(`[Prover]     C_H  = ${C_H}  (KZG commitment to H(x))`);
  console.log(`[Prover]     evalPoint = ${r}`);
  console.log(`[Prover]     y_A  = ${y_A}  (A(r))`);
  console.log(`[Prover]     y_B  = ${y_B}  (B(r))`);
  console.log(`[Prover]     y_C  = ${y_C}  (C(r))`);
  console.log(`[Prover]     y_H  = ${y_H}  (H(r))`);
  console.log(`[Prover]     π_A  = ${pi_A}  (opening proof for A(r))`);
  console.log(`[Prover]     π_B  = ${pi_B}  (opening proof for B(r))`);
  console.log(`[Prover]     π_C  = ${pi_C}  (opening proof for C(r))`);
  console.log(`[Prover]     π_H  = ${pi_H}  (opening proof for H(r))`);
  console.log(`[Prover] Notably ABSENT from proof.json:`);
  console.log(`[Prover]   - witness values (private)`);
  console.log("=========== PROVER END ===========");
}

main();
