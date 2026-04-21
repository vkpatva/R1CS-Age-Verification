"use strict";
/**
 * kzg.js — Simulated KZG polynomial commitment scheme
 *
 * IMPORTANT — Educational simulation only
 * ─────────────────────────────────────────
 * Real KZG uses elliptic curve groups (e.g. BN254) with pairings:
 *
 *   Trusted setup:
 *     τ is secret; SRS = { [τ^0]G, [τ^1]G, ..., [τ^d]G }  (G1 points)
 *
 *   Commit:
 *     C = Σ f_i · [τ^i]G   (a single G1 point, "inner product" of coefficients with SRS)
 *
 *   Open (prove f(r) = y):
 *     q(x) = (f(x) − y) / (x − r)   (quotient polynomial)
 *     π = Σ q_i · [τ^i]G             (another G1 point)
 *
 *   Verify:
 *     e(C − y·G,  G2)  ==  e(π,  [τ]G2 − [r]G2)
 *     where e: G1×G2 → GT is a bilinear pairing.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SIMULATION APPROACH — Additive field arithmetic
 * ─────────────────────────────────────────────────────────────────────────────
 * We simulate the elliptic curve groups using field elements in F_p:
 *   - "G1 point" [x]G  →  field element  x  ∈ F_p
 *   - "Scalar multiplication" k·[x]G  →  k·x mod p
 *   - "Group addition" [x]G + [y]G  →  (x + y) mod p
 *   - "Pairing" e(a, b) → GT  →  a · b mod p  (field multiplication)
 *
 * Under this mapping:
 *
 *   SRS[i] = τ^i mod p                       (represents [τ^i]G)
 *
 *   commit(f) = Σ f[i]·τ^i  mod p  =  f(τ)  (polynomial evaluation at τ)
 *   (In EC KZG: Σ f[i]·[τ^i]G = [f(τ)]G)
 *
 *   open(f, r):
 *     y = f(r) mod p
 *     q(x) = (f(x) − y) / (x − r)
 *     π = q(τ) mod p
 *   (In EC KZG: π = [q(τ)]G)
 *
 *   verify(C, r, y, π):
 *     Check:  (C − y) · 1  ==  π · (τ − r)   mod p
 *     i.e.:   C − y       ==  π · (τ − r)    mod p
 *   (In EC KZG: e(C − y·G, G2) == e(π, [τ]G2 − [r]G2))
 *
 * Why it works: f(τ) − f(r) = q(τ) · (τ − r) is a polynomial identity
 * so evaluating both sides at τ gives C − y = π·(τ−r) exactly.
 *
 * What it simulates but does NOT replicate:
 *   - Hiding: τ is public in this simulation; in EC KZG it's never revealed.
 *   - Binding: in EC KZG, finding a collision requires the discrete log of τ.
 *   - Zero-knowledge: real EC KZG hides the polynomial; here f(τ) reveals information.
 *
 * Trusted Setup
 * ─────────────
 * In a real ceremony, τ (the "toxic waste") is chosen by multiple parties
 * via MPC, used to build the SRS, then discarded.  Here τ = 42 (as requested).
 */

// ─────────────────────────────────────────────────────────────────────────────
// Parameters
// ─────────────────────────────────────────────────────────────────────────────

const PRIME = 2305843009213693951n; // 2^61 − 1, Mersenne prime

// Trusted setup secret (toxic waste).
const TAU = 42n;

// ─────────────────────────────────────────────────────────────────────────────
// Field arithmetic helpers
// ─────────────────────────────────────────────────────────────────────────────

function mod(n, p) {
  return ((n % p) + p) % p;
}

function modPow(base, exp, p) {
  let b = mod(base, p);
  let e = exp < 0n ? mod(exp, p - 1n) : exp; // handle negative exponents
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = mod(out * b, p);
    b = mod(b * b, p);
    e >>= 1n;
  }
  return out;
}

function modInv(n, p) {
  const v = mod(n, p);
  if (v === 0n) throw new Error("modInv: division by zero");
  return modPow(v, p - 2n, p);
}

// ─────────────────────────────────────────────────────────────────────────────
// Polynomial helpers (coefficients low→high degree, BigInt)
// ─────────────────────────────────────────────────────────────────────────────

function polyEval(poly, x, p) {
  let result = 0n;
  let xPow = 1n;
  for (const c of poly) {
    result = mod(result + c * xPow, p);
    xPow = mod(xPow * x, p);
  }
  return result;
}

function polyTrim(poly) {
  const out = poly.slice();
  while (out.length > 1 && out[out.length - 1] === 0n) out.pop();
  return out;
}

/**
 * Compute quotient polynomial q(x) = (f(x) − y) / (x − root) by synthetic division.
 * The caller is responsible for ensuring f(root) == y (exact division).
 */
function polyQuotient(fMinusY, root, p) {
  // Synthetic division of fMinusY by (x − root).
  // If fMinusY = [c0, c1, ..., cn], quotient q = [q0, ..., q_{n-1}] where:
  //   q[n-2] = c[n]
  //   q[i]   = c[i+1] + root * q[i+1]   for i = n-3 downto 0
  const n = fMinusY.length;
  if (n <= 1) return [0n];
  const q = Array(n - 1).fill(0n);
  q[n - 2] = fMinusY[n - 1];
  for (let i = n - 3; i >= 0; i--) {
    q[i] = mod(fMinusY[i + 1] + root * q[i + 1], p);
  }
  return polyTrim(q);
}

// ─────────────────────────────────────────────────────────────────────────────
// SRS (Structured Reference String) generation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate the SRS for polynomials up to degree `maxDegree`.
 *
 * In real KZG:  SRS[i] = [τ^i]G  ∈ G1   (an elliptic curve point)
 * Simulated:    SRS[i] = τ^i  mod p      (a field element)
 *
 * @param {number} maxDegree
 * @returns {bigint[]} srs  — array of length maxDegree+1
 */
function generateSRS(maxDegree) {
  const srs = [];
  let tauPow = 1n; // τ^0 = 1
  for (let i = 0; i <= maxDegree; i++) {
    srs.push(tauPow);
    tauPow = mod(tauPow * TAU, PRIME);
  }
  return srs;
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute the KZG commitment to polynomial `f`.
 *
 * In real KZG:  C = Σ f[i] · [τ^i]G  ∈ G1   (scalar mult + point addition)
 * Simulated:    C = Σ f[i] · τ^i  mod p  =  f(τ)   (polynomial evaluation)
 *
 * The commitment C is the evaluation of f at the hidden point τ.
 *
 * @param {bigint[]} poly  — coefficients low→high
 * @param {bigint[]} srs   — structured reference string (τ^i values)
 * @returns {bigint} commitment C = f(τ) mod p
 */
function commit(poly, srs) {
  const p = PRIME;
  let C = 0n;
  for (let i = 0; i < poly.length; i++) {
    C = mod(C + poly[i] * srs[i], p);
  }
  return C;
}

// ─────────────────────────────────────────────────────────────────────────────
// Open (create evaluation proof)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create an opening proof that f(evalPoint) = y.
 *
 * Quotient polynomial:  q(x) = (f(x) − y) / (x − evalPoint)
 *
 * In real KZG:  π = [q(τ)]G  ∈ G1
 * Simulated:    π = q(τ)  mod p
 *
 * @param {bigint[]} poly       — f(x) coefficients
 * @param {bigint}   evalPoint  — the point r at which to open
 * @param {bigint[]} srs        — structured reference string
 * @returns {{ y: bigint, pi: bigint, q: bigint[] }}
 */
function open(poly, evalPoint, srs) {
  const p = PRIME;
  const y = polyEval(poly, evalPoint, p);

  // f(x) − y  (subtract y from the constant term)
  const fMinusY = poly.slice();
  fMinusY[0] = mod(fMinusY[0] - y, p);

  // q(x) = (f(x) − y) / (x − evalPoint) via synthetic division
  const q = polyQuotient(fMinusY, evalPoint, p);

  // π = q(τ) = commit(q)
  const pi = commit(q, srs);
  return { y, pi, q };
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verify a KZG opening proof.
 *
 * In real KZG (pairing-based):
 *   e(C − y·G,  G2)  ==  e(π,  [τ]G2 − [r]G2)
 *
 * Simulated (field arithmetic, same algebraic identity):
 *   C  = f(τ)     (field element)
 *   π  = q(τ)     (field element)
 *   y  = f(r)     (field element)
 *
 *   The pairing e(a, b) maps to a·b in F_p.
 *   [τ]G2 − [r]G2 maps to τ − r.
 *   So the check becomes:
 *
 *     (C − y) · 1  ==  π · (τ − r)   mod p
 *     i.e.  C − y  ==  π · (τ − r)   mod p
 *
 * Algebraically: f(τ) − f(r) = q(τ)·(τ−r) is the polynomial identity
 *   f(x) − f(r) = q(x)·(x−r)  evaluated at x=τ. This holds exactly.
 *
 * @param {bigint}   C          — commitment = f(τ)
 * @param {bigint}   evalPoint  — r
 * @param {bigint}   y          — claimed f(r)
 * @param {bigint}   pi         — opening proof = q(τ)
 * @returns {boolean}
 */
function verify(C, evalPoint, y, pi) {
  const p = PRIME;
  // LHS = C − y  =  f(τ) − f(r)
  const LHS = mod(C - y, p);
  // RHS = π · (τ − r)  =  q(τ) · (τ − r)
  const tauMinusR = mod(TAU - evalPoint, p);
  const RHS = mod(pi * tauMinusR, p);
  return LHS === RHS;
}

// ─────────────────────────────────────────────────────────────────────────────
// Logging helpers
// ─────────────────────────────────────────────────────────────────────────────

function logSRS(srs, maxDegree) {
  console.log(`\n[KZG] ===== Structured Reference String (SRS) =====`);
  console.log(`[KZG] Trusted setup: τ (tau) = ${TAU}  (fixed "toxic waste" for this demo)`);
  console.log(`[KZG] Prime field:   p = ${PRIME}  (2^61 − 1)`);
  console.log(`[KZG]`);
  console.log(`[KZG] In real KZG:  SRS[i] = [τ^i]G  ∈ G1  (elliptic curve point)`);
  console.log(`[KZG] Simulated:    SRS[i] = τ^i mod p      (field element)`);
  console.log(`[KZG] The simulation replaces EC group operations with field arithmetic:`);
  console.log(`[KZG]   "scalar mult" k·[x]G  →  k·x mod p`);
  console.log(`[KZG]   "group add"   [x]G + [y]G  →  (x+y) mod p`);
  console.log(`[KZG]   "pairing"     e(a,b)  →  a·b mod p`);
  console.log(`[KZG]`);
  console.log(`[KZG] SRS[i] = τ^i mod p   for i = 0 .. ${maxDegree}`);
  console.log(`[KZG]`);
  let tauPow = 1n;
  for (let i = 0; i <= maxDegree; i++) {
    console.log(`[KZG]   SRS[${i.toString().padStart(2)}] = ${TAU}^${i} mod p = ${srs[i]}`);
    tauPow = mod(tauPow * TAU, PRIME);
  }
  console.log(`[KZG] ============================================================`);
}

function logCommit(label, poly, srs, C) {
  const p = PRIME;
  console.log(`\n[KZG] ===== Commitment C_${label} =====`);
  console.log(`[KZG] In real KZG: C_${label} = Σ poly[i]·[τ^i]G  (a single G1 point)`);
  console.log(`[KZG] Simulated:   C_${label} = Σ poly[i]·τ^i mod p  =  ${label}(τ)`);
  console.log(`[KZG] i.e. C_${label} is just the polynomial ${label}(x) evaluated at the secret τ`);
  console.log(`[KZG]`);
  console.log(`[KZG] ${label}(x) coefficients (low→high): [${poly.join(", ")}]`);
  console.log(`[KZG] SRS used (τ^i): [${srs.slice(0, poly.length).join(", ")}]`);
  console.log(`[KZG]`);
  let acc = 0n;
  for (let i = 0; i < poly.length; i++) {
    const term = mod(poly[i] * srs[i], p);
    const before = acc;
    acc = mod(acc + term, p);
    console.log(`[KZG]   i=${i}: ${poly[i]} · τ^${i}(=${srs[i]}) = ${term} mod p;  running sum: ${before} + ${term} = ${acc}`);
  }
  console.log(`[KZG] C_${label} = ${label}(τ) = ${C}`);
  console.log(`[KZG] ============================================================`);
}

function logOpen(label, poly, evalPoint, y, q, pi, srs) {
  const p = PRIME;
  console.log(`\n[KZG] ===== Opening Proof π_${label} =====`);
  console.log(`[KZG] Proves: ${label}(r) = ${y}  at evaluation point r = ${evalPoint}`);
  console.log(`[KZG]`);
  console.log(`[KZG] Step 1 — Compute quotient q(x) = (${label}(x) − ${y}) / (x − ${evalPoint})`);

  const fMinusY = poly.slice();
  fMinusY[0] = mod(fMinusY[0] - y, p);
  console.log(`[KZG]   (${label}(x) − ${y}) coefficients (low→high): [${fMinusY.join(", ")}]`);
  console.log(`[KZG]   q(x) coefficients (low→high): [${q.join(", ")}]`);
  console.log(`[KZG]`);
  console.log(`[KZG]   Verify: q(x) * (x − ${evalPoint}) == ${label}(x) − ${y}`);
  const checkPoints = [1n, 2n, 3n];
  for (const pt of checkPoints) {
    const lhs = mod(polyEval(q, pt, p) * mod(pt - evalPoint, p), p);
    const rhs = mod(polyEval(poly, pt, p) - y, p);
    console.log(`[KZG]     x=${pt}: q(${pt})*(${pt}−${evalPoint}) = ${lhs};  ${label}(${pt})−${y} = ${rhs}  →  ${lhs===rhs ? "✓" : "✗"}`);
  }
  console.log(`[KZG]`);
  console.log(`[KZG] Step 2 — π_${label} = q(τ) = commit(q)`);
  console.log(`[KZG]   In real KZG: π_${label} = [q(τ)]G ∈ G1  (a single EC point)`);
  console.log(`[KZG]   Simulated:   π_${label} = q(τ) mod p`);

  let acc = 0n;
  for (let i = 0; i < q.length; i++) {
    const term = mod(q[i] * srs[i], p);
    const before = acc;
    acc = mod(acc + term, p);
    console.log(`[KZG]     i=${i}: ${q[i]} · τ^${i}(=${srs[i]}) = ${term};  sum = ${acc}`);
  }
  console.log(`[KZG]   π_${label} = ${pi}`);
  console.log(`[KZG] ============================================================`);
}

function logVerify(label, C, evalPoint, y, pi, passed) {
  const p = PRIME;
  console.log(`\n[KZG] ===== Verification of π_${label} =====`);
  console.log(`[KZG] Claim: ${label}(${evalPoint}) = ${y}`);
  console.log(`[KZG]`);
  console.log(`[KZG] Real KZG check (pairing-based):`);
  console.log(`[KZG]   e( C_${label} − y·G,  G2 )  ==  e( π_${label},  [τ]G2 − [r]G2 )`);
  console.log(`[KZG]`);
  console.log(`[KZG] Simulated check (field arithmetic, pairing → multiplication):`);
  console.log(`[KZG]   C_${label} − y  ==  π_${label} · (τ − r)   mod p`);
  console.log(`[KZG]`);
  const LHS = mod(C - y, p);
  const tauMinusR = mod(TAU - evalPoint, p);
  const RHS = mod(pi * tauMinusR, p);
  console.log(`[KZG]   LHS = C_${label} − y  =  ${C} − ${y}  mod p  =  ${LHS}`);
  console.log(`[KZG]       (this represents f(τ) − f(r))`);
  console.log(`[KZG]`);
  console.log(`[KZG]   RHS = π_${label} · (τ − r)  =  ${pi} · (${TAU} − ${evalPoint}) mod p`);
  console.log(`[KZG]       = ${pi} · ${tauMinusR} mod p  =  ${RHS}`);
  console.log(`[KZG]       (this represents q(τ) · (τ − r))`);
  console.log(`[KZG]`);
  console.log(`[KZG]   Why they match: f(x)−f(r) = q(x)·(x−r) as polynomials,`);
  console.log(`[KZG]   so evaluating both sides at x=τ gives LHS = RHS exactly.`);
  console.log(`[KZG]`);
  console.log(`[KZG] ${LHS} ${LHS === RHS ? "==" : "!="} ${RHS}  →  π_${label} ${passed ? "VALID ✓" : "INVALID ✗"}`);
  console.log(`[KZG] ============================================================`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  PRIME,
  TAU,
  mod,
  modPow,
  modInv,
  polyEval,
  generateSRS,
  commit,
  open,
  verify,
  logSRS,
  logCommit,
  logOpen,
  logVerify,
};
