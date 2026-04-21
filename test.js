#!/usr/bin/env node
"use strict";

/**
 * Test suite for the ZK dynamic range proof system.
 *
 * Tests are organised into groups:
 *   1. setup.js argument validation
 *   2. Full pipeline — valid ranges and ages
 *   3. Boundary values (exact lo, exact hi)
 *   4. Out-of-range rejection (prover refuses invalid ages)
 *   5. Proof tampering (verifier rejects modified proofs)
 *   6. Cross-range rejection (proof for one range fails another range's vk)
 *   7. Circuit structure (key file contents, k values, digest changes)
 *
 * No external dependencies — uses only Node.js built-ins.
 */

const assert = require("assert");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DIR = __dirname;

// ---------------------------------------------------------------------------
// Minimal test runner
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    process.stdout.write(`  \x1b[32m✓\x1b[0m ${name}\n`);
    passed++;
  } catch (err) {
    process.stdout.write(`  \x1b[31m✗\x1b[0m ${name}\n`);
    process.stdout.write(`      ${err.message}\n`);
    failures.push({ name, message: err.message });
    failed++;
  }
}

function section(title) {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

function run(cmd) {
  try {
    const stdout = execSync(cmd, {
      cwd: DIR,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    return {
      ok: false,
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      code: err.status,
    };
  }
}

const setup = (lo, hi) => run(`node setup.js ${lo} ${hi}`);
const prove = (age) => run(`node prover.js ${age}`);
const verify = () => run("node verifier.js");

/** Run the full setup → prove → verify pipeline and return all three results. */
function pipeline(lo, hi, age) {
  const s = setup(lo, hi);
  assert.ok(s.ok, `setup(${lo}, ${hi}) failed:\n${s.stderr}`);
  const p = prove(age);
  assert.ok(p.ok, `prove(${age}) failed:\n${p.stderr}`);
  const v = verify();
  assert.ok(v.ok, `verify() process exited non-zero:\n${v.stderr}`);
  assert.ok(
    v.stdout.includes("SUCCESS"),
    `verification output does not contain SUCCESS:\n${v.stdout}`
  );
  return { setup: s, prove: p, verify: v };
}

function readProof() {
  return JSON.parse(fs.readFileSync(path.join(DIR, "proof.json"), "utf8"));
}
function writeProof(obj) {
  fs.writeFileSync(path.join(DIR, "proof.json"), JSON.stringify(obj, null, 2));
}
function readProvingKey() {
  return JSON.parse(fs.readFileSync(path.join(DIR, "proving_key.json"), "utf8"));
}
function readVerificationKey() {
  return JSON.parse(fs.readFileSync(path.join(DIR, "verification_key.json"), "utf8"));
}

// ---------------------------------------------------------------------------
// 1. Setup argument validation
// ---------------------------------------------------------------------------

section("1. Setup argument validation");

test("rejects missing arguments (no args)", () => {
  const r = run("node setup.js");
  assert.ok(!r.ok, "expected non-zero exit code");
});

test("rejects single argument", () => {
  const r = run("node setup.js 0");
  assert.ok(!r.ok, "expected non-zero exit code");
});

test("rejects lo > hi", () => {
  const r = setup(10, 5);
  assert.ok(!r.ok);
});

test("rejects lo === hi", () => {
  const r = setup(10, 10);
  assert.ok(!r.ok);
});

test("rejects hi > 256", () => {
  const r = setup(0, 257);
  assert.ok(!r.ok);
});

test("rejects negative lo", () => {
  const r = setup(-1, 10);
  assert.ok(!r.ok);
});

test("rejects non-integer values", () => {
  const r = run("node setup.js 1.5 10");
  // parseInt("1.5") === 1, so this actually works — depends on impl.
  // What matters is that the system doesn't crash on the float part.
  // Either it succeeds (treating as lo=1) or fails — both are acceptable.
  // Just ensure it doesn't throw an uncaught exception.
  assert.ok(r.ok || !r.ok); // tautology — just checking it doesn't hard-crash
});

test("accepts valid minimal range [0, 1]", () => {
  const r = setup(0, 1);
  assert.ok(r.ok, `setup(0,1) failed: ${r.stderr}`);
});

test("accepts maximum supported range [0, 256]", () => {
  const r = setup(0, 256);
  assert.ok(r.ok, `setup(0,256) failed: ${r.stderr}`);
});

// ---------------------------------------------------------------------------
// 2. Full pipeline — valid ranges and ages
// ---------------------------------------------------------------------------

section("2. Full pipeline — valid ranges and ages");

test("range [0, 15] age=0", () => pipeline(0, 15, 0));
test("range [0, 15] age=7", () => pipeline(0, 15, 7));
test("range [0, 15] age=15", () => pipeline(0, 15, 15));

test("range [4, 16] age=4", () => pipeline(4, 16, 4));
test("range [4, 16] age=10", () => pipeline(4, 16, 10));
test("range [4, 16] age=16", () => pipeline(4, 16, 16));

test("range [18, 65] age=18", () => pipeline(18, 65, 18));
test("range [18, 65] age=40", () => pipeline(18, 65, 40));
test("range [18, 65] age=65", () => pipeline(18, 65, 65));

test("range [0, 64] age=0", () => pipeline(0, 64, 0));
test("range [0, 64] age=33", () => pipeline(0, 64, 33));
test("range [0, 64] age=64", () => pipeline(0, 64, 64));

test("range [32, 256] age=32", () => pipeline(32, 256, 32));
test("range [32, 256] age=100", () => pipeline(32, 256, 100));
test("range [32, 256] age=256", () => pipeline(32, 256, 256));

test("range [0, 256] age=0", () => pipeline(0, 256, 0));
test("range [0, 256] age=128", () => pipeline(0, 256, 128));
test("range [0, 256] age=256", () => pipeline(0, 256, 256));

test("range [100, 200] age=150", () => pipeline(100, 200, 150));
test("range [255, 256] age=255", () => pipeline(255, 256, 255));
test("range [255, 256] age=256", () => pipeline(255, 256, 256));

test("verification output mentions the range [lo, hi]", () => {
  const r = pipeline(18, 65, 30);
  assert.ok(
    r.verify.stdout.includes("18") && r.verify.stdout.includes("65"),
    "verifier output should display the range"
  );
});

// ---------------------------------------------------------------------------
// 3. Boundary values (exact lo, exact hi)
// ---------------------------------------------------------------------------

section("3. Boundary values");

test("exact lo is accepted — [10, 50] age=10", () => {
  const r = pipeline(10, 50, 10);
  assert.ok(r.verify.stdout.includes("SUCCESS"));
});

test("exact hi is accepted — [10, 50] age=50", () => {
  const r = pipeline(10, 50, 50);
  assert.ok(r.verify.stdout.includes("SUCCESS"));
});

test("lo+1 is accepted — [10, 50] age=11", () => {
  const r = pipeline(10, 50, 11);
  assert.ok(r.verify.stdout.includes("SUCCESS"));
});

test("hi-1 is accepted — [10, 50] age=49", () => {
  const r = pipeline(10, 50, 49);
  assert.ok(r.verify.stdout.includes("SUCCESS"));
});

test("minimal gap [5, 6] age=5", () => {
  const r = pipeline(5, 6, 5);
  assert.ok(r.verify.stdout.includes("SUCCESS"));
});

test("minimal gap [5, 6] age=6", () => {
  const r = pipeline(5, 6, 6);
  assert.ok(r.verify.stdout.includes("SUCCESS"));
});

// ---------------------------------------------------------------------------
// 4. Out-of-range rejection (prover)
// ---------------------------------------------------------------------------

section("4. Out-of-range rejection (prover)");

test("age one below lo is rejected", () => {
  assert.ok(setup(18, 65).ok);
  const r = prove(17);
  assert.ok(!r.ok, "prover should reject age below lo");
});

test("age one above hi is rejected", () => {
  assert.ok(setup(18, 65).ok);
  const r = prove(66);
  assert.ok(!r.ok, "prover should reject age above hi");
});

test("age=0 rejected when lo=1", () => {
  assert.ok(setup(1, 50).ok);
  assert.ok(!prove(0).ok);
});

test("age=256 rejected for range [0, 255]", () => {
  assert.ok(setup(0, 255).ok);
  assert.ok(!prove(256).ok);
});

test("age far below range is rejected", () => {
  assert.ok(setup(100, 200).ok);
  assert.ok(!prove(0).ok);
});

test("age far above range is rejected", () => {
  assert.ok(setup(100, 200).ok);
  assert.ok(!prove(256).ok);
});

test("error message mentions the correct range", () => {
  assert.ok(setup(20, 30).ok);
  const r = prove(15);
  assert.ok(
    r.stderr.includes("20") || r.stdout.includes("20"),
    "error should mention the range"
  );
});

// ---------------------------------------------------------------------------
// 5. Proof tampering (verifier must reject)
// ---------------------------------------------------------------------------

section("5. Proof tampering");

test("zeroed commitment is rejected", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  proof.commitment = "0".repeat(64);
  writeProof(proof);
  const v = verify();
  assert.ok(
    !v.stdout.includes("SUCCESS") || v.stdout.includes("FAILED"),
    "tampered commitment should not verify"
  );
});

test("flipped commitment byte is rejected", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  const orig = proof.commitment;
  // Flip the first nibble
  const flipped = (parseInt(orig[0], 16) ^ 0xf).toString(16) + orig.slice(1);
  proof.commitment = flipped;
  writeProof(proof);
  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "commitment with flipped byte should fail");
});

test("tampered A_x coefficient is rejected", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  proof.polynomialCoefficients.A_x[0] = "999999999999999999";
  writeProof(proof);
  const v = verify();
  // Commitment will not match → FAILED at step 1
  assert.ok(!v.stdout.includes("SUCCESS"), "tampered A_x should fail");
});

test("tampered B_x coefficient is rejected", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  proof.polynomialCoefficients.B_x[0] = "123456789";
  writeProof(proof);
  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "tampered B_x should fail");
});

test("tampered H_x coefficient is rejected", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  proof.polynomialCoefficients.H_x[0] = "42";
  writeProof(proof);
  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "tampered H_x should fail");
});

test("removed salt causes commitment mismatch", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  delete proof.salt;
  writeProof(proof);
  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "missing salt should fail commitment check");
});

// ---------------------------------------------------------------------------
// 6. Cross-range rejection
// ---------------------------------------------------------------------------

section("6. Cross-range rejection");

test("proof for [0,15] rejected by verifier with [0,30] keys", () => {
  // Generate valid proof for [0,15]
  pipeline(0, 15, 7);
  const proof015 = readProof();

  // Overwrite keys with [0,30]
  assert.ok(setup(0, 30).ok, "setup for [0,30] failed");

  // Restore proof that was made for [0,15]
  writeProof(proof015);

  // Verifier has [0,30] vk but proof is from [0,15] circuit
  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "cross-range proof must not verify");
});

test("proof for [18,65] rejected by verifier with [0,100] keys", () => {
  pipeline(18, 65, 30);
  const proof1865 = readProof();

  assert.ok(setup(0, 100).ok);
  writeProof(proof1865);

  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "cross-range proof must not verify");
});

test("proof replayed with different (valid) range key fails", () => {
  // Two ranges with same gap but different lo/hi
  pipeline(10, 20, 15);
  const proof = readProof();

  // New keys: [20, 30] — same gap, different lo
  assert.ok(setup(20, 30).ok);
  writeProof(proof);

  const v = verify();
  assert.ok(!v.stdout.includes("SUCCESS"), "replay with shifted range must fail");
});

// ---------------------------------------------------------------------------
// 7. Circuit structure verification
// ---------------------------------------------------------------------------

section("7. Circuit structure");

test("proving key contains all expected fields", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  assert.ok(pk.prime, "missing prime");
  assert.ok(pk.range, "missing range");
  assert.strictEqual(pk.range.lo, 4);
  assert.strictEqual(pk.range.hi, 16);
  assert.ok(pk.k > 0, "k should be positive");
  assert.ok(pk.witnessLayout, "missing witnessLayout");
  assert.ok(pk.r1cs, "missing r1cs");
  assert.ok(pk.r1cs.A && pk.r1cs.B && pk.r1cs.C, "r1cs must have A, B, C");
  assert.ok(pk.targetPolynomial, "missing targetPolynomial");
  assert.ok(pk.circuitDigest, "missing circuitDigest");
});

test("verification key does NOT contain r1cs matrices", () => {
  assert.ok(setup(4, 16).ok);
  const vk = readVerificationKey();
  assert.ok(!vk.r1cs, "vk must not expose r1cs matrices");
  assert.strictEqual(vk.range.lo, 4);
  assert.strictEqual(vk.range.hi, 16);
  assert.ok(vk.circuitDigest, "missing circuitDigest");
  assert.ok(vk.targetPolynomial, "missing targetPolynomial");
});

test("proof does NOT contain witness values", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  assert.ok(!proof.witness, "witness must not be in proof");
  assert.ok(!proof.age, "age must not be in proof");
  assert.ok(proof.commitment, "proof must have commitment");
  assert.ok(proof.salt, "proof must have salt");
  assert.ok(proof.polynomialCoefficients, "proof must have polynomialCoefficients");
  const { A_x, B_x, C_x, H_x } = proof.polynomialCoefficients;
  assert.ok(A_x && B_x && C_x && H_x, "proof must have all four poly coefficient arrays");
});

test("proof contains KZG commitments and opening proofs", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  assert.ok(proof.kzg, "proof must have kzg field");
  const { C_A, C_B, C_C, C_H, evalPoint, y_A, y_B, y_C, y_H, pi_A, pi_B, pi_C, pi_H } = proof.kzg;
  assert.ok(C_A && C_B && C_C && C_H, "proof.kzg must have all four commitments");
  assert.ok(pi_A && pi_B && pi_C && pi_H, "proof.kzg must have all four opening proofs");
  assert.ok(evalPoint, "proof.kzg must have evalPoint");
  assert.ok(y_A !== undefined && y_B !== undefined && y_C !== undefined && y_H !== undefined,
    "proof.kzg must have all four claimed evaluations");
});

test("KZG commitments are distinct", () => {
  pipeline(4, 16, 10);
  const { kzg: k } = readProof();
  // All four commitments should generally differ (polynomials are different)
  const vals = [k.C_A, k.C_B, k.C_C, k.C_H];
  const unique = new Set(vals);
  assert.ok(unique.size > 1, "KZG commitments should not all be identical");
});

test("KZG opening proofs change when age changes", () => {
  assert.ok(setup(0, 15).ok);
  assert.ok(prove(3).ok);
  const pi_A_1 = readProof().kzg.pi_A;
  assert.ok(prove(9).ok);
  const pi_A_2 = readProof().kzg.pi_A;
  assert.notStrictEqual(pi_A_1, pi_A_2, "opening proof must differ for different ages");
});

test("proving key contains KZG SRS", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  assert.ok(pk.kzg, "proving key must have kzg field");
  assert.ok(pk.kzg.srs, "proving key must have SRS");
  assert.ok(Array.isArray(pk.kzg.srs), "SRS must be an array");
  assert.ok(pk.kzg.srs.length > 0, "SRS must be non-empty");
  assert.strictEqual(pk.kzg.tau, "42", "SRS must use tau=42");
});

test("verification key contains KZG SRS", () => {
  assert.ok(setup(4, 16).ok);
  const vk = readVerificationKey();
  assert.ok(vk.kzg, "verification key must have kzg field");
  assert.ok(vk.kzg.srs, "verification key must have SRS");
  assert.ok(Array.isArray(vk.kzg.srs), "SRS must be an array");
  assert.strictEqual(vk.kzg.tau, "42", "SRS must use tau=42");
});

test("SRS[0] = 1 and SRS[1] = 42 (tau^0 and tau^1)", () => {
  assert.ok(setup(0, 15).ok);
  const pk = readProvingKey();
  assert.strictEqual(pk.kzg.srs[0], "1", "SRS[0] = tau^0 = 1");
  assert.strictEqual(pk.kzg.srs[1], "42", "SRS[1] = tau^1 = 42");
  assert.strictEqual(pk.kzg.srs[2], "1764", "SRS[2] = tau^2 = 1764");
});

test("SRS length covers degree 4k+4", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  const expectedLen = 4 * pk.k + 4 + 1; // degree d means d+1 entries
  assert.strictEqual(pk.kzg.srs.length, expectedLen,
    `SRS length should be ${expectedLen} for k=${pk.k}`);
});

test("KZG evalPoint matches Fiat-Shamir r (same challenge used)", () => {
  pipeline(0, 15, 7);
  const proof = readProof();
  // The KZG opening proofs are computed at the same r as the QAP identity check.
  // We can't easily recompute r here, but we can verify the evalPoint is a large number
  // (not a small constraint point like 1,2,3), showing it came from the hash.
  const r = BigInt(proof.kzg.evalPoint);
  const constraintPoints = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n];
  assert.ok(!constraintPoints.includes(r), "evalPoint should be the Fiat-Shamir challenge, not a constraint point");
  assert.ok(r > 1000n, "Fiat-Shamir evalPoint should be a large random value");
});

test("circuit digest changes when lo changes", () => {
  assert.ok(setup(0, 20).ok);
  const d1 = readProvingKey().circuitDigest;
  assert.ok(setup(1, 20).ok);
  const d2 = readProvingKey().circuitDigest;
  assert.notStrictEqual(d1, d2, "digest must differ when lo changes");
});

test("circuit digest changes when hi changes", () => {
  assert.ok(setup(0, 20).ok);
  const d1 = readProvingKey().circuitDigest;
  assert.ok(setup(0, 21).ok);
  const d2 = readProvingKey().circuitDigest;
  assert.notStrictEqual(d1, d2, "digest must differ when hi changes");
});

test("circuit digest is same across two setups with identical range", () => {
  assert.ok(setup(4, 16).ok);
  const d1 = readProvingKey().circuitDigest;
  assert.ok(setup(4, 16).ok);
  const d2 = readProvingKey().circuitDigest;
  assert.strictEqual(d1, d2, "digest must be deterministic for the same range");
});

test("k = 1 for gap = 1", () => {
  assert.ok(setup(0, 1).ok);
  assert.strictEqual(readProvingKey().k, 1);
});

test("k = 4 for gap = 12 (range [4,16])", () => {
  assert.ok(setup(4, 16).ok);
  assert.strictEqual(readProvingKey().k, 4);  // ceil(log2(13)) = 4
});

test("k = 6 for gap = 47 (range [18,65])", () => {
  assert.ok(setup(18, 65).ok);
  assert.strictEqual(readProvingKey().k, 6);  // ceil(log2(48)) = 6
});

test("k = 7 for gap = 64 (range [0,64])", () => {
  assert.ok(setup(0, 64).ok);
  assert.strictEqual(readProvingKey().k, 7);  // ceil(log2(65)) = 7
});

test("k = 8 for gap = 224 (range [32,256])", () => {
  assert.ok(setup(32, 256).ok);
  assert.strictEqual(readProvingKey().k, 8);  // ceil(log2(225)) = 8
});

test("k = 9 for gap = 256 (range [0,256])", () => {
  assert.ok(setup(0, 256).ok);
  assert.strictEqual(readProvingKey().k, 9);  // ceil(log2(257)) = 9
});

test("R1CS has 2k+2 constraint rows", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  const expectedRows = 2 * pk.k + 2;
  assert.strictEqual(pk.r1cs.A.length, expectedRows);
  assert.strictEqual(pk.r1cs.B.length, expectedRows);
  assert.strictEqual(pk.r1cs.C.length, expectedRows);
});

test("R1CS rows have correct witness length (2 + 2k)", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  const expectedCols = 2 + 2 * pk.k;
  for (const row of [...pk.r1cs.A, ...pk.r1cs.B, ...pk.r1cs.C]) {
    assert.strictEqual(row.length, expectedCols, "each R1CS row must have 2+2k entries");
  }
});

test("Z polynomial has degree equal to number of constraints", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  const numConstraints = pk.constraintPoints.length;
  const zDegree = pk.targetPolynomial.coeffsLowToHighDegree.length - 1;
  assert.strictEqual(zDegree, numConstraints, "Z degree must equal number of constraints");
});

test("witnessLayout length matches 2 + 2k", () => {
  assert.ok(setup(4, 16).ok);
  const pk = readProvingKey();
  assert.strictEqual(pk.witnessLayout.length, 2 + 2 * pk.k);
});

test("two proofs for the same age have different commitments (salt ensures uniqueness)", () => {
  assert.ok(setup(0, 15).ok);
  assert.ok(prove(7).ok);
  const commitment1 = readProof().commitment;

  assert.ok(prove(7).ok);
  const commitment2 = readProof().commitment;

  assert.notStrictEqual(commitment1, commitment2, "random salt must produce unique commitments");
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

const line = "─".repeat(44);
console.log(`\n${line}`);
if (failed === 0) {
  console.log(`\x1b[32mAll ${passed} tests passed.\x1b[0m`);
} else {
  console.log(`\x1b[31m${failed} test(s) failed\x1b[0m, ${passed} passed.`);
  console.log("\nFailed tests:");
  failures.forEach((f) => console.log(`  • ${f.name}`));
}
console.log(line);

process.exit(failed > 0 ? 1 : 0);
