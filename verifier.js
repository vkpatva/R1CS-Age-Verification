const fs = require("fs");
const crypto = require("crypto");

function mod(n, p) {
  return ((n % p) + p) % p;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

function deriveChallengeR({ commitment, prime, publicSeed, forbiddenPoints }) {
  let counter = 0;
  while (true) {
    const toHash = `${commitment}|${publicSeed}|${counter}`;
    const hex = sha256Hex(toHash);
    const num = parseInt(hex.slice(0, 8), 16);
    const r = num % prime;
    const isForbidden = (forbiddenPoints || []).includes(r);
    if (!isForbidden) return r;
    counter += 1;
  }
}

function polyEval(poly, x, p) {
  let result = 0;
  let xPow = 1;
  for (const c of poly) {
    result = mod(result + c * xPow, p);
    xPow = mod(xPow * x, p);
  }
  return result;
}

function main() {
  const requirements = JSON.parse(fs.readFileSync("requirements.json", "utf8"));
  const proof = JSON.parse(fs.readFileSync("proof.json", "utf8"));
  console.log("========= VERIFIER START =========");
  console.log("[Verifier] Reading requirements.json and proof.json");

  console.log("Verifier is reading [commitment] from proof.json");
  const commitment = proof.commitment;

  console.log("Verifier is reading [A(r), B(r), C(r), H(r)] from proof.json");
  const { A_r, B_r, C_r, H_r } = proof.polynomialEvaluationsAtSecretPoint;

  const p = requirements.prime;
  const Z = requirements.targetPolynomial.coeffsLowToHighDegree;
  const points = requirements.constraintPoints;
  const publicSeed = JSON.stringify({
    prime: p,
    constraintPoints: points,
    targetZCoeffsLowToHighDegree: Z,
  });

  const forbiddenPoints = [1, 2, 3];
  const r = deriveChallengeR({
    commitment,
    prime: p,
    publicSeed,
    forbiddenPoints,
  });
  console.log(`[Verifier] Field prime: ${p}`);
  console.log(
    `[Verifier] Derived Fiat–Shamir challenge point r=${r} from commitment`
  );
  console.log(`[Verifier] Target Z(x) coeffs (low->high): ${JSON.stringify(Z)}`);
  const Z_r = polyEval(Z, r, p);

  const lhs = mod(A_r * B_r - C_r, p);
  const rhs = mod(H_r * Z_r, p);

  console.log(
    `[Verifier] Parsed evaluations from proof: ${JSON.stringify({ A_r, B_r, C_r, H_r })}`
  );
  console.log(`Verifier computed LHS = A(r)*B(r)-C(r): ${lhs}`);
  console.log(`Verifier computed RHS = H(r)*Z(r): ${rhs}`);
  console.log(`Verifier computed Z(r): ${Z_r}`);

  if (lhs === rhs) {
    console.log("Verification SUCCESS: A(r) * B(r) - C(r) == H(r) * Z(r)");
  } else {
    console.log("Verification FAILED: identity does not hold.");
  }
  console.log("========== VERIFIER END ==========");
}

main();
