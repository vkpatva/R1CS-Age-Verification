const fs = require("fs");

function mod(n, p) {
  return ((n % p) + p) % p;
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

  console.log("Verifier is reading [secretPoint] from proof.json");
  const r = proof.secretPoint;

  console.log("Verifier is reading [A(r), B(r), C(r), H(r)] from proof.json");
  const { A_r, B_r, C_r, H_r } = proof.polynomialEvaluationsAtSecretPoint;

  const p = requirements.prime;
  const Z = requirements.targetPolynomial.coeffsLowToHighDegree;
  console.log(`[Verifier] Field prime: ${p}`);
  console.log(`[Verifier] Using secret point r=${r}`);
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
