const fs = require("fs");

const PRIME = 97;
const CONSTRAINT_POINTS = [1, 2, 3];

// Witness layout: [1, age, b0, b1]
const A = [
  [0, 0, 1, 0], // b0
  [0, 0, 0, 1], // b1
  [0, 1, 0, 0], // age
];

const B = [
  [-1, 0, 1, 0], // b0 - 1
  [-1, 0, 0, 1], // b1 - 1
  [1, 0, 0, 0], // 1
];

const C = [
  [0, 0, 0, 0], // 0
  [0, 0, 0, 0], // 0
  [0, 0, 1, 2], // b0 + 2*b1
];

function mod(n) {
  return ((n % PRIME) + PRIME) % PRIME;
}

function mulPoly(a, b) {
  const out = Array(a.length + b.length - 1).fill(0);
  for (let i = 0; i < a.length; i += 1) {
    for (let j = 0; j < b.length; j += 1) {
      out[i + j] = mod(out[i + j] + a[i] * b[j]);
    }
  }
  return out;
}

function polyFromRoots(roots) {
  let p = [1];
  for (const r of roots) {
    p = mulPoly(p, [mod(-r), 1]);
  }
  return p;
}

const Z = polyFromRoots(CONSTRAINT_POINTS);

const requirements = {
  prime: PRIME,
  witnessLayout: ["1", "age", "b0", "b1"],
  constraintsDescription: [
    "b0 * (b0 - 1) = 0",
    "b1 * (b1 - 1) = 0",
    "age * 1 = b0 + 2*b1",
  ],
  constraintPoints: CONSTRAINT_POINTS,
  r1cs: { A, B, C },
  targetPolynomial: {
    name: "Z(x)",
    coeffsLowToHighDegree: Z,
    display: "(x-1)(x-2)(x-3)",
  },
};

console.log("========== SETUP START ==========");
console.log(`[Setup] Prime field selected: F_${PRIME}`);
console.log(
  `[Setup] Constraint interpolation points: ${JSON.stringify(CONSTRAINT_POINTS)}`
);
console.log("[Setup] Witness layout fixed as: [1, age, b0, b1]");
console.log("[Setup] Constraint 1: b0 * (b0 - 1) = 0");
console.log("[Setup] Constraint 2: b1 * (b1 - 1) = 0");
console.log("[Setup] Constraint 3: age * 1 = b0 + 2*b1");
console.log(`[Setup] Matrix A: ${JSON.stringify(A)}`);
console.log(`[Setup] Matrix B: ${JSON.stringify(B)}`);
console.log(`[Setup] Matrix C: ${JSON.stringify(C)}`);
console.log("[Setup] Why Z(x) looks like [91,11,91,1]:");
console.log("[Setup] We place constraints at x=1, x=2, x=3, so Z(x) must be 0 at each.");
console.log("[Setup] Z(x) = (x-1)(x-2)(x-3)");
console.log("[Setup] Step 1: (x-1)(x-2) = x^2 - 3x + 2");
console.log(
  "[Setup] Step 2: (x^2 - 3x + 2)(x-3) = x^3 - 6x^2 + 11x - 6"
);
console.log(
  "[Setup] Convert negatives into F_97: -6 -> 91, 11 -> 11, -6 -> 91, leading 1 -> 1"
);
console.log(
  "[Setup] Therefore Z(x) coeffs from x^0..x^3 are [91,11,91,1] in F_97."
);
console.log(
  `[Setup] Computed target polynomial Z(x) coefficients (low->high): ${JSON.stringify(
    Z
  )}`
);
console.log("[Setup] Writing requirements.json with R1CS + QAP target data.");

fs.writeFileSync(
  "requirements.json",
  JSON.stringify(requirements, null, 2),
  "utf8"
);

console.log("requirements.json generated successfully.");
console.log("R1CS matrices and target polynomial Z(x) are ready.");
console.log("=========== SETUP END ===========");
