const fs = require("fs");
const crypto = require("crypto");

function mod(n, p) {
  return ((n % p) + p) % p;
}

function modPow(base, exp, p) {
  let b = mod(base, p);
  let e = exp;
  let out = 1;
  while (e > 0) {
    if (e & 1) out = mod(out * b, p);
    b = mod(b * b, p);
    e >>= 1;
  }
  return out;
}

function modInv(n, p) {
  if (mod(n, p) === 0) {
    throw new Error("Attempted inversion of 0 in finite field.");
  }
  // Fermat's little theorem, p is prime
  return modPow(n, p - 2, p);
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

function deriveChallengeR({ commitment, prime, publicSeed, forbiddenPoints }) {
  // Fiat–Shamir-style: r is derived from transcript data (commitment + public seed),
  // so the prover cannot pick an arbitrary r.
  let counter = 0;
  while (true) {
    const toHash = `${commitment}|${publicSeed}|${counter}`;
    const hex = sha256Hex(toHash);
    // Use first 8 hex chars to get a deterministic number (fits in JS safe integer).
    const num = parseInt(hex.slice(0, 8), 16);
    const r = num % prime;
    const isForbidden = (forbiddenPoints || []).includes(r);
    if (!isForbidden) return r;
    counter += 1;
  }
}

function polyTrim(poly) {
  const out = poly.slice();
  while (out.length > 1 && out[out.length - 1] === 0) out.pop();
  return out;
}

function polyAdd(a, b, p) {
  const len = Math.max(a.length, b.length);
  const out = Array(len).fill(0);
  for (let i = 0; i < len; i += 1) {
    out[i] = mod((a[i] || 0) + (b[i] || 0), p);
  }
  return polyTrim(out);
}

function polySub(a, b, p) {
  const len = Math.max(a.length, b.length);
  const out = Array(len).fill(0);
  for (let i = 0; i < len; i += 1) {
    out[i] = mod((a[i] || 0) - (b[i] || 0), p);
  }
  return polyTrim(out);
}

function polyMul(a, b, p) {
  const out = Array(a.length + b.length - 1).fill(0);
  for (let i = 0; i < a.length; i += 1) {
    for (let j = 0; j < b.length; j += 1) {
      out[i + j] = mod(out[i + j] + a[i] * b[j], p);
    }
  }
  return polyTrim(out);
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

function polyDiv(numerator, denominator, p) {
  const num = numerator.slice();
  const den = polyTrim(denominator);
  const numDeg = () => polyTrim(num).length - 1;
  const denDeg = den.length - 1;

  if (denDeg < 0 || (denDeg === 0 && den[0] === 0)) {
    throw new Error("Division by zero polynomial.");
  }

  const quotient = Array(Math.max(0, num.length - den.length + 1)).fill(0);

  while (numDeg() >= denDeg) {
    const curDeg = numDeg();
    const leadNum = num[curDeg];
    const leadDen = den[denDeg];
    const scale = mod(leadNum * modInv(leadDen, p), p);
    const shift = curDeg - denDeg;
    quotient[shift] = scale;

    for (let i = 0; i <= denDeg; i += 1) {
      num[i + shift] = mod(num[i + shift] - scale * den[i], p);
    }
  }

  const remainder = polyTrim(num);
  return { quotient: polyTrim(quotient), remainder };
}

function dot(row, witness, p) {
  let s = 0;
  for (let i = 0; i < row.length; i += 1) {
    s = mod(s + row[i] * witness[i], p);
  }
  return s;
}

function lagrangeInterpolate(xs, ys, p) {
  let result = [0];
  for (let i = 0; i < xs.length; i += 1) {
    let basis = [1];
    let denom = 1;
    for (let j = 0; j < xs.length; j += 1) {
      if (i === j) continue;
      basis = polyMul(basis, [mod(-xs[j], p), 1], p);
      denom = mod(denom * mod(xs[i] - xs[j], p), p);
    }
    const scale = mod(ys[i] * modInv(denom, p), p);
    basis = basis.map((c) => mod(c * scale, p));
    result = polyAdd(result, basis, p);
  }
  return polyTrim(result);
}

function toBits2(age) {
  const b0 = age & 1;
  const b1 = (age >> 1) & 1;
  return [b0, b1];
}

function formatPoly(poly) {
  const terms = [];
  for (let i = poly.length - 1; i >= 0; i -= 1) {
    const c = poly[i];
    if (c === 0) continue;
    if (i === 0) terms.push(`${c}`);
    else if (i === 1) terms.push(`${c}*x`);
    else terms.push(`${c}*x^${i}`);
  }
  return terms.length === 0 ? "0" : terms.join(" + ");
}

function logDetailedLagrangeForLabel(label, vals, p) {
  const inv2 = modInv(2, p);
  const l1 = [3, 46, 49]; // 49x^2 + 46x + 3
  const l2 = [94, 4, 96]; // 96x^2 + 4x + 94
  const l3 = [1, 47, 49]; // 49x^2 + 47x + 1

  const x2Raw = vals[0] * l1[2] + vals[1] * l2[2] + vals[2] * l3[2];
  const x1Raw = vals[0] * l1[1] + vals[1] * l2[1] + vals[2] * l3[1];
  const x0Raw = vals[0] * l1[0] + vals[1] * l2[0] + vals[2] * l3[0];

  console.log(`[Prover] Detailed Lagrange explanation for ${label}(x):`);
  console.log(`[Prover] Target points: ${label}(1)=${vals[0]}, ${label}(2)=${vals[1]}, ${label}(3)=${vals[2]}`);
  console.log("[Prover] Build Lagrange basis polynomials over points {1,2,3} in F_97:");
  console.log("[Prover]   L1(x) = ((x-2)(x-3))/((1-2)(1-3)) = ((x-2)(x-3))/2");
  console.log("[Prover]         = (x^2 - 5x + 6)/2");
  console.log(
    `[Prover]         divide by 2 in F_97 means multiply by inverse(2)=${inv2}, since 2*${inv2}=1 mod 97`
  );
  console.log("[Prover]         = 49*(x^2 - 5x + 6) mod 97");
  console.log("[Prover]         = 49x^2 + 46x + 3");
  console.log("[Prover]   L2(x) = ((x-1)(x-3))/((2-1)(2-3)) = ((x-1)(x-3))/(-1)");
  console.log("[Prover]         = -(x^2 - 4x + 3)");
  console.log("[Prover]         = 96x^2 + 4x + 94");
  console.log("[Prover]   L3(x) = ((x-1)(x-2))/((3-1)(3-2)) = ((x-1)(x-2))/2");
  console.log("[Prover]         = (x^2 - 3x + 2)/2");
  console.log(
    `[Prover]         divide by 2 in F_97 means multiply by inverse(2)=${inv2}`
  );
  console.log("[Prover]         = 49*(x^2 - 3x + 2) mod 97");
  console.log("[Prover]         = 49x^2 + 47x + 1");
  console.log("[Prover] Interpolate:");
  console.log(
    `[Prover]   ${label}(x) = ${vals[0]}*L1(x) + ${vals[1]}*L2(x) + ${vals[2]}*L3(x) mod 97`
  );
  console.log("[Prover] Coefficient-by-coefficient:");
  console.log(
    `[Prover]   x^2: ${vals[0]}*49 + ${vals[1]}*96 + ${vals[2]}*49 = ${x2Raw} mod 97 = ${mod(
      x2Raw,
      p
    )}`
  );
  console.log(
    `[Prover]   x^1: ${vals[0]}*46 + ${vals[1]}*4 + ${vals[2]}*47 = ${x1Raw} mod 97 = ${mod(
      x1Raw,
      p
    )}`
  );
  console.log(
    `[Prover]   x^0: ${vals[0]}*3 + ${vals[1]}*94 + ${vals[2]}*1 = ${x0Raw} mod 97 = ${mod(
      x0Raw,
      p
    )}`
  );
  console.log(
    `[Prover] Therefore ${label}(x) coeffs(low->high) = [${mod(x0Raw, p)},${mod(
      x1Raw,
      p
    )},${mod(x2Raw, p)}]`
  );
}

function logDetailedPComputation(APoly, BPoly, CPoly, p) {
  console.log("[Prover] Detailed polynomial multiplication for A(x) * B(x):");
  console.log(`[Prover]   A(x) = ${formatPoly(APoly)}`);
  console.log(`[Prover]   B(x) = ${formatPoly(BPoly)}`);

  const mult = Array(APoly.length + BPoly.length - 1).fill(0);
  for (let i = 0; i < APoly.length; i += 1) {
    for (let j = 0; j < BPoly.length; j += 1) {
      const raw = APoly[i] * BPoly[j];
      const deg = i + j;
      const before = mult[deg];
      mult[deg] = mod(mult[deg] + raw, p);
      console.log(
        `[Prover]   term: (${APoly[i]}*x^${i}) * (${BPoly[j]}*x^${j}) = ${raw}*x^${deg}; accumulate coeff[x^${deg}] ${before} -> ${mult[deg]} (mod ${p})`
      );
    }
  }
  console.log(
    `[Prover]   Result A(x)B(x) coeffs(low->high): ${JSON.stringify(mult)}`
  );
  console.log(
    `[Prover]   Result A(x)B(x) readable: ${formatPoly(mult)}`
  );
  console.log("[Prover] Now subtract C(x) coefficient-by-coefficient:");
  console.log(`[Prover]   C(x) coeffs(low->high): ${JSON.stringify(CPoly)}`);

  const len = Math.max(mult.length, CPoly.length);
  const pCoeffs = Array(len).fill(0);
  for (let d = 0; d < len; d += 1) {
    const left = mult[d] || 0;
    const right = CPoly[d] || 0;
    const raw = left - right;
    pCoeffs[d] = mod(raw, p);
    console.log(
      `[Prover]   degree x^${d}: (${left}) - (${right}) = ${raw} -> ${pCoeffs[d]} mod ${p}`
    );
  }

  console.log(
    `[Prover]   Final P(x)=A(x)B(x)-C(x) coeffs(low->high): ${JSON.stringify(
      pCoeffs
    )}`
  );
  if (pCoeffs[0] === 0) {
    console.log(
      "[Prover]   Note: x^0 term is 0 because constant terms cancelled in this witness."
    );
  }
}

function logDetailedZExplanation(p) {
  console.log("[Prover] Detailed target polynomial Z(x) explanation:");
  console.log("[Prover]   Constraint points are x=1,2,3 so Z(x) must vanish there.");
  console.log("[Prover]   Z(x) = (x-1)(x-2)(x-3)");
  console.log("[Prover]   (x-1)(x-2) = x^2 - 3x + 2");
  console.log("[Prover]   (x^2 - 3x + 2)(x-3) = x^3 - 6x^2 + 11x - 6");
  console.log(
    `[Prover]   Convert to F_${p}: -6 -> ${mod(-6, p)}, 11 -> ${mod(
      11,
      p
    )}, -6 -> ${mod(-6, p)}`
  );
  console.log(
    `[Prover]   Therefore Z(x) coeffs(low->high) = [${mod(-6, p)},${mod(
      11,
      p
    )},${mod(-6, p)},1]`
  );
}

function detailedPolyDiv(numerator, denominator, p) {
  const num = numerator.slice();
  const den = polyTrim(denominator);
  const quotient = Array(Math.max(0, num.length - den.length + 1)).fill(0);

  console.log("[Prover] Detailed long division for H(x) = P(x)/Z(x):");
  console.log(`[Prover]   P(x) coeffs(low->high): ${JSON.stringify(num)}`);
  console.log(`[Prover]   Z(x) coeffs(low->high): ${JSON.stringify(den)}`);
  console.log(`[Prover]   P(x) readable: ${formatPoly(num)}`);
  console.log(`[Prover]   Z(x) readable: ${formatPoly(den)}`);

  while (polyTrim(num).length - 1 >= den.length - 1) {
    const curDeg = polyTrim(num).length - 1;
    const denDeg = den.length - 1;
    const leadNum = num[curDeg];
    const leadDen = den[denDeg];
    const invLeadDen = modInv(leadDen, p);
    const scale = mod(leadNum * invLeadDen, p);
    const shift = curDeg - denDeg;
    quotient[shift] = scale;

    console.log(
      `[Prover]   Step: cancel degree x^${curDeg} using (${leadNum}/${leadDen})*x^${shift}`
    );
    console.log(
      `[Prover]         in F_${p}: ${leadNum} * inv(${leadDen}) where inv(${leadDen})=${invLeadDen}, so scale=${scale}`
    );
    console.log(
      `[Prover]         add ${scale}*x^${shift} to quotient => current H coeffs(low->high): ${JSON.stringify(
        polyTrim(quotient)
      )}`
    );

    // Human-friendly expansion for the current subtraction step.
    const rawExpanded = [];
    const modExpanded = [];
    for (let i = 0; i <= denDeg; i += 1) {
      const degree = i + shift;
      const rawCoeff = scale * den[i];
      rawExpanded.push({ degree, coeff: rawCoeff });
      modExpanded.push({ degree, coeff: mod(rawCoeff, p) });
    }
    const rawExpandedText = rawExpanded
      .sort((a, b) => b.degree - a.degree)
      .map((t) => `${t.coeff}x^${t.degree}`)
      .join(" + ");
    const modExpandedText = modExpanded
      .sort((a, b) => b.degree - a.degree)
      .map((t) => `${t.coeff}x^${t.degree}`)
      .join(" + ");
    console.log(
      `[Prover]         expanded raw product (${scale}*x^${shift})*Z(x): ${rawExpandedText}`
    );
    console.log(
      `[Prover]         after mod ${p}: ${modExpandedText}`
    );

    for (let i = 0; i <= denDeg; i += 1) {
      const idx = i + shift;
      const subTerm = mod(scale * den[i], p);
      const before = num[idx];
      num[idx] = mod(num[idx] - subTerm, p);
      console.log(
        `[Prover]         update degree x^${idx}: ${before} - (${scale}*${den[i]}=${subTerm}) -> ${num[idx]} mod ${p}`
      );
    }
    console.log(
      `[Prover]         numerator after step (low->high): ${JSON.stringify(
        polyTrim(num)
      )}`
    );
  }

  const remainder = polyTrim(num);
  console.log(
    `[Prover]   Final H(x) coeffs(low->high): ${JSON.stringify(polyTrim(
      quotient
    ))}`
  );
  console.log(
    `[Prover]   Final remainder coeffs(low->high): ${JSON.stringify(remainder)}`
  );
  if (remainder.length === 1 && remainder[0] === 0) {
    console.log("[Prover]   Since remainder is 0, Z(x) divides P(x) exactly.");
    console.log(
      `[Prover]   Therefore in QAP form: P(x) = H(x) * Z(x), with H(x) = ${formatPoly(
        polyTrim(quotient)
      )}`
    );
  }
  return { quotient: polyTrim(quotient), remainder };
}

function logEvaluationHandshake({
  p,
  r,
  APoly,
  BPoly,
  CPoly,
  HPoly,
  Z,
  witness,
  evals,
}) {
  const Zr = polyEval(Z, r, p);
  const lhsRaw = evals.A_r * evals.B_r - evals.C_r;
  const rhsRaw = evals.H_r * Zr;
  const lhs = mod(lhsRaw, p);
  const rhs = mod(rhsRaw, p);

  console.log("[Prover] ===== Evaluation Handshake (Proof Packaging) =====");
  console.log(
    `[Prover] We now move from full polynomials to single-point evaluations at secret r=${r}.`
  );
  console.log(
    "[Prover] Why: sending full polynomial coefficients can leak structure; sending evaluations is the proof-style check."
  );
  console.log(
    `[Prover] Public/derived polynomials: A(x)=${formatPoly(APoly)}, B(x)=${formatPoly(
      BPoly
    )}, C(x)=${formatPoly(CPoly)}, H(x)=${formatPoly(HPoly)}`
  );
  console.log(
    `[Prover] Evaluate at r=${r}: A(r)=${evals.A_r}, B(r)=${evals.B_r}, C(r)=${evals.C_r}, H(r)=${evals.H_r}`
  );
  console.log(
    `[Prover] Debug note: witness ${JSON.stringify(
      witness
    )} is included only for learning/debugging. Real ZK proofs do NOT reveal witness values.`
  );

  console.log("[Prover] Verifier-side equation that must hold in F_97:");
  console.log("[Prover]   (A(r) * B(r) - C(r)) == H(r) * Z(r)");
  console.log(
    `[Prover]   Z(r) is public-computable from Z(x): Z(${r}) = ${Zr}`
  );
  console.log(
    `[Prover]   LHS raw: (${evals.A_r} * ${evals.B_r}) - ${evals.C_r} = ${lhsRaw}; LHS mod ${p} = ${lhs}`
  );
  console.log(
    `[Prover]   RHS raw: (${evals.H_r} * ${Zr}) = ${rhsRaw}; RHS mod ${p} = ${rhs}`
  );
  console.log(
    `[Prover]   Handshake check value: ${lhs} ${lhs === rhs ? "==" : "!="} ${rhs}`
  );
  console.log(
    "[Prover] If this equality fails, the witness does not satisfy the circuit constraints."
  );
  console.log("[Prover] ==================================================");
}

function main() {
  const requirements = JSON.parse(fs.readFileSync("requirements.json", "utf8"));
  const p = requirements.prime;
  const points = requirements.constraintPoints;
  const { A, B, C } = requirements.r1cs;
  const Z = requirements.targetPolynomial.coeffsLowToHighDegree;

  const ageRaw = process.argv[2];
  const age = ageRaw === undefined ? 2 : Number(ageRaw);

  console.log("========== PROVER START ==========");
  console.log("[Prover] Reading requirements.json");
  console.log(`[Prover] Field prime: ${p}`);
  console.log(`[Prover] Constraint points: ${JSON.stringify(points)}`);
  console.log(
    `[Prover] Input age from CLI: ${ageRaw === undefined ? "(not provided, default=2)" : ageRaw}`
  );

  if (!Number.isInteger(age) || age < 0 || age > 3) {
    throw new Error("Age must be an integer in [0, 3] for 2-bit range proof.");
  }

  const [b0, b1] = toBits2(age);
  const witness = [1, age, b0, b1];
  console.log(
    `[Prover] Derived 2-bit decomposition: age=${age} -> b0=${b0}, b1=${b1}`
  );
  console.log(`[Prover] Witness vector: ${JSON.stringify(witness)}`);

  const aVals = A.map((row) => dot(row, witness, p));
  const bVals = B.map((row) => dot(row, witness, p));
  const cVals = C.map((row) => dot(row, witness, p));
  console.log(`[Prover] A-values at constraints: ${JSON.stringify(aVals)}`);
  console.log(`[Prover] B-values at constraints: ${JSON.stringify(bVals)}`);
  console.log(`[Prover] C-values at constraints: ${JSON.stringify(cVals)}`);
  console.log("[Prover] How these are computed (row dot witness) in R1CS:");
  A.forEach((row, i) => {
    console.log(
      `[Prover]   A row ${i + 1}: ${JSON.stringify(row)} dot ${JSON.stringify(
        witness
      )} = ${aVals[i]}`
    );
  });
  B.forEach((row, i) => {
    console.log(
      `[Prover]   B row ${i + 1}: ${JSON.stringify(row)} dot ${JSON.stringify(
        witness
      )} = ${bVals[i]}`
    );
  });
  C.forEach((row, i) => {
    console.log(
      `[Prover]   C row ${i + 1}: ${JSON.stringify(row)} dot ${JSON.stringify(
        witness
      )} = ${cVals[i]}`
    );
  });
  console.log(
    "[Prover] Interpolation idea: build one polynomial that matches each list at x=1,2,3."
  );
  console.log(
    `[Prover]   A(1)=${aVals[0]}, A(2)=${aVals[1]}, A(3)=${aVals[2]}`
  );
  console.log(
    `[Prover]   B(1)=${bVals[0]}, B(2)=${bVals[1]}, B(3)=${bVals[2]}`
  );
  console.log(
    `[Prover]   C(1)=${cVals[0]}, C(2)=${cVals[1]}, C(3)=${cVals[2]}`
  );
  logDetailedLagrangeForLabel("A", aVals, p);
  logDetailedLagrangeForLabel("B", bVals, p);
  logDetailedLagrangeForLabel("C", cVals, p);

  const APoly = lagrangeInterpolate(points, aVals, p);
  const BPoly = lagrangeInterpolate(points, bVals, p);
  const CPoly = lagrangeInterpolate(points, cVals, p);
  console.log(
    `[Prover] Interpolated A(x) coeffs (low->high): ${JSON.stringify(APoly)}`
  );
  console.log(
    `[Prover] Interpolated B(x) coeffs (low->high): ${JSON.stringify(BPoly)}`
  );
  console.log(
    `[Prover] Interpolated C(x) coeffs (low->high): ${JSON.stringify(CPoly)}`
  );
  console.log(`[Prover] A(x) readable form in F_${p}: ${formatPoly(APoly)}`);
  console.log(`[Prover] B(x) readable form in F_${p}: ${formatPoly(BPoly)}`);
  console.log(`[Prover] C(x) readable form in F_${p}: ${formatPoly(CPoly)}`);
  console.log(
    "[Prover] Check: each polynomial above, when evaluated at x=1,2,3, gives the corresponding values list."
  );
  logDetailedPComputation(APoly, BPoly, CPoly, p);
  logDetailedZExplanation(p);

  const P = polySub(polyMul(APoly, BPoly, p), CPoly, p); // A*B - C
  const { quotient: HPoly, remainder } = detailedPolyDiv(P, Z, p);
  console.log(
    `[Prover] Computed P(x)=A(x)B(x)-C(x) coeffs (low->high): ${JSON.stringify(P)}`
  );
  console.log(
    `[Prover] Target Z(x) coeffs (low->high): ${JSON.stringify(Z)}`
  );
  console.log(
    `[Prover] Quotient H(x) coeffs (low->high): ${JSON.stringify(HPoly)}`
  );
  console.log(
    `[Prover] Division remainder coeffs (must be [0]): ${JSON.stringify(
      remainder
    )}`
  );

  if (!(remainder.length === 1 && remainder[0] === 0)) {
    throw new Error("Remainder is non-zero: witness does not satisfy constraints.");
  }

  // Fiat–Shamir "challenge": r is derived from the prover's polynomial commitment (hash),
  // plus public parameters, so the prover can't freely choose r after seeing the verifier.
  const commitment = sha256Hex(
    JSON.stringify({
      A_x: APoly,
      B_x: BPoly,
      C_x: CPoly,
      H_x: HPoly,
    })
  );
  const publicSeed = JSON.stringify({
    prime: p,
    constraintPoints: points,
    targetZCoeffsLowToHighDegree: Z,
  });

  const forbiddenPoints = [1, 2, 3];
  const secretPoint = deriveChallengeR({
    commitment,
    prime: p,
    publicSeed,
    forbiddenPoints,
  });

  console.log(
    `[Prover] Derived Fiat–Shamir challenge point r=${secretPoint} from commitment.`
  );
  const payload = {
    prime: p,
    commitment,
    witness: {
      layout: requirements.witnessLayout,
      values: witness,
    },
    polynomialEvaluationsAtSecretPoint: {
      A_r: polyEval(APoly, secretPoint, p),
      B_r: polyEval(BPoly, secretPoint, p),
      C_r: polyEval(CPoly, secretPoint, p),
      H_r: polyEval(HPoly, secretPoint, p),
    },
    polynomialsLowToHighDegree: {
      A_x: APoly,
      B_x: BPoly,
      C_x: CPoly,
      H_x: HPoly,
    },
  };
  logEvaluationHandshake({
    p,
    r: secretPoint,
    APoly,
    BPoly,
    CPoly,
    HPoly,
    Z,
    witness,
    evals: payload.polynomialEvaluationsAtSecretPoint,
  });
  console.log(
    `[Prover] Evaluations at r: ${JSON.stringify(
      payload.polynomialEvaluationsAtSecretPoint
    )}`
  );

  console.log(
    `Prover is sending [witness.values=${JSON.stringify(
      payload.witness.values
    )}] to proof.json`
  );
  console.log(
    `Prover is sending [A(r), B(r), C(r), H(r)=${JSON.stringify(
      payload.polynomialEvaluationsAtSecretPoint
    )}] to proof.json`
  );

  fs.writeFileSync("proof.json", JSON.stringify(payload, null, 2), "utf8");
  console.log("proof.json generated successfully.");
  console.log("=========== PROVER END ===========");
}

main();
