# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Educational zero-knowledge proof demo implementing a **2-bit range proof** using R1CS → QAP conversion. Proves `0 ≤ Age ≤ 3` without revealing the actual age value. Intentionally verbose for learning purposes — not production ZK.

## Commands

```bash
# Stage 1: Generate proving key, verification key, and circuit digest
npm run setup          # or: node setup.js

# Stage 2: Generate proof for a witness value (0-3)
npm run prove -- <age> # or: node prover.js <age>

# Stage 3: Verify the proof
npm run verify         # or: node verifier.js

# Full demo pipeline (age=2)
npm run demo
```

No test framework or linter is configured.

## Architecture

Three-stage pipeline across three source files. All arithmetic uses `BigInt` throughout.

**`setup.js`** — Defines 3 R1CS constraints and builds the QAP:
- Witness layout: `[1, age, b0, b1]`
- Target polynomial `Z(x) = (x-1)(x-2)(x-3)` with roots at constraint points `{1, 2, 3}`
- Computes `circuitDigest = sha256(prime‖R1CS‖Z)` to bind proofs to this exact circuit
- Writes `proving_key.json` (full R1CS + digest) and `verification_key.json` (Z(x) + digest only)

**`prover.js`** — Full proving pipeline:
- Reads `proving_key.json`; decomposes `age` into bits: `age = b0 + 2*b1`
- Lagrange-interpolates R1CS dot products to build `A(x)`, `B(x)`, `C(x)`
- Computes quotient `H(x)` such that `A(x)*B(x) - C(x) = H(x)*Z(x)` (zero remainder proves constraints)
- Commitment = `sha256(circuitDigest ‖ A_x ‖ B_x ‖ C_x ‖ H_x)`; derives Fiat-Shamir `r` from it
- Writes `proof.json` with commitment + polynomial coefficients; **witness is not written**

**`verifier.js`** — Reads only `verification_key.json`:
1. Recomputes commitment from submitted coefficients + `circuitDigest` from vk; checks it matches
2. Derives `r` from the verified commitment
3. Evaluates `A(r)`, `B(r)`, `C(r)`, `H(r)` itself (not from the proof) and `Z(r)` from vk
4. Checks: `A(r) * B(r) - C(r) == H(r) * Z(r)` in field F_(2^61-1)

## Key Design Details

- **Prime field**: `2^61 - 1` (Mersenne prime); soundness error ≈ 2⁻⁵⁹ vs ~4% with the original F₉₇
- **BigInt**: all polynomial arithmetic and field operations use JS `BigInt` to avoid 53-bit overflow
- **The 3 constraints**: `b0*(b0-1)=0`, `b1*(b1-1)=0`, `age = b0 + 2*b1`
- **Commitment binding**: verifier recomputes evaluations from committed coefficients — a prover cannot fabricate evaluations inconsistent with committed polynomials
- **Circuit integrity**: `circuitDigest` in vk catches any post-setup tampering of circuit parameters
- **Proving/verification key split**: verifier never reads R1CS matrices
- **Remaining ZK limitation**: polynomial coefficients in the proof encode the witness (they're needed for the commitment opening). True ZK requires replacing hash-based commitment with an EC polynomial commitment scheme (e.g. KZG)

## Generated Files

- `proving_key.json` — R1CS matrices, Z(x), circuit digest (output of setup; prover input)
- `verification_key.json` — Z(x), circuit digest only (output of setup; verifier input)
- `proof.json` — Commitment + polynomial coefficients as commitment opening (no witness, no pre-computed evaluations)
