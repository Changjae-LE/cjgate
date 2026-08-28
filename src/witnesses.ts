/**
 * CJGate witness implementations.
 *
 * The CJGate contract declares two witnesses — `secretsFound` and
 * `sastHighFindings` — that feed the security gate its private signals. Their
 * numeric values live only here, on the prover's machine: they are never
 * written to the ledger and never printed or logged by this project. The
 * on-chain contract only ever learns the boolean outcome of `== 0`.
 *
 * The counts are carried in the contract's private state and populated by the
 * scanner integrations, driven by `npm run cjgate:check`:
 *   - `secretsFound`     <- Gitleaks (`src/scanners/gitleaks.ts`)
 *   - `sastHighFindings` <- Semgrep, blocking-severity findings only
 *                           (`src/scanners/semgrep.ts`)
 */

import type { WitnessContext } from '@midnight-ntwrk/compact-runtime';

/** Private, off-chain security-scan signals for one gate evaluation. */
export type CJGatePrivateState = {
  /** Number of verified secret-scanner findings. Private. */
  readonly secretsFound: bigint;
  /** Number of high-severity SAST findings. Private. */
  readonly sastHighFindings: bigint;
};

/**
 * Build a CJGate private state from scan counts. Values are coerced to
 * BigInt and bounds-checked (non-negative, fits Uint<64>) so a bad signal
 * fails here rather than deep inside the circuit runtime.
 */
export const createCJGatePrivateState = (
  secretsFound: bigint | number,
  sastHighFindings: bigint | number,
): CJGatePrivateState => {
  const secrets = BigInt(secretsFound);
  const sast = BigInt(sastHighFindings);
  const MAX_U64 = (1n << 64n) - 1n;
  if (secrets < 0n || sast < 0n) {
    throw new Error('CJGate: scan signals must be non-negative');
  }
  if (secrets > MAX_U64 || sast > MAX_U64) {
    throw new Error('CJGate: scan signals must fit in Uint<64>');
  }
  return { secretsFound: secrets, sastHighFindings: sast };
};

/**
 * Default private state used at deploy time: a clean scan. The deployed
 * contract is re-evaluated per gate run with the caller's real scan counts.
 */
export const cleanCJGatePrivateState: CJGatePrivateState = createCJGatePrivateState(0n, 0n);

/**
 * Witness object passed to `CompiledContract.withWitnesses(...)` and to the
 * generated `Contract` class. Keys match the Compact witness names exactly.
 * Each witness returns `[unchangedPrivateState, value]` — it only reads.
 */
export const witnesses = {
  secretsFound: (
    { privateState }: WitnessContext<unknown, CJGatePrivateState>,
  ): [CJGatePrivateState, bigint] => [privateState, privateState.secretsFound],

  sastHighFindings: (
    { privateState }: WitnessContext<unknown, CJGatePrivateState>,
  ): [CJGatePrivateState, bigint] => [privateState, privateState.sastHighFindings],
};
