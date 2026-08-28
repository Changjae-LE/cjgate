/**
 * Shared CJGate policy evaluation.
 *
 * One place that runs the compiled `runSecurityGate` circuit against a given
 * private state, entirely in-process (no wallet, proof server, or devnet).
 * Both `scripts/policy-check.ts` and `scripts/cjgate-check.ts` go through here
 * so the Compact policy is evaluated identically everywhere.
 *
 * The private scan counts are never returned or logged by this module — only
 * the pass/block outcome and the public `policyPassed` ledger value.
 */
import {
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
} from '@midnight-ntwrk/compact-runtime';

import {
  Contract,
  ledger,
  type Ledger,
} from '../contracts/managed/cjgate/contract/index.js';
import { witnesses, type CJGatePrivateState } from './witnesses.js';

/** A stand-in Zswap coin public key for local, proof-free execution. */
const LOCAL_COIN_PUBLIC_KEY = '0'.repeat(64);

export type PolicyResult =
  | { outcome: 'PASS'; policyPassed: boolean }
  | { outcome: 'BLOCK'; policyPassed: false };

/**
 * Evaluate the CJGate security policy for `privateState`.
 *
 * - `PASS`  — the circuit succeeded and the public `policyPassed` flag is true.
 * - `BLOCK` — an in-circuit assertion failed (a scanner signal was non-zero);
 *   no state transition occurred.
 *
 * Never throws for a policy violation; only genuinely unexpected runtime
 * errors propagate.
 */
export function evaluatePolicy(privateState: CJGatePrivateState): PolicyResult {
  const contract = new Contract<CJGatePrivateState>(witnesses);

  const { currentContractState, currentPrivateState, currentZswapLocalState } =
    contract.initialState(
      createConstructorContext(privateState, LOCAL_COIN_PUBLIC_KEY),
    );

  const circuitContext = createCircuitContext<CJGatePrivateState>(
    sampleContractAddress(),
    currentZswapLocalState,
    currentContractState.data,
    currentPrivateState,
  );

  try {
    const { context } = contract.impureCircuits.runSecurityGate(circuitContext);
    const state: Ledger = ledger(context.currentQueryContext.state);
    // A pass is only real if the public flag actually flipped to true.
    return state.policyPassed
      ? { outcome: 'PASS', policyPassed: true }
      : { outcome: 'BLOCK', policyPassed: false };
  } catch (err) {
    // An assertion failure is the expected "policy violated" path. Re-throw
    // anything that doesn't look like a Compact assertion abort.
    const msg = err instanceof Error ? err.message : String(err);
    if (!/failed assert/i.test(msg)) throw err;
    return { outcome: 'BLOCK', policyPassed: false };
  }
}
