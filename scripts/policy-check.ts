/**
 * Local verification for the CJGate security gate.
 *
 * Runs the compiled `runSecurityGate` circuit entirely in-process against the
 * Compact JS runtime — no wallet, no proof server, no devnet. It exercises
 * three cases:
 *
 *   clean input      (0 secrets, 0 SAST high)  -> PASS  (policyPassed == true)
 *   secret violation (1 secret,  0 SAST high)  -> BLOCK  (assertion fails)
 *   SAST violation   (0 secrets, 1 SAST high)  -> BLOCK  (assertion fails)
 *
 * The private scan counts are never printed. Only the pass/block outcome and
 * the public `policyPassed` ledger value are reported.
 *
 * Exit code 0 iff all three cases behave as expected.
 */
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

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
import {
  createCJGatePrivateState,
  witnesses,
  type CJGatePrivateState,
} from '../src/witnesses.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// A stand-in Zswap coin public key for local, proof-free execution.
const LOCAL_COIN_PUBLIC_KEY = '0'.repeat(64);

type GateOutcome =
  | { kind: 'pass'; policyPassed: boolean }
  | { kind: 'block'; reason: string };

/**
 * Instantiate the contract with the given private state and run the gate
 * once. Returns 'pass' with the resulting public ledger value, or 'block'
 * when the circuit aborts (an assertion failed).
 */
function runGate(privateState: CJGatePrivateState): GateOutcome {
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
    return { kind: 'pass', policyPassed: state.policyPassed };
  } catch (err) {
    return { kind: 'block', reason: err instanceof Error ? err.message : String(err) };
  }
}

type Case = {
  name: string;
  privateState: CJGatePrivateState;
  expect: 'PASS' | 'BLOCK';
};

const cases: Case[] = [
  {
    name: 'clean input',
    privateState: createCJGatePrivateState(0n, 0n),
    expect: 'PASS',
  },
  {
    name: 'secret violation',
    privateState: createCJGatePrivateState(1n, 0n),
    expect: 'BLOCK',
  },
  {
    name: 'SAST violation',
    privateState: createCJGatePrivateState(0n, 1n),
    expect: 'BLOCK',
  },
];

function main(): void {
  console.log('\nCJGate local policy verification');
  console.log('contract: contracts/managed/cjgate  circuit: runSecurityGate\n');

  let failures = 0;

  for (const c of cases) {
    const outcome = runGate(c.privateState);

    let actual: 'PASS' | 'BLOCK';
    let detail: string;
    if (outcome.kind === 'pass') {
      // A pass is only valid if the public flag actually flipped to true.
      actual = outcome.policyPassed ? 'PASS' : 'BLOCK';
      detail = `policyPassed=${outcome.policyPassed}`;
    } else {
      actual = 'BLOCK';
      detail = 'assertion failed, ledger unchanged';
    }

    const ok = actual === c.expect;
    if (!ok) failures++;
    console.log(
      `  ${ok ? 'ok  ' : 'FAIL'}  ${c.name.padEnd(18)} expected ${c.expect}, got ${actual}  (${detail})`,
    );
  }

  console.log('');
  if (failures > 0) {
    console.error(`${failures} case(s) did not match expectations`);
    process.exit(1);
  }
  console.log('All CJGate policy cases behaved as expected.');
  process.exit(0);
}

main();
