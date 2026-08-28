/**
 * Local verification for the CJGate security gate.
 *
 * Runs the compiled `runSecurityGate` circuit entirely in-process (via
 * `src/policy.ts`) — no wallet, no proof server, no devnet. It exercises
 * three cases with synthetic signal values:
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
import { evaluatePolicy } from '../src/policy.js';
import { createCJGatePrivateState, type CJGatePrivateState } from '../src/witnesses.js';

type Case = {
  name: string;
  privateState: CJGatePrivateState;
  expect: 'PASS' | 'BLOCK';
};

const cases: Case[] = [
  { name: 'clean input', privateState: createCJGatePrivateState(0n, 0n), expect: 'PASS' },
  { name: 'secret violation', privateState: createCJGatePrivateState(1n, 0n), expect: 'BLOCK' },
  { name: 'SAST violation', privateState: createCJGatePrivateState(0n, 1n), expect: 'BLOCK' },
];

function main(): void {
  console.log('\nCJGate local policy verification');
  console.log('contract: contracts/managed/cjgate  circuit: runSecurityGate\n');

  let failures = 0;

  for (const c of cases) {
    const result = evaluatePolicy(c.privateState);
    const detail =
      result.outcome === 'PASS'
        ? `policyPassed=${result.policyPassed}`
        : 'assertion failed, ledger unchanged';

    const ok = result.outcome === c.expect;
    if (!ok) failures++;
    console.log(
      `  ${ok ? 'ok  ' : 'FAIL'}  ${c.name.padEnd(18)} expected ${c.expect}, got ${result.outcome}  (${detail})`,
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
