/**
 * Fixture test for the CJGate + Gitleaks pipeline.
 *
 * Runs both bundled fixtures through the real path
 * (Gitleaks scan -> private `secretsFound` -> CJGate Compact policy):
 *
 *   fixtures/clean   -> PASS   (no secrets)
 *   fixtures/secret  -> BLOCK  (one deliberately fake credential)
 *
 * Prints only PASS/BLOCK outcomes. Never prints finding counts, secret
 * values, or file contents.
 *
 * Exit code 0 iff both fixtures behave as expected.
 */
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runGitleaksScan } from '../src/scanners/gitleaks.js';
import { evaluatePolicy } from '../src/policy.js';
import { createCJGatePrivateState } from '../src/witnesses.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

type FixtureCase = { name: string; dir: string; expect: 'PASS' | 'BLOCK' };

const cases: FixtureCase[] = [
  { name: 'clean fixture', dir: 'fixtures/clean', expect: 'PASS' },
  { name: 'synthetic secret fixture', dir: 'fixtures/secret', expect: 'BLOCK' },
];

function main(): void {
  console.log('\nCJGate Gitleaks fixture test\n');

  let failures = 0;

  for (const c of cases) {
    // Gitleaks -> count only.
    const { secretsFound } = runGitleaksScan(c.dir, { cwd: repoRoot });
    // Gitleaks-only stage: SAST kept private and fixed at zero.
    const privateState = createCJGatePrivateState(BigInt(secretsFound), 0n);
    const { outcome } = evaluatePolicy(privateState);

    const ok = outcome === c.expect;
    if (!ok) failures++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${c.name.padEnd(26)} expected ${c.expect}, got ${outcome}`);
  }

  console.log('');
  if (failures > 0) {
    console.error(`${failures} fixture case(s) did not match expectations`);
    process.exit(1);
  }
  console.log('Both CJGate Gitleaks fixtures behaved as expected.');
  process.exit(0);
}

main();
