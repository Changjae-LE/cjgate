/**
 * Fixture test for the full CJGate pipeline (Gitleaks + Semgrep).
 *
 * Runs each bundled fixture through the real path
 * (Gitleaks -> private `secretsFound`, Semgrep -> private `sastHighFindings`,
 * both -> CJGate Compact policy):
 *
 *   fixtures/clean   -> PASS   (no secrets, no SAST findings)
 *   fixtures/secret  -> BLOCK  (one deliberately fake credential)
 *   fixtures/sast    -> BLOCK  (one intentionally vulnerable demo file)
 *
 * Prints only PASS/BLOCK outcomes. Never prints finding counts, secret
 * values, vulnerable source, or file contents.
 *
 * Exit code 0 iff all fixtures behave as expected.
 */
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runGitleaksScan } from '../src/scanners/gitleaks.js';
import { runSemgrepScan } from '../src/scanners/semgrep.js';
import { evaluatePolicy } from '../src/policy.js';
import { createCJGatePrivateState } from '../src/witnesses.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

type FixtureCase = { name: string; dir: string; expect: 'PASS' | 'BLOCK' };

const cases: FixtureCase[] = [
  { name: 'clean fixture', dir: 'fixtures/clean', expect: 'PASS' },
  { name: 'synthetic secret fixture', dir: 'fixtures/secret', expect: 'BLOCK' },
  { name: 'synthetic SAST fixture', dir: 'fixtures/sast', expect: 'BLOCK' },
];

function main(): void {
  console.log('\nCJGate scanner fixture test (gitleaks + semgrep)\n');

  let failures = 0;

  for (const c of cases) {
    // Gitleaks -> count only.
    const { secretsFound } = runGitleaksScan(c.dir, { cwd: repoRoot });
    // Semgrep -> blocking-severity count only. exclude: [] so a fixture dir
    // targeted directly is never skipped by the default exclude list.
    const { sastHighFindings } = runSemgrepScan(c.dir, { cwd: repoRoot, exclude: [] });

    const privateState = createCJGatePrivateState(
      BigInt(secretsFound),
      BigInt(sastHighFindings),
    );
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
  console.log('All CJGate scanner fixtures behaved as expected.');
  process.exit(0);
}

main();
