/**
 * `npm run cjgate:check [-- --source <path>]`
 *
 * Runs both real CJGate scanner stages over the target directory
 * (default: the repository root):
 *
 *   1. Gitleaks  -> finding count           -> private `secretsFound`
 *   2. Semgrep   -> blocking-severity count -> private `sastHighFindings`
 *   3. Both private values feed the CJGate Compact policy (`runSecurityGate`),
 *      evaluated locally.
 *
 * Output is deliberately minimal. This script never prints vulnerable source,
 * matched snippets, rule messages, file contents, finding locations, finding
 * counts, or the numeric `secretsFound` / `sastHighFindings` values — only
 * high-level status lines.
 *
 * Exit codes: 0 = policy passed, 1 = policy blocked, 2 = a scanner failed to run.
 */
import { runGitleaksScan } from '../src/scanners/gitleaks.js';
import { runSemgrepScan } from '../src/scanners/semgrep.js';
import { evaluatePolicy } from '../src/policy.js';
import { createCJGatePrivateState } from '../src/witnesses.js';

function parseSource(argv: string[]): string {
  const args = argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--source' || a === '-s') {
      const v = args[i + 1];
      if (!v) {
        console.error('cjgate:check: --source requires a path argument');
        process.exit(2);
      }
      return v;
    }
    if (a.startsWith('--source=')) return a.slice('--source='.length);
  }
  return '.';
}

function main(): void {
  const source = parseSource(process.argv);

  console.log('CJGate security check');
  console.log('  scanners: gitleaks, semgrep');
  console.log(`  target:   ${source}`);
  console.log('');

  // ── Stage 1: Gitleaks -> secretsFound (private) ─────────────────────────
  let secretsFound: number;
  try {
    secretsFound = runGitleaksScan(source).secretsFound; // private — never printed
    console.log('Gitleaks scan completed');
  } catch (err) {
    console.error('Gitleaks scan failed to run:', err instanceof Error ? err.message : String(err));
    process.exit(2);
  }

  // ── Stage 2: Semgrep -> sastHighFindings (private) ──────────────────────
  let sastHighFindings: number;
  try {
    sastHighFindings = runSemgrepScan(source).sastHighFindings; // private — never printed
    console.log('Semgrep scan completed');
  } catch (err) {
    console.error('Semgrep scan failed to run:', err instanceof Error ? err.message : String(err));
    process.exit(2);
  }

  // ── Stage 3: CJGate Compact policy ─────────────────────────────────────
  const privateState = createCJGatePrivateState(
    BigInt(secretsFound),
    BigInt(sastHighFindings),
  );
  const result = evaluatePolicy(privateState);

  console.log('');
  if (result.outcome === 'PASS') {
    console.log('Security policy passed');
    process.exit(0);
  } else {
    console.log('Security policy blocked');
    process.exit(1);
  }
}

main();
