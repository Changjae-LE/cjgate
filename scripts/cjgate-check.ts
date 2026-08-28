/**
 * `npm run cjgate:check [-- --source <path>]`
 *
 * Runs the first real CJGate scanner stage:
 *
 *   1. Gitleaks scans the target directory (default: the repository root).
 *   2. The finding count becomes the private `secretsFound` signal.
 *   3. `sastHighFindings` is kept private and fixed at zero for this
 *      Gitleaks-only stage (Semgrep is not integrated yet).
 *   4. The CJGate Compact policy (`runSecurityGate`) is evaluated locally.
 *
 * Output is deliberately minimal. This script never prints secret values,
 * matched strings, file snippets, finding locations, or the numeric
 * `secretsFound` count — only high-level status lines.
 *
 * Exit code: 0 when the policy passes, 1 when it is blocked.
 */
import { runGitleaksScan } from '../src/scanners/gitleaks.js';
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
  console.log(`  scanner: gitleaks`);
  console.log(`  target:  ${source}`);
  console.log('');

  // ── Stage 1: Gitleaks ────────────────────────────────────────────────────
  let secretsFound: number;
  try {
    const scan = runGitleaksScan(source);
    secretsFound = scan.secretsFound; // private from here on — never printed
    console.log('Gitleaks scan completed');
  } catch (err) {
    console.error('Gitleaks scan failed to run:', err instanceof Error ? err.message : String(err));
    process.exit(2);
  }

  // ── Stage 2: SAST (not yet integrated) ───────────────────────────────────
  // Kept private and fixed at zero until Semgrep is wired up.
  const sastHighFindings = 0n;

  // ── Stage 3: CJGate Compact policy ──────────────────────────────────────
  const privateState = createCJGatePrivateState(BigInt(secretsFound), sastHighFindings);
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
