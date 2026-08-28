/**
 * Semgrep static-analysis (SAST) integration for CJGate.
 *
 * Runs Semgrep over a target directory, processes its JSON report locally,
 * and returns ONLY a count: the number of findings that meet CJGate's
 * blocking SAST severity policy. Nothing sensitive crosses this boundary:
 *
 *   - vulnerable source, matched snippets, rule messages, and file paths of
 *     findings are never returned, logged, or kept beyond the transient report;
 *   - the report is written to a gitignored temp dir and deleted right after
 *     it is counted;
 *   - Semgrep runs with metrics disabled — no finding data leaves the machine.
 *
 * The returned count becomes the private `sastHighFindings` signal fed into
 * the CJGate Compact policy.
 *
 * Runner: a native `semgrep` on PATH is used if present; otherwise the
 * `semgrep/semgrep` Docker image. Override the image tag with
 * `CJGATE_SEMGREP_IMAGE`, the ruleset with `CJGATE_SEMGREP_CONFIG`.
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Directory (gitignored) for transient Semgrep reports. */
export const SEMGREP_TMP_DIR = '.cjgate/semgrep';

/** Default Docker image when no native `semgrep` binary is available. */
const DEFAULT_IMAGE = 'semgrep/semgrep:latest';

/**
 * CJGate blocking SAST severity policy.
 *
 * A finding blocks if its Semgrep severity is ERROR (classic 3-level scale) or
 * HIGH / CRITICAL (the newer scale that some rules report via metadata).
 * WARNING / INFO / MEDIUM / LOW findings are recorded by Semgrep but do not
 * count toward `sastHighFindings` at this stage.
 */
export const BLOCKING_SEVERITIES: ReadonlySet<string> = new Set([
  'ERROR',
  'HIGH',
  'CRITICAL',
]);

/** Paths excluded from a scan (noise / generated / other fixtures). */
export const DEFAULT_EXCLUDES: readonly string[] = [
  'node_modules',
  '.git',
  'dist',
  'contracts/managed',
  '.cjgate',
  '.midnight-wallet-state',
  'midnight-level-db',
  'fixtures/sast',
  'fixtures/secret',
];

export type SemgrepScanResult = {
  /** Absolute path that was scanned. Safe to log. */
  readonly source: string;
  /** Findings meeting the blocking severity policy. Treated as private downstream. */
  readonly sastHighFindings: number;
};

export type SemgrepScanOptions = {
  /** Working directory temp/config paths resolve against. Defaults to cwd. */
  readonly cwd?: string;
  /** Ruleset ref: a file path, or a registry ref like `p/default` / `auto`. */
  readonly config?: string;
  /** Path globs to exclude. Defaults to {@link DEFAULT_EXCLUDES}. */
  readonly exclude?: readonly string[];
};

type Runner =
  | { kind: 'native'; bin: string }
  | { kind: 'docker'; bin: string; image: string };

function detectRunner(cwd: string): Runner {
  const native = spawnSync('semgrep', ['--version'], { cwd, stdio: 'ignore' });
  if (!native.error && native.status === 0) return { kind: 'native', bin: 'semgrep' };

  const docker = spawnSync('docker', ['--version'], { cwd, stdio: 'ignore' });
  if (!docker.error && docker.status === 0) {
    return {
      kind: 'docker',
      bin: 'docker',
      image: process.env.CJGATE_SEMGREP_IMAGE?.trim() || DEFAULT_IMAGE,
    };
  }

  throw new Error(
    'Semgrep: no runner available. Install `semgrep` (https://semgrep.dev) or Docker.',
  );
}

/**
 * Scan `source` (a directory or file) with Semgrep and return the number of
 * findings that meet CJGate's blocking SAST severity policy.
 *
 * Throws only on infrastructure failure (no runner, scan crashed, unreadable
 * report) — never for the mere presence of findings.
 */
export function runSemgrepScan(
  source: string,
  options: SemgrepScanOptions = {},
): SemgrepScanResult {
  const cwd = options.cwd ?? process.cwd();
  const absSource = path.resolve(cwd, source);
  if (!fs.existsSync(absSource)) {
    throw new Error(`Semgrep: scan target does not exist: ${source}`);
  }

  const configRef =
    options.config ?? process.env.CJGATE_SEMGREP_CONFIG?.trim() ?? path.resolve(cwd, '.semgrep.yml');
  const excludes = options.exclude ?? DEFAULT_EXCLUDES;

  const reportDir = path.resolve(cwd, SEMGREP_TMP_DIR);
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `report-${process.pid}-${Date.now()}.json`);

  const runner = detectRunner(cwd);

  // Semgrep flags shared by both runners. `--json` goes to stdout; we persist
  // that to the temp report file ourselves so it is always user-owned.
  const semgrepArgs = (target: string, config: string): string[] => {
    const a = [
      'scan',
      '--config', config,
      '--json',
      '--quiet',
      '--metrics', 'off',
      '--disable-version-check',
    ];
    for (const ex of excludes) a.push('--exclude', ex);
    a.push(target);
    return a;
  };

  let argv: string[];
  if (runner.kind === 'native') {
    argv = semgrepArgs(absSource, configRef);
  } else {
    const isPathConfig = configRef.includes('/') || configRef.includes('\\') || configRef.endsWith('.yml') || configRef.endsWith('.yaml');
    const mounts = ['-v', `${absSource}:/src:ro`];
    let containerConfig = configRef;
    if (isPathConfig) {
      const absConfig = path.resolve(cwd, configRef);
      if (!fs.existsSync(absConfig)) {
        throw new Error(`Semgrep: ruleset not found: ${configRef}`);
      }
      mounts.push('-v', `${absConfig}:/cjgate-semgrep-rules.yml:ro`);
      containerConfig = '/cjgate-semgrep-rules.yml';
    }
    argv = [
      'run', '--rm',
      ...mounts,
      '-e', 'SEMGREP_SEND_METRICS=off',
      runner.image,
      'semgrep',
      ...semgrepArgs('/src', containerConfig),
    ];
  }

  try {
    const result = spawnSync(runner.bin, argv, {
      cwd,
      encoding: 'utf-8',
      // Capture output so it never reaches the terminal. stderr is not inspected.
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 256 * 1024 * 1024,
    });

    if (result.error) {
      const code = (result.error as NodeJS.ErrnoException).code;
      throw new Error(`Semgrep: failed to launch ${runner.bin} (${code ?? 'unknown error'})`);
    }
    // Semgrep `scan` exits 0 (no findings) or 1 (findings present). Anything
    // else is a real failure. Do not echo stderr wholesale (defensive).
    if (result.status !== 0 && result.status !== 1) {
      throw new Error(`Semgrep: scan exited with status ${result.status ?? 'null'}`);
    }

    fs.writeFileSync(reportPath, result.stdout ?? '', { mode: 0o600 });
    return { source: absSource, sastHighFindings: countBlockingFindings(reportPath) };
  } finally {
    // Delete the transient report; prune the working dirs if now empty.
    fs.rmSync(reportPath, { force: true });
    for (const dir of [reportDir, path.dirname(reportDir)]) {
      try {
        if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
      } catch {
        /* not empty or already gone — fine */
      }
    }
  }
}

/**
 * Read the Semgrep JSON report and count findings that meet the blocking
 * severity policy. The report contents (which include vulnerable code
 * snippets and rule messages) are never returned or logged.
 */
function countBlockingFindings(reportPath: string): number {
  const raw = fs.existsSync(reportPath) ? fs.readFileSync(reportPath, 'utf-8').trim() : '';
  if (raw === '') throw new Error('Semgrep: produced no JSON output');

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Semgrep: report was not valid JSON');
  }

  const results = (parsed as { results?: unknown }).results;
  if (!Array.isArray(results)) {
    throw new Error('Semgrep: unexpected report shape (missing results array)');
  }

  let blocking = 0;
  for (const r of results as Array<Record<string, any>>) {
    const extra = (r?.extra ?? {}) as Record<string, any>;
    const sev = String(extra.severity ?? '').toUpperCase();
    const metaSev = String(extra.metadata?.severity ?? '').toUpperCase();
    if (BLOCKING_SEVERITIES.has(sev) || BLOCKING_SEVERITIES.has(metaSev)) blocking++;
  }
  return blocking;
}
