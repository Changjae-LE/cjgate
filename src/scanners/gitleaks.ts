/**
 * Gitleaks secret-scanner integration for CJGate.
 *
 * Runs Gitleaks over a target directory, processes its JSON report locally,
 * and returns ONLY a finding count. Nothing sensitive crosses this boundary:
 *
 *   - secret values, matched strings, and file snippets are never returned,
 *     stored beyond the transient report, or logged;
 *   - the report is written to a gitignored temp dir and deleted right after
 *     it is counted;
 *   - Gitleaks is invoked with `--redact` so even its own diagnostics carry
 *     no secret material.
 *
 * The returned count becomes the private `secretsFound` signal fed into the
 * CJGate Compact policy.
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Directory (gitignored) for transient Gitleaks reports. */
export const GITLEAKS_TMP_DIR = '.cjgate/gitleaks';

export type GitleaksScanResult = {
  /** Absolute path that was scanned. Safe to log. */
  readonly source: string;
  /** Number of secret findings. Treated as private downstream. */
  readonly secretsFound: number;
};

export type GitleaksScanOptions = {
  /** Working directory the temp report dir is resolved against. Defaults to cwd. */
  readonly cwd?: string;
  /** Gitleaks binary name/path. Defaults to `gitleaks`. */
  readonly bin?: string;
};

/**
 * Scan `source` (a directory or file) for secrets with Gitleaks.
 *
 * Throws only on infrastructure failure (binary missing, scan crashed,
 * unreadable report) — never for the mere presence of findings.
 */
export function runGitleaksScan(
  source: string,
  options: GitleaksScanOptions = {},
): GitleaksScanResult {
  const cwd = options.cwd ?? process.cwd();
  const bin = options.bin ?? 'gitleaks';

  const absSource = path.resolve(cwd, source);
  if (!fs.existsSync(absSource)) {
    throw new Error(`Gitleaks: scan target does not exist: ${source}`);
  }

  const reportDir = path.resolve(cwd, GITLEAKS_TMP_DIR);
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(
    reportDir,
    `report-${process.pid}-${Date.now()}.json`,
  );

  try {
    const result = spawnSync(
      bin,
      [
        'dir',
        absSource,
        '--report-format', 'json',
        '--report-path', reportPath,
        '--redact',            // never surface secret material, even in logs
        '--no-banner',
        '--exit-code', '0',    // findings are not an error here; we count them
        '--log-level', 'error',
      ],
      {
        cwd,
        encoding: 'utf-8',
        // Capture output so it never reaches the terminal. It is not inspected.
        stdio: ['ignore', 'pipe', 'pipe'],
        maxBuffer: 64 * 1024 * 1024,
      },
    );

    if (result.error) {
      const code = (result.error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        throw new Error(
          `Gitleaks: '${bin}' not found on PATH. Install it from https://github.com/gitleaks/gitleaks`,
        );
      }
      throw new Error(`Gitleaks: failed to launch (${code ?? 'unknown error'})`);
    }
    if (typeof result.status === 'number' && result.status !== 0) {
      // With --exit-code 0, any non-zero status is a real scan failure.
      // Do not echo stderr wholesale (defensive); surface only the code.
      throw new Error(`Gitleaks: scan exited with status ${result.status}`);
    }

    const secretsFound = countFindings(reportPath);
    return { source: absSource, secretsFound };
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
 * Read the Gitleaks JSON report and return the number of findings. The report
 * contents (which include matched secrets) are never returned or logged.
 */
function countFindings(reportPath: string): number {
  if (!fs.existsSync(reportPath)) {
    // Gitleaks writes no report file when there is nothing to report.
    return 0;
  }
  const raw = fs.readFileSync(reportPath, 'utf-8').trim();
  if (raw === '') return 0;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Gitleaks: report was not valid JSON');
  }
  if (!Array.isArray(parsed)) {
    throw new Error('Gitleaks: unexpected report shape (expected a JSON array)');
  }
  return parsed.length;
}
