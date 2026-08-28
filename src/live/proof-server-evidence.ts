/**
 * Safe proof-server activity evidence for the CJGate live flow.
 *
 * Reads the local devnet proof-server container's logs and extracts only
 * high-level request/timing lines — request routing and proof lifecycle
 * markers. It NEVER surfaces the DEBUG `Received request: <hex>` payload
 * lines (which carry the serialized proving data): those are dropped, and as
 * a belt-and-braces measure any long hex/base64 run in a kept line is masked.
 *
 * This is used only to demonstrate that the proof server was (PASS) or was
 * not (BLOCK) exercised — never to inspect witness data.
 */
import { spawnSync } from 'node:child_process';

/** Default proof-server container name from docker-compose.yml. */
export const PROOF_SERVER_CONTAINER = 'cjgate-proof-server';

/** Lines we are willing to echo as evidence — request routing + proof lifecycle. */
const SAFE_LINE_PATTERNS: readonly RegExp[] = [
  /\b(GET|POST|PUT|DELETE)\s+\/\S*\s+HTTP\/[\d.]+;?\s*took\s/i, // actix access log
  /Starting to process request for \/\S+/i,
  /proof created; verifying/i,
  /\bproof ok\b/i,
  /starting \d+ workers/i,
];

/** Mask any run of >=12 hex/base64-ish chars so a payload can never leak. */
function maskBlobs(line: string): string {
  return line.replace(/[0-9a-fA-F]{12,}/g, '<redacted>').replace(/[A-Za-z0-9+/=]{24,}/g, '<redacted>');
}

/** Strip ANSI colour codes the proof server emits. */
function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\[[0-9;]*m/g, '');
}

export type ProofServerSnapshot = {
  /** ISO timestamp used as the `--since` boundary for the next diff. */
  readonly sinceIso: string;
};

export type ProofServerActivity = {
  /** New `POST /prove` access-log lines since the snapshot. */
  readonly proveRequests: number;
  /** New `POST /check` access-log lines since the snapshot. */
  readonly checkRequests: number;
  /** New "proof ok" lifecycle lines since the snapshot. */
  readonly proofsVerified: number;
  /** Safe, redacted excerpt of the new activity (may be empty). */
  readonly safeExcerpt: string[];
  /** True when the container could not be read (docker missing, etc.). */
  readonly unavailable: boolean;
};

/** Take a time boundary to diff proof-server logs against later. */
export function snapshotProofServer(): ProofServerSnapshot {
  return { sinceIso: new Date().toISOString() };
}

/**
 * Return safe proof-server activity that occurred after `snap`.
 * Never throws — on any error it reports `unavailable: true`.
 */
export function proofServerActivitySince(
  snap: ProofServerSnapshot,
  container = PROOF_SERVER_CONTAINER,
): ProofServerActivity {
  let raw = '';
  try {
    const r = spawnSync(
      'docker',
      ['logs', '--since', snap.sinceIso, container],
      { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 32 * 1024 * 1024 },
    );
    if (r.error || (typeof r.status === 'number' && r.status !== 0)) {
      return { proveRequests: 0, checkRequests: 0, proofsVerified: 0, safeExcerpt: [], unavailable: true };
    }
    raw = `${r.stdout ?? ''}${r.stderr ?? ''}`; // proof server logs to stderr
  } catch {
    return { proveRequests: 0, checkRequests: 0, proofsVerified: 0, safeExcerpt: [], unavailable: true };
  }

  const lines = raw.split('\n').map(stripAnsi).map((l) => l.trim()).filter(Boolean);
  const safe = lines.filter((l) => SAFE_LINE_PATTERNS.some((p) => p.test(l))).map(maskBlobs);

  const proveRequests = safe.filter((l) => /POST\s+\/prove\b/i.test(l)).length;
  const checkRequests = safe.filter((l) => /POST\s+\/check\b/i.test(l)).length;
  const proofsVerified = safe.filter((l) => /\bproof ok\b/i.test(l)).length;

  return { proveRequests, checkRequests, proofsVerified, safeExcerpt: safe, unavailable: false };
}

/** Hit the proof server's health endpoint. Returns true iff it reports ok. */
export async function proofServerHealthy(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(4000) });
    if (!res.ok) return false;
    const body = (await res.json()) as { status?: string };
    return body?.status === 'ok';
  } catch {
    return false;
  }
}
