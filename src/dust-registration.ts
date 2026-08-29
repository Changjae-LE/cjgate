// Resilient DUST-generation registration for NIGHT UTXOs.
//
// Wraps the official wallet SDK pattern
// (`wallet.registerNightUtxosForDustGeneration(...)` → `finalizeRecipe` →
// `submitTransaction`) with bounded retry/backoff for transient RPC/WebSocket
// disconnects.
//
// The retry is IDEMPOTENT. A WebSocket may drop *after* the network accepted
// the registration transaction but *before* the client saw confirmation, so
// before every (re)submission this routine:
//   - re-syncs the wallet to a fresh `isSynced` state,
//   - returns early if the DUST balance is already > 0,
//   - re-queries which NIGHT UTXOs are still unregistered on-chain,
//   - submits nothing if none remain,
//   - treats an "already registered" rejection as success.
//
// Only connection-shaped errors are retried; a chain/validity rejection fails
// immediately. After a successful (or already-present) registration it waits,
// bounded, for the DUST balance to become positive before returning.
//
// Nothing sensitive is logged: only UTXO counts, attempt numbers, and
// sanitized (hex-stripped, length-capped) error text.

import * as Rx from 'rxjs';

import type { NetworkId } from './network';
import { persistWalletState, unshieldedToken, type WalletContext } from './wallet';

export interface EnsureDustRegisteredOptions {
  readonly walletCtx: WalletContext;
  readonly network: NetworkId;
  /** Line logger. Defaults to `console.log`. */
  readonly log?: (msg: string) => void;
  /** Max submission attempts. Default 4. */
  readonly maxAttempts?: number;
  /** Delay (ms) *before* attempt N (index 0 = attempt 1). Default [0, 5s, 15s, 30s]. */
  readonly attemptDelaysMs?: readonly number[];
  /** Bounded wait for the wallet to reach `isSynced` before each check. Default 120s. */
  readonly resyncTimeoutMs?: number;
  /** Bounded wait for DUST balance > 0 after registration. Default env MIDNIGHT_DUST_TIMEOUT_MS or 10 min. */
  readonly dustWaitTimeoutMs?: number;
}

const DEFAULT_ATTEMPT_DELAYS_MS = [0, 5_000, 15_000, 30_000] as const;

// effect (`Effect.runPromise`) rejects with a `FiberFailure` whose `.message`
// is only the *head* error's message and which has NO own `.cause` property —
// the real cause graph is on this symbol.
const EFFECT_FIBER_FAILURE_CAUSE = Symbol.for('effect/Runtime/FiberFailure/Cause');

const COLLECT_MAX_NODES = 80;
const COLLECT_MAX_DEPTH = 14;
const COLLECT_MAX_TEXT = 16_000;
const COLLECT_MAX_PER_NODE = 4_000;

/** Object properties we will follow to reach a nested cause. Nothing else is read. */
const CAUSE_LINK_KEYS: readonly string[] = [
  'cause',
  'error',
  'defect',
  'value',
  'left',
  'right',
  'failure',
  'current',
  'parent',
  'originalError',
  'innerError',
];
const CAUSE_LINK_ARRAY_KEYS: readonly string[] = ['errors', 'failures', 'causes'];
/** Named text fields harvested from every node. */
const TEXT_FIELDS: readonly string[] = [
  'message',
  'name',
  '_tag',
  'code',
  'reason',
  'description',
  'shortMessage',
  'detail',
  'statusText',
];

/**
 * Deeply harvest every human-readable string from a thrown error and its whole
 * cause graph — standard `cause`, effect `FiberFailure` / `Cause` nodes, plus
 * `toString()` and `stack` renderings (effect's `FiberFailure.toString()` is
 * `Cause.pretty(cause, { renderErrorCause: true })`, which is the only place
 * the nested WebSocket-disconnect message appears).
 *
 * Only the fixed link keys above are followed — arbitrary object properties are
 * never read, so serialized transactions / key material cannot be pulled in.
 */
function collectErrorText(root: unknown): string {
  const out: string[] = [];
  const seen = new Set<unknown>();
  const queue: Array<{ node: unknown; depth: number }> = [{ node: root, depth: 0 }];
  let nodeBudget = COLLECT_MAX_NODES;
  let total = 0;

  const push = (s: unknown): void => {
    if (typeof s !== 'string') return;
    const t = s.trim();
    if (!t || t === '[object Object]' || t === '[object Error]') return;
    const clipped = t.length > COLLECT_MAX_PER_NODE ? t.slice(0, COLLECT_MAX_PER_NODE) : t;
    out.push(clipped);
    total += clipped.length;
  };

  while (queue.length > 0 && nodeBudget-- > 0 && total < COLLECT_MAX_TEXT) {
    const { node, depth } = queue.shift() as { node: unknown; depth: number };
    if (node == null || depth > COLLECT_MAX_DEPTH) continue;

    if (typeof node === 'string' || typeof node === 'number' || typeof node === 'boolean') {
      push(String(node));
      continue;
    }
    if (typeof node !== 'object' || seen.has(node)) continue;
    seen.add(node);

    const o = node as Record<PropertyKey, unknown>;

    for (const k of TEXT_FIELDS) {
      const v = o[k];
      if (typeof v === 'string' || typeof v === 'number') push(String(v));
    }
    // Rendered forms: effect FiberFailure.toString() / node's Error formatting
    // expose the nested cause here.
    try {
      push(String(o));
    } catch {
      /* ignore a throwing toString */
    }
    if (typeof o.stack === 'string') push(o.stack);

    // effect FiberFailure keeps the real Cause on a symbol prop.
    const fiberCause = (o as Record<symbol, unknown>)[EFFECT_FIBER_FAILURE_CAUSE];
    if (fiberCause != null) queue.push({ node: fiberCause, depth: depth + 1 });

    for (const k of CAUSE_LINK_KEYS) {
      if (k in o && o[k] != null) queue.push({ node: o[k], depth: depth + 1 });
    }
    for (const k of CAUSE_LINK_ARRAY_KEYS) {
      const arr = o[k];
      if (Array.isArray(arr)) for (const item of arr.slice(0, 8)) queue.push({ node: item, depth: depth + 1 });
    }
  }

  return out.join(' | ');
}

/** Strip key/tx-shaped blobs and cap length so no sensitive material is printed. */
function sanitize(text: string, max = 320): string {
  const cleaned = text
    .replace(/[0-9a-fA-F]{32,}/g, '<redacted>')
    .replace(/[A-Za-z0-9_\-+/=]{48,}/g, '<redacted>')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}

// ── error classification ─────────────────────────────────────────────────────

/** RPC / WebSocket connectivity failures — retryable wherever they appear in the graph. */
const RPC_CONNECTIVITY_PATTERNS: readonly RegExp[] = [
  /disconnected from/i,
  /wss?:\/\//i, // a websocket/ws URL in the text — practically always a disconnect notice
  /normal closure/i,
  /\b1000\b\s*::?\s*normal closure/i, // "1000:: Normal Closure"
  /websocket|\bws (closed|disconnect|error|failure)\b/i,
  /socket (hang ?up|closed|error)/i,
  /\b(ECONNRESET|ECONNREFUSED|ETIMEDOUT|EPIPE|ENETUNREACH|ENETDOWN|EHOSTUNREACH|EAI_AGAIN|ECONNABORTED|UND_ERR_SOCKET|UND_ERR_CONNECT_TIMEOUT|UND_ERR_HEADERS_TIMEOUT)\b/,
  /connection (closed|reset|lost|refused|terminated|aborted|dropped|error|failure)/i,
  /connection to .* (was )?(closed|lost|dropped)/i,
  /(rpc|node|relay|indexer|provider|endpoint|server)[^.|]{0,48}(disconnect|closed|unavailable|unreachable|timeout|reset|dropped)/i,
  /network (error|failure|timeout|unreachable|down)/i,
  /(request|response|read|write|handshake|connect) time(d)? ?out/i,
  /stream (closed|ended|terminated) (unexpectedly|early)/i,
  /premature close/i,
];

/** Markers that the failure is a transaction *submission* failure (any layer). */
const SUBMISSION_ERROR_PATTERNS: readonly RegExp[] = [
  /\bSubmissionError\b/,
  /transaction submission (error|failed|failure)/i,
  /failed to (submit|send) transaction/i,
];

/** Deterministic chain / validity / signing failures — never retried. */
const PERMANENT_PATTERNS: readonly RegExp[] = [
  /custom error/i,
  /invalid ?transaction/i,
  /\b1010\b/, // substrate: Invalid Transaction
  /bad ?proof|proof (verification )?failed/i,
  /\b(stale|future)\b/i,
  /\bnonce\b/i,
  /inputssignatureslengthmismatch/i,
  /signature (verification )?(failed|invalid|mismatch)|invalid signature|bad signature/i,
  /insufficient (funds|balance)|balance too low|not enough (funds|balance|night|dust)/i,
  /module ?error|dispatch ?error/i,
  /\bpayment\b/i,
  /already (been )?(registered|in the pool|imported)/i,
  /malformed|deserializ|decode (error|failed)|failed to parse|parse error/i,
  /exceeds .*(limit|maximum)|too large|size limit exceeded/i,
  /unknown transaction|transaction is outdated/i,
];

const ALREADY_REGISTERED_PATTERNS: readonly RegExp[] = [
  /already (been )?registered/i,
  /utxo[^.|]*registered/i,
  /duplicate registration/i,
  /registration already (exists|present)/i,
];

function isAlreadyRegistered(err: unknown): boolean {
  const text = collectErrorText(err);
  return ALREADY_REGISTERED_PATTERNS.some((re) => re.test(text));
}

/**
 * Classify the ORIGINAL error object (before any sanitising) by scanning its
 * full, deeply-collected cause-graph text.
 *
 *   1. A deterministic chain/validity/signing marker anywhere → permanent.
 *   2. Otherwise, a direct RPC/WebSocket connectivity marker anywhere → transient.
 *   3. Otherwise, a submission-failure marker + any connectivity phrasing → transient.
 *   4. Otherwise (incl. a bare `SubmissionError` with no connectivity text) → permanent.
 */
function classifyError(err: unknown): 'transient' | 'permanent' {
  const text = collectErrorText(err);

  if (PERMANENT_PATTERNS.some((re) => re.test(text))) return 'permanent';

  if (RPC_CONNECTIVITY_PATTERNS.some((re) => re.test(text))) return 'transient';

  const looksLikeSubmission = SUBMISSION_ERROR_PATTERNS.some((re) => re.test(text));
  const hasConnectivityPhrase =
    /\b(connect|disconnect|reconnect|socket|closure|closed|reset|timeout|timed out|unreachable|offline|network|ws|wss|rpc)\b/i.test(
      text,
    );
  if (looksLikeSubmission && hasConnectivityPhrase) return 'transient';

  return 'permanent';
}

function dustBalanceOf(state: any): bigint {
  try {
    const b = state?.dust?.balance?.(new Date());
    return typeof b === 'bigint' ? b : 0n;
  } catch {
    return 0n;
  }
}

function unregisteredNightUtxos(state: any): any[] {
  const coins = state?.unshielded?.availableCoins ?? [];
  return coins.filter((c: any) => !c?.meta?.registeredForDustGeneration);
}

/**
 * Ensure the wallet's NIGHT UTXOs are registered for DUST generation and that
 * DUST has started to accrue. Safe to call repeatedly. Throws a sanitized
 * error on permanent failure or once bounded retries are exhausted.
 */
export async function ensureDustRegistered(opts: EnsureDustRegisteredOptions): Promise<void> {
  const { walletCtx, network } = opts;
  const wallet = walletCtx.wallet;
  const log = opts.log ?? ((m: string) => console.log(m));
  const maxAttempts = Math.max(1, opts.maxAttempts ?? 4);
  const delays = opts.attemptDelaysMs ?? DEFAULT_ATTEMPT_DELAYS_MS;
  const resyncTimeoutMs = opts.resyncTimeoutMs ?? 120_000;
  const envDust = Number(process.env.MIDNIGHT_DUST_TIMEOUT_MS);
  const dustWaitTimeoutMs =
    opts.dustWaitTimeoutMs ?? (Number.isFinite(envDust) && envDust > 0 ? envDust : 10 * 60_000);

  const freshSyncedState = (): Promise<any> =>
    Rx.firstValueFrom(
      wallet.state().pipe(
        Rx.filter((s: any) => s.isSynced),
        Rx.timeout({ first: resyncTimeoutMs }),
      ),
    );

  let done = false;

  for (let attempt = 1; attempt <= maxAttempts && !done; attempt++) {
    if (attempt > 1) {
      const d = delays[Math.min(attempt - 1, delays.length - 1)] ?? 0;
      if (d > 0) {
        log(`  Backing off ${Math.round(d / 1000)}s before retry ${attempt}/${maxAttempts}...`);
        await new Promise((r) => setTimeout(r, d));
      }
    }

    // ── idempotency: re-sync and inspect the current on-chain state ──────────
    let state: any;
    try {
      state = await freshSyncedState();
    } catch (e) {
      if (attempt === maxAttempts) {
        throw new Error(
          `DUST registration: wallet did not re-sync within ${Math.round(resyncTimeoutMs / 1000)}s ` +
            `(${sanitize(collectErrorText(e))}). The persisted wallet state under ` +
            `.midnight-wallet-state/${network}/ is intact — re-run the deploy command to resume.`,
        );
      }
      log('  Wallet re-sync timed out; will retry.');
      continue;
    }
    await persistWalletState(network, walletCtx).catch(() => {});

    if (dustBalanceOf(state) > 0n) {
      log('  DUST balance is already > 0 — registration not needed.');
      done = true;
      break;
    }

    const unregistered = unregisteredNightUtxos(state);
    if (unregistered.length === 0) {
      log('  All NIGHT UTXOs are already registered for DUST generation — nothing to submit.');
      done = true;
      break;
    }

    // ── submit the registration (official SDK pattern) ──────────────────────
    log(`  Registering ${unregistered.length} NIGHT UTXO(s) for DUST generation (attempt ${attempt}/${maxAttempts})...`);
    try {
      // The signDustRegistration callback (3rd arg) already produces a recipe
      // with N signatures matching N inputs. Do NOT call signRecipe again — that
      // would double-sign and the chain rejects with InputsSignaturesLengthMismatch
      // (Custom error 192). Matches upstream example-counter and example-bboard.
      const recipe = await wallet.registerNightUtxosForDustGeneration(
        unregistered,
        walletCtx.unshieldedKeystore.getPublicKey(),
        (payload: Uint8Array) => walletCtx.unshieldedKeystore.signData(payload),
      );
      const finalized = await wallet.finalizeRecipe(recipe);
      await wallet.submitTransaction(finalized);
      log('  DUST registration transaction submitted and finalized.');
      await persistWalletState(network, walletCtx).catch(() => {});
      done = true;
      break;
    } catch (err) {
      await persistWalletState(network, walletCtx).catch(() => {});

      if (isAlreadyRegistered(err)) {
        log('  Network reports the NIGHT UTXO is already registered (a prior attempt landed) — continuing.');
        done = true;
        break;
      }

      const safe = sanitize(collectErrorText(err));
      if (classifyError(err) === 'permanent') {
        throw new Error(`DUST registration failed and will not be retried (permanent error): ${safe}`);
      }
      if (attempt === maxAttempts) {
        throw new Error(
          `DUST registration still failing after ${maxAttempts} attempts. ` +
            `Last (transient) error: ${safe}. No duplicate transaction was submitted; ` +
            `the persisted wallet state under .midnight-wallet-state/${network}/ is intact. ` +
            `Re-run the deploy command — it will re-check on-chain registration and resume.`,
        );
      }
      log(`  Transient submission error (attempt ${attempt}/${maxAttempts}): ${safe}`);
      log('  Will re-sync, re-check registration state, then retry.');
    }
  }

  if (!done) {
    throw new Error('DUST registration did not complete (unexpected — no error was raised).');
  }

  // ── after registration: wait (bounded) for DUST to accrue, then return ────
  log('  Waiting for the DUST balance to become > 0...');
  try {
    await Rx.firstValueFrom(
      wallet.state().pipe(
        Rx.throttleTime(5_000),
        Rx.filter((s: any) => s.isSynced),
        Rx.filter((s: any) => dustBalanceOf(s) > 0n),
        Rx.timeout({ first: dustWaitTimeoutMs }),
      ),
    );
  } catch (e) {
    throw new Error(
      `The DUST registration is on-chain, but the DUST balance did not become positive within ` +
        `${Math.round(dustWaitTimeoutMs / 60_000)} min (${sanitize(collectErrorText(e))}). ` +
        `Re-run the deploy command — it will skip registration and just wait for DUST ` +
        `(raise the wait with MIDNIGHT_DUST_TIMEOUT_MS).`,
    );
  }
  await persistWalletState(network, walletCtx).catch(() => {});
  log('  DUST tokens ready.');
}
