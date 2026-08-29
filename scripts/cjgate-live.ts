/**
 * `npm run cjgate:live [-- --network <id>] [--source <path>] [--redeploy]`
 *
 * The REAL Midnight zero-knowledge proof flow for CJGate. Defaults to the
 * local devnet (`undeployed`); `--network preprod` runs it against Midnight
 * Preprod (normally invoked via `npm run cjgate:preprod:live`). Distinct from
 * `npm run cjgate:check` (which evaluates the Compact policy in-process with no
 * proof server, no wallet, no chain — that is the CI path and is left
 * untouched).
 *
 * Local devnet: a missing/stale deployment is auto-deployed. Public networks
 * (preprod): the wallet and contract must already exist — this script never
 * creates a wallet, never requests faucet funds, and never auto-deploys.
 *
 * What this does:
 *   1. Runs the REAL scanners over the source path:
 *        Gitleaks -> private secretsFound
 *        Semgrep  -> private sastHighFindings
 *      Both results stay private: they are staged into the contract's private
 *      state for the witnesses and are NEVER printed or logged.
 *   2. Ensures a fresh CJGate contract is deployed to the local devnet
 *      (redeploys if the recorded deployment is missing, stale, or for a
 *      different contract; `--redeploy` forces it).
 *   3. Connects the deployed contract, invokes `runSecurityGate` through the
 *      Midnight proof server, and — for a clean policy result — submits a real
 *      transaction to the devnet and confirms `policyPassed` becomes true.
 *   4. For a policy violation the in-circuit assertion rejects the transition:
 *      no proof is requested, no transaction is submitted, ledger is unchanged.
 *
 * Safe to print: contract address, transaction id, block height, public
 * `policyPassed`, and high-level proof-server request/timing counts.
 * Never printed: scanner findings, snippets, secret contents, finding counts,
 * secretsFound, sastHighFindings, wallet seed/mnemonic, keys, witness values.
 *
 * Exit codes: 0 = live PASS (tx submitted), 1 = live BLOCK (no tx), 2 = setup
 * / infrastructure failure.
 */
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { WebSocket } from 'ws';

import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { CompiledContract } from '@midnight-ntwrk/midnight-js-protocol/compact-js';

import { resolveNetwork, getOrCreateWallet, getDeployment, loadState, type NetworkId } from '../src/network.js';
import { createWallet, persistWalletState, unshieldedToken, type WalletContext } from '../src/wallet.js';
import { witnesses, createCJGatePrivateState, cleanCJGatePrivateState } from '../src/witnesses.js';
import { runGitleaksScan } from '../src/scanners/gitleaks.js';
import { runSemgrepScan } from '../src/scanners/semgrep.js';
import {
  snapshotProofServer,
  proofServerActivitySince,
  proofServerHealthy,
} from '../src/live/proof-server-evidence.js';

// @ts-expect-error wallet sync + indexer WS need a global WebSocket
globalThis.WebSocket = WebSocket;

const PRIVATE_STATE_ID = 'cjgatePrivateState';
const PRIVATE_STATE_STORE = 'cjgate-state';
const CONTRACT_NAME = 'cjgate';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const zkConfigPath = path.join(repoRoot, 'contracts', 'managed', 'cjgate');
const contractPath = path.join(zkConfigPath, 'contract', 'index.js');

// ── args ──────────────────────────────────────────────────────────────────────
function parseArgs(argv: string[]): { source: string; redeploy: boolean } {
  const args = argv.slice(2);
  let source = '.';
  let redeploy = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--redeploy') redeploy = true;
    else if (a === '--source' || a === '-s') {
      const v = args[i + 1];
      if (!v) fail('--source requires a path argument');
      source = v;
      i++;
    } else if (a.startsWith('--source=')) source = a.slice('--source='.length);
  }
  return { source, redeploy };
}

function fail(msg: string): never {
  console.error(`cjgate:live: ${msg}`);
  process.exit(2);
}

// ── compiled contract binding ─────────────────────────────────────────────────
if (!fs.existsSync(contractPath)) fail('contract not compiled — run: npm run compile');
const CJGate = await import(pathToFileURL(contractPath).href);
const compiledContract: any = (CompiledContract.make(CONTRACT_NAME, CJGate.Contract) as any).pipe(
  (CompiledContract.withWitnesses as any)(witnesses),
  (CompiledContract.withCompiledFileAssets as any)(zkConfigPath),
);

// ── deployment freshness ─────────────────────────────────────────────────────
async function ensureFreshDeployment(
  network: NetworkId,
  networkConfig: { indexer: string; indexerWS: string },
  redeploy: boolean,
): Promise<string> {
  const existing = getDeployment(network);

  // Public networks: never auto-deploy or auto-fund. The contract must already
  // be on record (put there by `npm run cjgate:preprod:deploy`).
  if (network !== 'undeployed') {
    if (!existing) {
      fail(`no CJGate contract recorded for ${network} — run: npm run cjgate:${network}:deploy`);
    }
    if (existing.contract !== CONTRACT_NAME) {
      fail(
        `recorded ${network} deployment is for "${existing.contract ?? 'unknown'}", not "${CONTRACT_NAME}" — redeploy with: npm run cjgate:${network}:deploy`,
      );
    }
    console.log(`Using the CJGate contract recorded for ${network}.`);
    return existing.address;
  }

  // Local devnet: auto-deploy when missing / stale / for another contract.
  let reason: string | null = null;
  if (redeploy) reason = '--redeploy requested';
  else if (!existing) reason = 'no deployment on file';
  else if (existing.contract !== CONTRACT_NAME)
    reason = `recorded deployment is for "${existing.contract ?? 'unknown'}", not "${CONTRACT_NAME}"`;
  else {
    // A recorded CJGate address — verify it is actually indexed on this devnet.
    try {
      const probe = indexerPublicDataProvider(networkConfig.indexer, networkConfig.indexerWS);
      const state = await probe.queryContractState(existing.address);
      if (!state) reason = 'recorded contract address is not present on this devnet';
    } catch {
      reason = 'recorded contract address could not be verified on this devnet';
    }
  }

  if (reason) {
    console.log(`Deploying a fresh CJGate contract (${reason})...`);
    execFileSync('npm', ['run', 'deploy'], { cwd: repoRoot, stdio: 'inherit' });
    const after = getDeployment('undeployed');
    if (!after?.address) fail('deploy completed but no address was recorded in .midnight-state.json');
    return after.address;
  }

  console.log('Reusing the CJGate contract already deployed to the local devnet.');
  return existing!.address;
}

// ── providers (with proof-server / submit call counters for evidence) ─────────
function makeProviders(walletCtx: WalletContext, networkConfig: any) {
  const privateStatePassword =
    process.env.PRIVATE_STATE_PASSWORD?.trim() || 'Local-Devnet-Development-Placeholder-1';

  const counters = { proveTx: 0, submitTx: 0 };

  const walletProvider = {
    getCoinPublicKey: () => walletCtx.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => walletCtx.shieldedSecretKeys.encryptionPublicKey,
    async balanceTx(tx: any, ttl?: Date) {
      const recipe = await walletCtx.wallet.balanceUnboundTransaction(
        tx,
        { shieldedSecretKeys: walletCtx.shieldedSecretKeys, dustSecretKey: walletCtx.dustSecretKey },
        { ttl: ttl ?? new Date(Date.now() + 30 * 60 * 1000) },
      );
      return walletCtx.wallet.finalizeRecipe(recipe);
    },
    submitTx: (tx: any) => {
      counters.submitTx++;
      return walletCtx.wallet.submitTransaction(tx) as any;
    },
  };

  const zkConfigProvider = new NodeZkConfigProvider(zkConfigPath);

  // The real HTTP proof provider, wrapped in a transparent Proxy that only
  // *counts* calls to `proveTx` (proof-server round trips) — every other
  // property/method passes through untouched, and the proving payload is
  // never inspected.
  const baseProofProvider = httpClientProofProvider(networkConfig.proofServer, zkConfigProvider) as any;
  const proofProvider = new Proxy(baseProofProvider, {
    get(target, prop, receiver) {
      if (prop === 'proveTx') {
        const fn = target.proveTx.bind(target);
        return (...args: any[]) => {
          counters.proveTx++;
          return fn(...args);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });

  const providers = {
    privateStateProvider: levelPrivateStateProvider({
      privateStateStoreName: PRIVATE_STATE_STORE,
      accountId: walletCtx.unshieldedKeystore.getBech32Address().toString(),
      privateStoragePasswordProvider: () => privateStatePassword,
    }),
    publicDataProvider: indexerPublicDataProvider(networkConfig.indexer, networkConfig.indexerWS),
    zkConfigProvider,
    proofProvider,
    walletProvider,
    midnightProvider: walletProvider,
  };

  return { providers, counters };
}

async function readPolicyPassed(publicDataProvider: any, address: string): Promise<boolean | null> {
  const state = await publicDataProvider.queryContractState(address);
  if (!state) return null;
  return Boolean(CJGate.ledger(state.data).policyPassed);
}

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
  const { source, redeploy } = parseArgs(process.argv);
  const { network, config: networkConfig } = resolveNetwork();

  console.log('CJGate live proof flow');
  console.log(`  network: ${network}`);
  console.log(`  source:  ${source}`);
  console.log('');

  if (network !== 'undeployed' && network !== 'preprod') {
    fail(`live flow supports "undeployed" and "preprod"; active network is "${network}".`);
  }

  if (network !== 'undeployed') {
    // Dedicated CJGate wallet only — never a browser-wallet phrase/seed, and
    // never silently created here.
    if (process.env.MIDNIGHT_WALLET_MNEMONIC || process.env.MIDNIGHT_WALLET_SEED) {
      console.log('  note: ignoring MIDNIGHT_WALLET_* — CJGate Preprod uses its own dedicated wallet');
      delete process.env.MIDNIGHT_WALLET_MNEMONIC;
      delete process.env.MIDNIGHT_WALLET_SEED;
    }
    if (!loadState()?.wallets?.[network]) {
      fail(`no dedicated CJGate ${network} wallet — run: npm run cjgate:${network}:init`);
    }
  }

  // ── infra health ───────────────────────────────────────────────────────────
  console.log(`Checking ${network} + proof-server health...`);
  if (!(await proofServerHealthy(networkConfig.proofServer))) {
    fail(`proof server not healthy at ${networkConfig.proofServer} — run: npm run proof-server:start`);
  }
  try {
    const r = await fetch(networkConfig.indexer, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: '{ __typename }' }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) fail(`indexer returned HTTP ${r.status} at ${networkConfig.indexer}`);
  } catch (e) {
    fail(`indexer unreachable at ${networkConfig.indexer}: ${e instanceof Error ? e.message : e}`);
  }
  try {
    const r = await fetch(networkConfig.node.replace(/^ws/, 'http'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 1, jsonrpc: '2.0', method: 'system_health', params: [] }),
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) fail(`node RPC returned HTTP ${r.status}`);
  } catch (e) {
    fail(`node RPC unreachable: ${e instanceof Error ? e.message : e}`);
  }
  console.log('  node, indexer, proof server: healthy\n');

  // ── deployment ─────────────────────────────────────────────────────────────
  const contractAddress = await ensureFreshDeployment(network, networkConfig, redeploy);
  console.log(`  contract address: ${contractAddress}\n`);

  // ── real scanners -> PRIVATE signals ──────────────────────────────────────
  // The two numbers below never leave this scope in printable form.
  let secretsFound: number;
  let sastHighFindings: number;
  try {
    secretsFound = runGitleaksScan(source).secretsFound;
    console.log('Gitleaks scan completed');
  } catch (e) {
    fail(`Gitleaks failed to run: ${e instanceof Error ? e.message : e}`);
  }
  try {
    sastHighFindings = runSemgrepScan(source).sastHighFindings;
    console.log('Semgrep scan completed');
  } catch (e) {
    fail(`Semgrep failed to run: ${e instanceof Error ? e.message : e}`);
  }
  console.log('');

  // ── wallet + providers ────────────────────────────────────────────────────
  // undeployed → genesis seed; preprod → the persisted dedicated CJGate wallet
  // (guaranteed to exist by the guard above; never created here).
  const seed = getOrCreateWallet(network).seed;
  console.log(`Connecting wallet to ${network} (syncing)...`);
  const walletCtx = await createWallet({ network, networkConfig, seed });
  await walletCtx.wallet.waitForSyncedState();
  await persistWalletState(network, walletCtx);
  const { providers, counters } = makeProviders(walletCtx, networkConfig);
  console.log('  wallet synced\n');

  const deployed: any = await findDeployedContract(providers, {
    compiledContract: compiledContract as any,
    contractAddress,
    privateStateId: PRIVATE_STATE_ID,
    initialPrivateState: cleanCJGatePrivateState,
  });

  // Stage the private scanner results for the witnesses. Never logged.
  await providers.privateStateProvider.set(
    PRIVATE_STATE_ID,
    createCJGatePrivateState(BigInt(secretsFound), BigInt(sastHighFindings)),
  );

  // ── before snapshot ──────────────────────────────────────────────────────
  const policyPassedBefore = await readPolicyPassed(providers.publicDataProvider, contractAddress);
  const psSnap = snapshotProofServer();
  const proveBefore = counters.proveTx;
  const submitBefore = counters.submitTx;

  console.log('Invoking runSecurityGate on the deployed contract...');
  console.log('  (a clean result generates a real ZK proof via the proof server and submits a tx)\n');

  let txId: string | undefined;
  let blockHeight: number | string | undefined;
  let blocked = false;

  try {
    const tx = await deployed.callTx.runSecurityGate();
    txId = tx.public.txId;
    blockHeight = tx.public.blockHeight;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // The Compact assertion aborting the circuit is the expected BLOCK path.
    if (/failed assert/i.test(msg)) {
      blocked = true;
    } else {
      if (process.env.CJGATE_LIVE_DEBUG) console.error(err);
      await walletCtx.wallet.stop();
      fail(`runSecurityGate errored unexpectedly: ${msg}`);
    }
  }

  // ── after snapshot ───────────────────────────────────────────────────────
  const activity = proofServerActivitySince(psSnap);
  const proveDelta = counters.proveTx - proveBefore;
  const submitDelta = counters.submitTx - submitBefore;
  const policyPassedAfter = await readPolicyPassed(providers.publicDataProvider, contractAddress);

  await persistWalletState(network, walletCtx);
  await walletCtx.wallet.stop();

  // ── report ───────────────────────────────────────────────────────────────
  console.log('─── Result ──────────────────────────────────────────────────────');
  console.log(`  contract address:        ${contractAddress}`);
  console.log(`  policyPassed (before):   ${policyPassedBefore}`);
  console.log(`  policyPassed (after):    ${policyPassedAfter}`);
  console.log('');
  console.log('  proof-server evidence (safe):');
  if (activity.unavailable) {
    console.log('    container logs unavailable; relying on in-process counters');
  }
  console.log(`    proofProvider.proveTx calls (this invocation): ${proveDelta}`);
  console.log(`    walletProvider.submitTx calls (this invocation): ${submitDelta}`);
  console.log(`    new POST /prove log lines:  ${activity.proveRequests}`);
  console.log(`    new POST /check log lines:  ${activity.checkRequests}`);
  console.log(`    new "proof ok" log lines:   ${activity.proofsVerified}`);
  if (activity.safeExcerpt.length > 0) {
    console.log('    log excerpt:');
    for (const l of activity.safeExcerpt.slice(-8)) console.log(`      ${l}`);
  }
  console.log('');

  if (!blocked) {
    // PASS
    console.log('  outcome: PASS — real ZK proof generated and transaction submitted');
    console.log(`  transaction id:  ${txId}`);
    console.log(`  block height:    ${blockHeight}`);
    const ok =
      policyPassedAfter === true && proveDelta >= 1 && submitDelta >= 1;
    if (!ok) {
      console.error('\n  ✗ PASS invariant check failed (expected policyPassed=true, proveTx>=1, submitTx>=1)');
      process.exit(2);
    }
    console.log('\n  ✓ proof server was used, transaction submitted, public policyPassed == true');
    process.exit(0);
  } else {
    // BLOCK
    console.log('  outcome: BLOCK — Compact assertion rejected the state transition');
    console.log('  no proof requested, no transaction submitted');
    const unchanged = policyPassedAfter === policyPassedBefore;
    const noProof = proveDelta === 0 && submitDelta === 0 && activity.proveRequests === 0;
    if (!unchanged || !noProof) {
      console.error('\n  ✗ BLOCK invariant check failed (expected no proof/tx and unchanged ledger)');
      process.exit(2);
    }
    console.log('\n  ✓ no proof-server proving activity, no tx, public ledger state unchanged');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(2);
});
