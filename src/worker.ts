import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
import { BrowserPool } from './browser/pool';
import { validateUrlDNS } from './security/urlValidator';
import { runAllScanners } from './scanners/index';
import { calculateScore } from './utils/scoring';
import { ScanJob } from './types/findings';
import { IJobRepository } from './types/ports';
import { SupabaseJobRepository } from './infrastructure/SupabaseJobRepository';
import { EdgeFunctionJobRepository } from './infrastructure/EdgeFunctionJobRepository';

// ─────────────────────────── Config ───────────────────────────

const POLL_INTERVAL_MS = 2_000;
const IDLE_POLL_INTERVAL_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 15_000;
const SCAN_TIMEOUT_MS = 120_000;
const POOL_SIZE = 3;
const SCANNER_ID = process.env.SCANNER_ID || 'scanner-main';

// ─────────────────────────── Init ───────────────────────────

/**
 * Seleciona o adapter correto automaticamente:
 *
 * 1. GATEWAY_URL + WORKER_API_KEY  →  Edge Function gateway (seguro, sem service_role)
 * 2. SUPABASE_URL + SERVICE_KEY    →  Acesso direto (quando temos service_role)
 */
function createRepository(): IJobRepository {
  const gatewayUrl = process.env.GATEWAY_URL;
  const workerApiKey = process.env.WORKER_API_KEY;

  if (gatewayUrl && workerApiKey) {
    console.log('[init] Mode: Edge Function Gateway (secure proxy)');
    console.log(`[init] Gateway: ${gatewayUrl.replace(/\/\/(.{12}).*/, '//$1...')}`);
    return new EdgeFunctionJobRepository(gatewayUrl, workerApiKey);
  }

  // Fallback: acesso direto ao Supabase (requer service_role key)
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    console.error('[FATAL] Configure GATEWAY_URL + WORKER_API_KEY (recommended)');
    console.error('        or SUPABASE_URL + SUPABASE_SERVICE_KEY (direct access)');
    process.exit(1);
  }

  console.log('[init] Mode: Direct Supabase connection');
  console.log(`[init] URL: ${supabaseUrl.replace(/\/\/(.{8}).*/, '//$1...')}`);
  const client = createClient(supabaseUrl, supabaseKey);
  return new SupabaseJobRepository(client);
}

const repo: IJobRepository = createRepository();
const pool = new BrowserPool({ poolSize: POOL_SIZE });

let running = true;
let activeScans = 0;

// ─────────────────────────── Heartbeat ───────────────────────────

async function sendHeartbeat(jobRepo: IJobRepository): Promise<void> {
  try {
    await jobRepo.sendHeartbeat({
      scannerId: SCANNER_ID,
      poolSize: pool.healthyCount(),
      activeScans,
    });
  } catch (err) {
    console.error('[heartbeat] Failed:', err);
  }
}

// ─────────────────────────── Job Processing ───────────────────────────

async function processJob(job: ScanJob, jobRepo: IJobRepository): Promise<void> {
  const startTime = Date.now();
  console.log(`[worker] Processing job ${job.job_id} | scan ${job.scan_id} | ${job.url}`);
  activeScans++;

  // Anti-SSRF Layer 2: DNS validation
  const urlCheck = await validateUrlDNS(job.url);
  if (!urlCheck.valid) {
    console.warn(`[worker] SSRF blocked: ${urlCheck.reason}`);
    await jobRepo.failJob({
      jobId: job.job_id,
      scanId: job.scan_id,
      error: `URL blocked (SSRF protection): ${urlCheck.reason}`,
    });
    activeScans--;
    return;
  }

  // Get isolated browser page
  const { page, context, release } = await pool.getPage();

  try {
    // Inject session cookies if applicable
    let sessionToken: string | undefined;
    if (job.session_id) {
      try {
        const cookies = await jobRepo.getSessionCookies(job.session_id);
        if (cookies && Array.isArray(cookies)) {
          await context.setCookie(...(cookies as Parameters<typeof context.setCookie>));
          console.log(`  [worker] Injected ${cookies.length} session cookies`);

          // Extract Supabase auth token for authenticated probing
          for (const cookie of cookies as Array<{ name: string; value: string }>) {
            if (cookie.name.includes('auth-token') && cookie.value.startsWith('ey')) {
              sessionToken = cookie.value;
              console.log(`  [worker] Extracted auth token for IDOR probing`);
              break;
            }
          }
        }
      } catch (err) {
        console.warn(`  [worker] Failed to load session cookies:`, err);
      }
    }

    // Run all scanners with timeout
    const result = await Promise.race([
      runAllScanners(page, job.url, sessionToken),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Scan timeout exceeded (120s)')), SCAN_TIMEOUT_MS)
      ),
    ]);

    const score = calculateScore(result.findings);
    const duration = Date.now() - startTime;

    // Transactional completion via repository
    await jobRepo.completeJob({
      jobId: job.job_id,
      scanId: job.scan_id,
      score,
      durationMs: duration,
      pageTitle: result.pageTitle || '',
      findings: result.findings,
      metadata: result.metadata as unknown as Record<string, unknown>,
    });

    console.log(
      `[worker] ✓ Scan complete | score=${score} | ${result.findings.length} findings | ${duration}ms`
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[worker] ✗ Scan failed:`, message);

    const { willRetry } = await jobRepo.failJob({
      jobId: job.job_id,
      scanId: job.scan_id,
      error: message.substring(0, 500),
    });

    console.log(`[worker] ${willRetry ? 'Will retry' : 'Gave up'} on job ${job.job_id}`);
  } finally {
    await release();
    activeScans--;
  }
}

// ─────────────────────────── Poll Loop ───────────────────────────

async function pollForJobs(jobRepo: IJobRepository): Promise<void> {
  while (running) {
    try {
      const jobs = await jobRepo.dequeueJob();

      if (!jobs || jobs.length === 0) {
        await sleep(IDLE_POLL_INTERVAL_MS);
        continue;
      }

      // Process the dequeued job
      const job = jobs[0];
      await processJob(job, jobRepo);

      // Short delay before next poll (stay responsive)
      await sleep(POLL_INTERVAL_MS);
    } catch (err) {
      console.error('[poll] Unexpected error:', err);
      await sleep(IDLE_POLL_INTERVAL_MS);
    }
  }
}

// ─────────────────────────── Main ───────────────────────────

async function main(): Promise<void> {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║    SecureScan Scanner Worker v1.1.0          ║');
  console.log('║    Mode: Worker (no HTTP server)             ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log(`[main] SCANNER_ID: ${SCANNER_ID}`);
  console.log(`[main] POOL_SIZE: ${POOL_SIZE}`);

  // Init browser pool
  await pool.init();
  console.log(`[main] Browser pool ready (${pool.healthyCount()} healthy)`);

  // Start heartbeat interval
  const heartbeatTimer = setInterval(() => sendHeartbeat(repo), HEARTBEAT_INTERVAL_MS);
  await sendHeartbeat(repo); // first heartbeat immediately

  // Start polling
  console.log('[main] Starting job poll loop...\n');
  await pollForJobs(repo);

  // Cleanup
  clearInterval(heartbeatTimer);
  await pool.shutdown();
  console.log('[main] Worker stopped.');
}

// ─────────────────────────── Graceful Shutdown ───────────────────────────

process.on('SIGINT', () => {
  console.log('\n[main] SIGINT received, shutting down...');
  running = false;
});

process.on('SIGTERM', () => {
  console.log('\n[main] SIGTERM received, shutting down...');
  running = false;
});

process.on('unhandledRejection', (err) => {
  console.error('[FATAL] Unhandled rejection:', err);
});

// ─────────────────────────── Helpers ───────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─────────────────────────── Start ───────────────────────────

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
