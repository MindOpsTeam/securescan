import { ScanJob } from '../types/findings';
import {
  IJobRepository,
  CompleteJobParams,
  FailJobParams,
  HeartbeatParams,
} from '../types/ports';

/**
 * Adapter que conecta o worker ao Supabase via Edge Function Gateway.
 *
 * ┌──────────────┐      HTTPS + x-worker-key      ┌────────────────────┐
 * │ Railway      │ ──────────────────────────────▸  │ Edge Function      │
 * │ Worker       │                                  │ scanner-gateway    │
 * └──────────────┘                                  │ (service_role_key) │
 *                                                   └────────┬───────────┘
 *                                                            │
 *                                                            ▼
 *                                                   ┌────────────────┐
 *                                                   │  Supabase DB   │
 *                                                   └────────────────┘
 *
 * A Edge Function já tem acesso nativo ao SUPABASE_SERVICE_ROLE_KEY,
 * então o worker nunca precisa conhecer essa chave.
 */
export class EdgeFunctionJobRepository implements IJobRepository {
  constructor(
    private readonly gatewayUrl: string,
    private readonly workerApiKey: string,
  ) {}

  // ─────────────────── Helpers ───────────────────

  private async call<T>(action: string, params: Record<string, unknown> = {}): Promise<T> {
    const res = await fetch(this.gatewayUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-worker-key': this.workerApiKey,
      },
      body: JSON.stringify({ action, ...params }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '(no body)');
      throw new Error(`[EdgeGateway] ${action} failed (${res.status}): ${body}`);
    }

    return res.json() as Promise<T>;
  }

  // ─────────────────── IJobRepository ───────────────────

  async dequeueJob(): Promise<ScanJob[]> {
    const data = await this.call<ScanJob[]>('dequeue');
    return data ?? [];
  }

  async completeJob(params: CompleteJobParams): Promise<void> {
    await this.call('complete', {
      p_job_id: params.jobId,
      p_scan_id: params.scanId,
      p_score: params.score,
      p_duration_ms: params.durationMs,
      p_page_title: params.pageTitle,
      p_findings: params.findings,
      p_metadata: params.metadata || {},
    });
  }

  async failJob({ jobId, scanId, error }: FailJobParams): Promise<{ willRetry: boolean }> {
    const data = await this.call<{ willRetry: boolean }>('fail', {
      p_job_id: jobId,
      p_scan_id: scanId,
      p_error: error.substring(0, 500),
    });
    return { willRetry: !!data?.willRetry };
  }

  async sendHeartbeat({ scannerId, poolSize, activeScans }: HeartbeatParams): Promise<void> {
    await this.call('heartbeat', {
      p_scanner_id: scannerId,
      p_pool_size: poolSize,
      p_active: activeScans,
    });
  }

  async getSessionCookies(sessionId: string): Promise<unknown[] | null> {
    const data = await this.call<{ cookies_encrypted?: string } | null>('get_session_cookies', {
      p_session_id: sessionId,
    });

    if (data?.cookies_encrypted) {
      try {
        const cookies = JSON.parse(data.cookies_encrypted);
        return Array.isArray(cookies) ? cookies : null;
      } catch {
        return null;
      }
    }
    return null;
  }
}
