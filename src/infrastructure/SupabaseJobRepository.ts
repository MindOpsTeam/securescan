import { SupabaseClient } from '@supabase/supabase-js';
import { ScanJob } from '../types/findings';
import {
  IJobRepository,
  CompleteJobParams,
  FailJobParams,
  HeartbeatParams,
} from '../types/ports';

/**
 * Implementação concreta de IJobRepository usando Supabase SDK.
 * Este é o ÚNICO adapter que conhece @supabase/supabase-js no domínio de jobs.
 */
export class SupabaseJobRepository implements IJobRepository {
  constructor(private readonly client: SupabaseClient) {}

  async dequeueJob(): Promise<ScanJob[]> {
    const { data, error } = await this.client.rpc('dequeue_scan_job');
    if (error) {
      throw new Error(`[dequeue] RPC error: ${error.message}`);
    }
    return (data as ScanJob[]) ?? [];
  }

  async completeJob(params: CompleteJobParams): Promise<void> {
    const { error } = await this.client.rpc('complete_scan_job', {
      p_job_id: params.jobId,
      p_scan_id: params.scanId,
      p_score: params.score,
      p_duration_ms: params.durationMs,
      p_page_title: params.pageTitle,
      p_findings: params.findings,
      p_metadata: params.metadata || {},
    });
    if (error) {
      throw new Error(`[completeJob] RPC error: ${error.message}`);
    }
  }

  async failJob({ jobId, scanId, error }: FailJobParams): Promise<{ willRetry: boolean }> {
    const result = await this.client.rpc('fail_scan_job', {
      p_job_id: jobId,
      p_scan_id: scanId,
      p_error: error.substring(0, 500),
    });
    if (result.error) {
      console.error(`[failJob] RPC error:`, result.error.message);
      return { willRetry: false };
    }
    return { willRetry: !!result.data };
  }

  async sendHeartbeat({ scannerId, poolSize, activeScans }: HeartbeatParams): Promise<void> {
    const { error } = await this.client.rpc('scanner_heartbeat', {
      p_scanner_id: scannerId,
      p_pool_size: poolSize,
      p_active: activeScans,
    });
    if (error) {
      console.error('[heartbeat] RPC error:', error.message);
    }
  }

  async getSessionCookies(sessionId: string): Promise<unknown[] | null> {
    const { data, error } = await this.client.rpc('get_session_cookies', {
      p_session_id: sessionId,
    });
    if (error) {
      console.warn('[getSessionCookies] RPC error:', error.message);
      return null;
    }
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
