import { Finding, ScanJob } from './findings';

// ────────────────── Job Repository Port ──────────────────

export interface CompleteJobParams {
  readonly jobId: string;
  readonly scanId: string;
  readonly score: number;
  readonly durationMs: number;
  readonly pageTitle: string;
  readonly findings: Finding[];
  readonly metadata?: Record<string, unknown>;
}

export interface FailJobParams {
  readonly jobId: string;
  readonly scanId: string;
  readonly error: string;
}

export interface HeartbeatParams {
  readonly scannerId: string;
  readonly poolSize: number;
  readonly activeScans: number;
}

/**
 * Port (contrato) para acesso ao sistema de filas e persistência de jobs.
 * Implementações concretas vivem em infrastructure/.
 */
export interface IJobRepository {
  dequeueJob(): Promise<ScanJob[]>;
  completeJob(params: CompleteJobParams): Promise<void>;
  failJob(params: FailJobParams): Promise<{ willRetry: boolean }>;
  sendHeartbeat(params: HeartbeatParams): Promise<void>;
  getSessionCookies(sessionId: string): Promise<unknown[] | null>;
}
