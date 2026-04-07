// ────────────────── Core Finding Types ──────────────────

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FindingType =
  | 'exposed_secret'
  | 'missing_header'
  | 'insecure_header'
  | 'cors_misconfiguration'
  | 'insecure_storage'
  | 'insecure_cookie'
  | 'supabase_rls_violation'
  | 'supabase_exposed_table'
  | 'insecure_network';

export interface Finding {
  type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  location?: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanJob {
  job_id: string;
  scan_id: string;
  session_id: string | null;
  url: string;
}

// ────────────────── Supabase Scanner Domain Types ──────────────────

export interface SupabaseInstance {
  projectUrl: string;   // https://xxx.supabase.co
  anonKey: string | null;
  source: string;       // onde encontrou (network, source code, env)
}

export interface JWTInfo {
  readonly role: string;
  readonly isServiceRole: boolean;
  readonly projectRef: string;
  readonly issuer: string;
  readonly expiresAt: string;
}

// ────────────────── Table Probe Domain Types ──────────────────

/** Uma linha de dados redactada de uma tabela, pronta para exibição. */
export type RedactedRow = Readonly<Record<string, string | number | boolean | null>>;

export interface TableSelectResult {
  allowed: boolean;
  rowCount: number;
  sample: readonly RedactedRow[] | null;
}

export interface TableWriteResult {
  allowed: boolean;
  error: string | null;
}

export interface TableProbeResult {
  readonly table: string;
  select: TableSelectResult;
  insert: TableWriteResult;
  update: TableWriteResult;
  delete: TableWriteResult;
}

// ────────────────── Secret Scanner Domain Types ──────────────────

export type PatternName =
  | 'AWS_ACCESS_KEY'
  | 'AWS_SECRET_KEY'
  | 'GOOGLE_API_KEY'
  | 'FIREBASE_CONFIG'
  | 'SUPABASE_JWT'
  | 'STRIPE_SECRET'
  | 'STRIPE_PUBLIC'
  | 'PRIVATE_KEY'
  | 'GENERIC_API_KEY'
  | 'GENERIC_SECRET';

export interface SecretPattern {
  readonly name: PatternName;
  readonly regex: RegExp;
  readonly severity: Severity;
  readonly remediation: string;
}
