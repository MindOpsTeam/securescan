import { Finding, Severity } from '../types/findings';

/**
 * Scoring v2 — Rendimentos Decrescentes por Categoria
 *
 * Cada finding adicional da mesma severidade penaliza MENOS que o anterior.
 * Exemplo HIGH: 1º = 10pts, 2º = 7pts, 3º = 5pts, 4º = 3pts, 5º+ = 2pts
 * Cada severidade tem um TETO MÁXIMO de penalização, impedindo que
 * muitos achados informativos (headers ausentes, etc) destruam a nota.
 *
 * Referência de notas esperadas:
 *   0 findings           → 100 (A+)
 *   1 LOW                →  98 (A+)
 *   1 MEDIUM             →  95 (A+)
 *   1 HIGH               →  90 (A)
 *   1 CRITICAL           →  80 (B+)
 *   3 MEDIUM             →  85 (A-)
 *   1 CRITICAL + 2 HIGH  →  63 (C)
 *   2 CRITICAL + 3 HIGH  →  40 (D-)
 */

/** Penalidade do N-ésimo finding de cada severidade (índice 0-based) */
const DIMINISHING_PENALTIES: Record<Severity, number[]> = {
  INFO:     [],                          // nunca penaliza
  CRITICAL: [20, 15, 10, 8, 5, 3],      // max ~61 (cap 55)
  HIGH:     [10, 7, 5, 3, 2, 2],        // max ~29 (cap 25)
  MEDIUM:   [5, 4, 3, 2, 1, 1],         // max ~16 (cap 12)
  LOW:      [2, 1, 1, 1, 1],            // max ~6  (cap 5)
};

/** Teto máximo de penalidade por severidade */
const MAX_PENALTY_PER_SEVERITY: Record<Severity, number> = {
  INFO: 0,
  CRITICAL: 55,
  HIGH: 25,
  MEDIUM: 12,
  LOW: 5,
};

/**
 * Determina se um finding é informativo (não penaliza o score).
 */
function isInformationalFinding(f: Finding): boolean {
  if (f.severity === 'INFO') return true;
  if (f.title.includes('✅')) return true;
  if (f.metadata?.['protected'] === true) return true;
  if (f.metadata?.['managedHosting'] === true) return true;
  return false;
}

/**
 * Converte score numérico (0-100) em nota de letra.
 */
export function scoreToGrade(score: number): string {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 85) return 'A-';
  if (score >= 80) return 'B+';
  if (score >= 75) return 'B';
  if (score >= 70) return 'B-';
  if (score >= 65) return 'C+';
  if (score >= 60) return 'C';
  if (score >= 55) return 'C-';
  if (score >= 50) return 'D+';
  if (score >= 45) return 'D';
  if (score >= 40) return 'D-';
  return 'F';
}

/**
 * Calcula security score (0-100) baseado nos findings usando
 * rendimentos decrescentes por categoria de severidade.
 *
 * Findings informativos (INFO, ✅, protected, managedHosting) NÃO penalizam.
 */
export function calculateScore(findings: Finding[]): number {
  // Agrupa findings penalizáveis por severidade
  const countBySeverity: Record<Severity, number> = {
    INFO: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };

  for (const f of findings) {
    if (isInformationalFinding(f)) continue;
    countBySeverity[f.severity]++;
  }

  // Calcula penalidade com rendimentos decrescentes
  let totalPenalty = 0;

  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]) {
    const count = countBySeverity[severity];
    if (count === 0) continue;

    const schedule = DIMINISHING_PENALTIES[severity];
    let severityPenalty = 0;

    for (let i = 0; i < count; i++) {
      // Se excedeu o schedule, usa o último valor (penalidade mínima de repetição)
      const penalty = i < schedule.length
        ? schedule[i]
        : schedule[schedule.length - 1];
      severityPenalty += penalty;
    }

    // Aplica teto da categoria
    severityPenalty = Math.min(severityPenalty, MAX_PENALTY_PER_SEVERITY[severity]);
    totalPenalty += severityPenalty;
  }

  return Math.max(0, Math.min(100, 100 - totalPenalty));
}
