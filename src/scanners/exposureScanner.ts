import { Page } from 'puppeteer';
import { Finding, Severity } from '../types/findings';

// ────────────────── Exposure Scanner ──────────────────
// Detects exposed sensitive files: .env, source maps, .git, config files

interface ExposureCheck {
  readonly path: string;
  readonly severity: Severity;
  readonly title: string;
  readonly contentCheck?: (body: string) => boolean;
  readonly remediation: string;
  readonly aiPrompt: string;
}

/** Fixed paths to probe on the target host. */
const SENSITIVE_PATHS: readonly ExposureCheck[] = [
  {
    path: '/.env',
    severity: 'CRITICAL',
    title: 'Arquivo .env exposto publicamente',
    contentCheck: (body) => {
      // Must have at least 2 KEY=VALUE lines and no HTML tags (SPA catch-all guard)
      if (/<(div|script|meta|html|head|body|link|style)/i.test(body)) return false;
      const kvLines = body.split('\n').filter(l => /^[A-Z_][A-Z0-9_]*\s*=/.test(l.trim()));
      return kvLines.length >= 2;
    },
    remediation: 'Bloqueie o acesso a /.env no servidor/CDN. Rotacione TODAS as credenciais expostas.',
    aiPrompt:
      'URGENTE: O arquivo .env está acessível publicamente. Este arquivo contém credenciais sensíveis. ' +
      'Ações imediatas: 1) Bloqueie o acesso a /.env no nginx/apache/CDN. 2) Rotacione TODAS as chaves ' +
      'e senhas que estavam neste arquivo. 3) Adicione .env ao .gitignore se ainda não estiver.',
  },
  {
    path: '/.env.local',
    severity: 'CRITICAL',
    title: 'Arquivo .env.local exposto publicamente',
    contentCheck: (body) => {
      if (/<(div|script|meta|html|head|body|link|style)/i.test(body)) return false;
      const kvLines = body.split('\n').filter(l => /^[A-Z_][A-Z0-9_]*\s*=/.test(l.trim()));
      return kvLines.length >= 2;
    },
    remediation: 'Bloqueie o acesso a arquivos .env no servidor/CDN.',
    aiPrompt: 'O arquivo .env.local está acessível publicamente. Rotacione todas as credenciais e bloqueie o acesso.',
  },
  {
    path: '/.git/config',
    severity: 'CRITICAL',
    title: 'Repositório .git exposto publicamente',
    contentCheck: (body) => body.includes('[core]') || body.includes('[remote'),
    remediation: 'Bloqueie acesso ao diretório .git no servidor. O código-fonte completo pode ser baixado.',
    aiPrompt:
      'URGENTE: O diretório .git está acessível. Um atacante pode baixar todo o código-fonte e histórico ' +
      'de commits, incluindo credenciais que já foram commitadas. Bloqueie /.git/ no servidor imediatamente.',
  },
  {
    path: '/.git/HEAD',
    severity: 'CRITICAL',
    title: 'Repositório .git exposto publicamente',
    contentCheck: (body) => body.startsWith('ref:') || /^[0-9a-f]{40}$/.test(body.trim()),
    remediation: 'Bloqueie acesso ao diretório .git no servidor.',
    aiPrompt: 'O diretório .git está acessível publicamente. Bloqueie /.git/ no servidor imediatamente.',
  },
  {
    path: '/env.js',
    severity: 'HIGH',
    title: 'Arquivo de configuração env.js exposto',
    contentCheck: (body) =>
      !body.includes('<html') && (body.includes('API_KEY') || body.includes('SECRET') || body.includes('supabase')),
    remediation: 'Não exponha variáveis de ambiente em arquivos JS estáticos. Use variáveis de build-time.',
    aiPrompt:
      'O arquivo env.js está expondo configurações sensíveis. Migre para variáveis de build-time (VITE_*, NEXT_PUBLIC_*) ' +
      'e remova o arquivo env.js do deploy.',
  },
  {
    path: '/config.js',
    severity: 'MEDIUM',
    title: 'Arquivo de configuração config.js exposto',
    contentCheck: (body) =>
      !body.includes('<html') && (body.includes('api') || body.includes('key') || body.includes('secret')),
    remediation: 'Revise o conteúdo de config.js para garantir que não contenha credenciais.',
    aiPrompt: 'O arquivo config.js está acessível. Verifique se ele não contém credenciais sensíveis.',
  },
  {
    path: '/wp-config.php',
    severity: 'CRITICAL',
    title: 'wp-config.php exposto (WordPress)',
    contentCheck: (body) => body.includes('DB_PASSWORD') || body.includes('DB_NAME'),
    remediation: 'Bloqueie acesso a wp-config.php. Se exposto, rotacione credenciais do banco de dados.',
    aiPrompt: 'URGENTE: wp-config.php está exposto com credenciais do banco de dados. Rotacione todas as senhas imediatamente.',
  },
];

/**
 * Testa um URL de source map derivado de um bundle JS capturado.
 */
function buildSourceMapCheck(bundleUrl: string): ExposureCheck {
  const mapUrl = `${bundleUrl}.map`;
  const filename = mapUrl.split('/').pop() || mapUrl;
  return {
    path: mapUrl,
    severity: 'MEDIUM',
    title: `Source map exposto: ${filename}`,
    contentCheck: (body) => body.includes('"sources"') || body.includes('"mappings"'),
    remediation: 'Desabilite source maps em produção. No Vite: build.sourcemap = false. No Webpack: devtool = false.',
    aiPrompt:
      'Source maps estão acessíveis em produção, expondo o código-fonte original. ' +
      'Para desabilitar: No Vite, adicione `build: { sourcemap: false }` no vite.config.ts. ' +
      'No Webpack, remova `devtool` ou defina como `false`. No Next.js, adicione `productionBrowserSourceMaps: false`.',
  };
}

/**
 * Scan for exposed sensitive files (.env, source maps, .git, etc.)
 *
 * @param page - Puppeteer page (used to derive base URL)
 * @param url - Base URL of the target
 * @param capturedBundleUrls - URLs of JS bundles captured during navigation
 */
export async function scanExposures(
  page: Page,
  url: string,
  capturedBundleUrls: string[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const baseUrl = new URL(url).origin;

  // 1. Static sensitive paths
  console.log(`  [exposure] Testing ${SENSITIVE_PATHS.length} sensitive paths...`);
  const staticChecks = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (check) => {
      try {
        const res = await fetch(`${baseUrl}${check.path}`, {
          signal: AbortSignal.timeout(5000),
          redirect: 'follow',
          headers: { 'User-Agent': 'SecureScan/1.2' },
        });

        if (!res.ok) return null;

        // Avoid false positives from SPA catch-all routes that return HTML for any path
        const contentType = res.headers.get('content-type') || '';
        const body = await res.text();

        // SPA guard: if response is HTML and path is non-HTML, skip
        if (contentType.includes('text/html') && !check.path.endsWith('.html') && !check.path.endsWith('.php')) {
          return null;
        }

        // Content validation
        if (check.contentCheck && !check.contentCheck(body)) return null;

        return { check, body: body.substring(0, 200) };
      } catch {
        return null;
      }
    }),
  );

  for (const result of staticChecks) {
    if (result.status === 'fulfilled' && result.value) {
      const { check, body } = result.value;
      findings.push({
        type: 'exposed_secret',
        severity: check.severity,
        title: check.title,
        description: `O arquivo ${check.path} está acessível publicamente.\n\nPreview:\n${body}...`,
        location: `${baseUrl}${check.path}`,
        remediation: check.remediation,
        metadata: {
          path: check.path,
          ai_prompt: check.aiPrompt,
        },
      });
    }
  }

  // 2. Source maps from captured JS bundles
  const mapChecks: ExposureCheck[] = capturedBundleUrls
    .filter((u) => u.endsWith('.js'))
    .slice(0, 10) // Limit to 10 bundles
    .map(buildSourceMapCheck);

  if (mapChecks.length > 0) {
    console.log(`  [exposure] Testing ${mapChecks.length} source maps...`);

    const mapResults = await Promise.allSettled(
      mapChecks.map(async (check) => {
        try {
          // Source map URLs are absolute already
          const targetUrl = check.path.startsWith('http') ? check.path : `${baseUrl}${check.path}`;
          const res = await fetch(targetUrl, {
            signal: AbortSignal.timeout(5000),
            headers: { 'User-Agent': 'SecureScan/1.2' },
          });

          if (!res.ok) return null;

          const contentType = res.headers.get('content-type') || '';
          // Source maps should be JSON, not HTML
          if (contentType.includes('text/html')) return null;

          const body = await res.text();
          if (check.contentCheck && !check.contentCheck(body)) return null;

          return { check };
        } catch {
          return null;
        }
      }),
    );

    let mapsExposed = 0;
    for (const result of mapResults) {
      if (result.status === 'fulfilled' && result.value) {
        mapsExposed++;
        // Only report the first one to avoid flood
        if (mapsExposed === 1) {
          const { check } = result.value;
          findings.push({
            type: 'exposed_secret',
            severity: check.severity,
            title: `Source maps expostos em produção (${mapChecks.length} bundles testados)`,
            description:
              'Source maps estão acessíveis publicamente, permitindo que atacantes visualizem o código-fonte original da aplicação.',
            location: url,
            remediation: check.remediation,
            metadata: {
              mapsExposed,
              totalBundlesTested: mapChecks.length,
              ai_prompt: check.aiPrompt,
            },
          });
        }
      }
    }
    // Update count in the finding
    if (mapsExposed > 1) {
      const mapFinding = findings.find((f) => f.title.includes('Source maps'));
      if (mapFinding?.metadata) {
        mapFinding.metadata['mapsExposed'] = mapsExposed;
        mapFinding.description = `${mapsExposed} source maps estão acessíveis publicamente, permitindo que atacantes visualizem o código-fonte original.`;
      }
    }
  }

  const exposedCount = findings.length;
  if (exposedCount > 0) {
    console.log(`  [exposure] ⚠ ${exposedCount} arquivo(s) sensível(is) exposto(s)`);
  } else {
    console.log(`  [exposure] ✅ Nenhum arquivo sensível exposto`);
  }

  return findings;
}
