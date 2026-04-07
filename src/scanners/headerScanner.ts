import { Page } from 'puppeteer';
import { Finding } from '../types/findings';

interface HeaderCheck {
  header: string;
  severity: Finding['severity'];
  title: string;
  remediation: string;
  aiPrompt: string;
  /** Custom validator. If returns true = OK. If undefined, existence check only. */
  validate?: (value: string) => boolean;
}

const REQUIRED_HEADERS: HeaderCheck[] = [
  {
    header: 'strict-transport-security',
    severity: 'HIGH',
    title: 'Header HSTS ausente',
    remediation: 'Adicione Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    aiPrompt:
      'Configure o header HTTP Strict-Transport-Security no servidor/proxy da aplicação. ' +
      'O valor deve ser: max-age=31536000; includeSubDomains; preload. ' +
      'Se estiver usando Vercel, adicione no vercel.json. Se Nginx, adicione no bloco server. ' +
      'Se Express, use o middleware helmet.',
  },
  {
    header: 'x-content-type-options',
    severity: 'MEDIUM',
    title: 'Header X-Content-Type-Options ausente',
    remediation: 'Adicione X-Content-Type-Options: nosniff',
    aiPrompt:
      'Adicione o header HTTP X-Content-Type-Options com valor nosniff na configuração do servidor. ' +
      'Isso impede que o navegador tente adivinhar o tipo de conteúdo, prevenindo ataques de MIME sniffing.',
    validate: (v) => v.toLowerCase() === 'nosniff',
  },
  {
    header: 'x-frame-options',
    severity: 'MEDIUM',
    title: 'Header X-Frame-Options ausente (proteção contra clickjacking)',
    remediation: 'Adicione X-Frame-Options: DENY ou SAMEORIGIN',
    aiPrompt:
      'Adicione o header HTTP X-Frame-Options com valor DENY (ou SAMEORIGIN se houver iframes legítimos) ' +
      'na configuração do servidor. Isso impede ataques de clickjacking onde um site malicioso embutiria sua página em um iframe invisível.',
  },
  {
    header: 'content-security-policy',
    severity: 'HIGH',
    title: 'Header Content-Security-Policy ausente',
    remediation: 'Adicione um header Content-Security-Policy. Comece com uma política report-only.',
    aiPrompt:
      'Adicione um header Content-Security-Policy para a aplicação. Comece com uma política permissiva e vá restringindo: ' +
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; " +
      "font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://*.supabase.co. " +
      'Se estiver usando Vercel, adicione no vercel.json em headers.',
  },
  {
    header: 'referrer-policy',
    severity: 'LOW',
    title: 'Header Referrer-Policy ausente',
    remediation: 'Adicione Referrer-Policy: strict-origin-when-cross-origin',
    aiPrompt: 'Adicione o header HTTP Referrer-Policy com valor strict-origin-when-cross-origin na configuração do servidor.',
  },
  {
    header: 'permissions-policy',
    severity: 'LOW',
    title: 'Header Permissions-Policy ausente',
    remediation: 'Adicione Permissions-Policy para restringir funcionalidades do navegador.',
    aiPrompt:
      'Adicione o header HTTP Permissions-Policy para restringir acesso a funcionalidades sensíveis do navegador: ' +
      'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(). ' +
      'Isso impede que scripts de terceiros acessem câmera, microfone e localização sem seu controle.',
  },
  {
    header: 'x-xss-protection',
    severity: 'LOW',
    title: 'Header X-XSS-Protection ausente',
    remediation: 'Adicione X-XSS-Protection: 0 (prática moderna; confie no CSP).',
    aiPrompt:
      'Adicione o header HTTP X-XSS-Protection com valor 0 na configuração do servidor. ' +
      'O filtro XSS do navegador é considerado inseguro e foi descontinuado — a proteção deve vir do Content-Security-Policy.',
  },
];

interface InsecureHeaderCheck {
  header: string;
  pattern: RegExp;
  severity: Finding['severity'];
  title: string;
  remediation: string;
  aiPrompt: string;
}

const INSECURE_VALUES: InsecureHeaderCheck[] = [
  {
    header: 'content-security-policy',
    pattern: /unsafe-inline|unsafe-eval/i,
    severity: 'MEDIUM',
    title: 'CSP permite unsafe-inline ou unsafe-eval',
    remediation: 'Remova unsafe-inline e unsafe-eval do seu CSP. Use políticas baseadas em nonce ou hash.',
    aiPrompt:
      'O Content-Security-Policy atual usa unsafe-inline ou unsafe-eval, o que anula a proteção contra XSS. ' +
      'Remova essas diretivas e use políticas baseadas em nonce. Para estilos inline, mova para arquivos CSS externos. ' +
      'Para scripts inline, use nonce ou hash.',
  },
  {
    header: 'strict-transport-security',
    pattern: /max-age=0/,
    severity: 'HIGH',
    title: 'HSTS max-age é 0 (desabilitado)',
    remediation: 'Defina max-age para pelo menos 31536000 (1 ano).',
    aiPrompt:
      'O header Strict-Transport-Security está com max-age=0, efetivamente desabilitado. ' +
      'Altere para max-age=31536000; includeSubDomains; preload para forçar HTTPS por 1 ano.',
  },
  {
    header: 'server',
    pattern: /.+/,
    severity: 'LOW',
    title: 'Header Server expõe stack tecnológica',
    remediation: 'Remova ou ofusque o header Server para evitar revelar sua stack tecnológica.',
    aiPrompt:
      'Remova o header Server da resposta HTTP para não expor a stack tecnológica do servidor. ' +
      'Se estiver usando Nginx, adicione server_tokens off; no bloco http. Se Express, use helmet().',
  },
  {
    header: 'x-powered-by',
    pattern: /.+/,
    severity: 'LOW',
    title: 'Header X-Powered-By expõe framework',
    remediation: "Remova o header X-Powered-By (ex: app.disable('x-powered-by') no Express).",
    aiPrompt:
      "Remova o header X-Powered-By que expõe o framework usado. Se Express, adicione app.disable('x-powered-by') no início da aplicação.",
  },
];

/**
 * Verifica security headers da resposta HTTP.
 */
export async function scanHeaders(page: Page, url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const response = await page.goto(url, {
    waitUntil: 'domcontentloaded',
    timeout: 30_000,
  });

  if (!response) {
    findings.push({
      type: 'missing_header',
      severity: 'HIGH',
      title: 'Página não retornou resposta',
      description: `A navegação para ${url} não retornou resposta.`,
      location: url,
      remediation: 'Verifique se a URL está acessível e retorna uma resposta HTTP válida.',
    });
    return findings;
  }

  const headers = response.headers();
  const statusCode = response.status();

  if (statusCode >= 400) {
    findings.push({
      type: 'missing_header',
      severity: statusCode >= 500 ? 'HIGH' : 'MEDIUM',
      title: `Resposta HTTP ${statusCode}`,
      description: `A página retornou HTTP ${statusCode}.`,
      location: url,
      remediation: 'Verifique se a URL está correta e acessível.',
      metadata: { statusCode },
    });
  }

  // ── Detect managed hosting (user can't configure server headers) ──
  const serverHeader = headers['server'] || '';
  const viaHeader = headers['via'] || '';
  const poweredBy = headers['x-powered-by'] || '';
  const urlLower = url.toLowerCase();
  const isManagedHosting =
    urlLower.includes('.lovable.app') ||
    urlLower.includes('.vercel.app') ||
    urlLower.includes('.netlify.app') ||
    urlLower.includes('.pages.dev') ||       // Cloudflare Pages
    urlLower.includes('.web.app') ||          // Firebase Hosting
    urlLower.includes('.firebaseapp.com') ||
    urlLower.includes('.amplifyapp.com') ||   // AWS Amplify
    urlLower.includes('.surge.sh') ||
    urlLower.includes('.render.com') ||
    serverHeader.toLowerCase().includes('vercel') ||
    serverHeader.toLowerCase().includes('cloudflare') ||
    serverHeader.toLowerCase().includes('netlify') ||
    serverHeader.toLowerCase().includes('framer') ||
    viaHeader.includes('Vercel') ||
    poweredBy.includes('Next.js');

  if (isManagedHosting) {
    console.log(`  [headers] Hosting gerenciado detectado — headers de servidor serão INFO`);
  }

  for (const check of REQUIRED_HEADERS) {
    const value = headers[check.header];

    if (!value) {
      // On managed hosting, missing server headers are informational (user can't fix)
      const effectiveSeverity = isManagedHosting ? 'INFO' as const : check.severity;
      findings.push({
        type: 'missing_header',
        severity: effectiveSeverity,
        title: check.title,
        description: `O header ${check.header} está ausente.${isManagedHosting ? ' (limitação do hosting gerenciado)' : ''}`,
        location: url,
        remediation: isManagedHosting
          ? `Header configurável apenas no servidor/CDN. Em hosting gerenciado, esta configuração não está disponível.`
          : check.remediation,
        metadata: { header: check.header, ai_prompt: check.aiPrompt, managedHosting: isManagedHosting || undefined },
      });
    } else if (check.validate && !check.validate(value)) {
      findings.push({
        type: 'insecure_header',
        severity: check.severity,
        title: `${check.header} com valor inseguro`,
        description: `Valor: ${value}`,
        location: url,
        remediation: check.remediation,
        metadata: { header: check.header, value, ai_prompt: check.aiPrompt },
      });
    }
  }

  for (const check of INSECURE_VALUES) {
    const value = headers[check.header];
    if (value && check.pattern.test(value)) {
      const effectiveSeverity = isManagedHosting ? 'INFO' as const : check.severity;
      findings.push({
        type: 'insecure_header',
        severity: effectiveSeverity,
        title: check.title,
        description: `${check.header}: ${value}${isManagedHosting ? ' (limitação do hosting gerenciado)' : ''}`,
        location: url,
        remediation: isManagedHosting
          ? 'Header definido pelo provedor de hosting/CDN. Em infraestrutura gerenciada, esta configuração não pode ser alterada.'
          : check.remediation,
        metadata: { header: check.header, value, ai_prompt: check.aiPrompt, managedHosting: isManagedHosting || undefined },
      });
    }
  }

  return findings;
}
