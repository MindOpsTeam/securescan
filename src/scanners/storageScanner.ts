import { Page } from 'puppeteer';
import { Finding } from '../types/findings';

export async function scanStorage(page: Page, url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const storageData = await page.evaluate(() => {
    const lsKeys: string[] = [];
    const ssKeys: string[] = [];
    const lsItems: Record<string, string> = {};
    const ssItems: Record<string, string> = {};
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) { lsKeys.push(key); lsItems[key] = (localStorage.getItem(key) || '').substring(0, 200); }
      }
    } catch {}
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) { ssKeys.push(key); ssItems[key] = (sessionStorage.getItem(key) || '').substring(0, 200); }
      }
    } catch {}
    return { lsKeys, ssKeys, lsItems, ssItems };
  });

  const sensitivePatterns = [
    { pattern: /token|jwt|auth|session|password|secret|key|credential/i, severity: 'HIGH' as const },
    { pattern: /credit.?card|ssn|social.?sec/i, severity: 'CRITICAL' as const },
  ];

  for (const key of storageData.lsKeys) {
    // Ignora chaves de marketing comuns, chaves com ":" (plugins) e analytics sessions
    const isIgnoredKey = /^(_ga|_fbp|_hjid|amp_|mixpanel_|intercom_|eng_|optimizely|rdstation|hubspot)/i.test(key) || 
                         key.includes(':') || 
                         /session.?data|tracking/i.test(key);
    if (isIgnoredKey) continue;

    for (const sp of sensitivePatterns) {
      if (sp.pattern.test(key) || sp.pattern.test(storageData.lsItems[key] || '')) {
        findings.push({
          type: 'insecure_storage',
          severity: sp.severity,
          title: `Dados sensíveis no localStorage: "${key}"`,
          description: `Encontrados dados potencialmente sensíveis armazenados no localStorage na chave "${key}".`,
          location: url,
          remediation: 'Migre tokens de autenticação para cookies HttpOnly ao invés de localStorage.',
          metadata: {
            storage: 'localStorage', key, preview: storageData.lsItems[key]?.substring(0, 50),
            ai_prompt:
              `A chave "${key}" está sendo armazenada no localStorage, que é acessível por qualquer JavaScript na página (incluindo XSS). ` +
              'Migre tokens de autenticação para cookies HttpOnly. Se usando Supabase, configure o storage adapter para usar cookies: ' +
              "createBrowserClient(url, key, { auth: { flowType: 'pkce', storage: cookieStorage } }). " +
              'Se for um framework como Next.js, use @supabase/ssr para gerenciar a sessão via cookies automaticamente.',
          },
        });
        break;
      }
    }
  }

  const cookies = await page.cookies();

  // Whitelist abrangente de cookies de terceiros (analytics, marketing, A/B testing)
  const THIRD_PARTY_COOKIE_RE = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_hjid|_hj|_clck|_clsk|_tt_|_pin_|_uet|ajs_|amp_|mixpanel|intercom|eng_|optimizely|rdstation|hubspot|vwo_|ph_|__cf)/i;

  for (const cookie of cookies) {
    if (THIRD_PARTY_COOKIE_RE.test(cookie.name)) continue;
    if (!cookie.httpOnly && /session|token|auth|sid|jwt/i.test(cookie.name)) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'HIGH',
        title: `Cookie "${cookie.name}" não é HttpOnly`,
        description: `O cookie "${cookie.name}" parece ser de sessão/auth mas não possui a flag HttpOnly. Pode ser roubado via XSS.`,
        location: url,
        remediation: 'Defina a flag HttpOnly em cookies de autenticação.',
        metadata: {
          cookie: cookie.name, domain: cookie.domain,
          ai_prompt:
            `O cookie de autenticação '${cookie.name}' não possui a flag HttpOnly. ` +
            `Ao criar este cookie no servidor, adicione: Set-Cookie: ${cookie.name}=...; HttpOnly; Secure; SameSite=Lax.`,
        },
      });
    }

    // Secure flag só é relevante para cookies de autenticação/sessão
    if (!cookie.secure && cookie.domain && !cookie.domain.includes('localhost') && /session|token|auth|sid|jwt/i.test(cookie.name)) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'MEDIUM',
        title: `Cookie "${cookie.name}" sem flag Secure`,
        description: `O cookie "${cookie.name}" pode ser enviado em conexões HTTP não criptografadas.`,
        location: url,
        remediation: 'Defina a flag Secure em todos os cookies de autenticação.',
        metadata: {
          cookie: cookie.name, domain: cookie.domain,
          ai_prompt: `O cookie '${cookie.name}' não tem a flag Secure. Adicione a flag na configuração para garantir envio apenas via HTTPS.`,
        },
      });
    }

    if ((!cookie.sameSite || cookie.sameSite === 'None') && /session|token|auth|sid|jwt/i.test(cookie.name)) {
      findings.push({
        type: 'insecure_cookie',
        severity: 'MEDIUM',
        title: `Cookie "${cookie.name}" com SameSite=None`,
        description: `O cookie "${cookie.name}" pode ser enviado em requisições cross-site, habilitando ataques CSRF.`,
        location: url,
        remediation: 'Defina SameSite=Lax ou Strict em cookies de autenticação.',
        metadata: {
          cookie: cookie.name, sameSite: cookie.sameSite,
          ai_prompt: `O cookie '${cookie.name}' tem SameSite=None. Altere para SameSite=Lax ou SameSite=Strict.`,
        },
      });
    }
  }

  return findings;
}
