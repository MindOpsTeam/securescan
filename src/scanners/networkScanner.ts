import { Page } from 'puppeteer';
import { Finding } from '../types/findings';

interface CapturedRequest {
  url: string;
  method: string;
  resourceType: string;
  headers: Record<string, string>;
  postData: string | null;
}

interface CapturedResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
}

export interface NetworkCapture {
  requests: CapturedRequest[];
  responses: CapturedResponse[];
}

export async function scanNetwork(page: Page, url: string, capture: NetworkCapture): Promise<Finding[]> {
  const findings: Finding[] = [];
  const reportedIssues = new Set<string>();

  for (const req of capture.requests) {
    try {
      const parsed = new URL(req.url);
      for (const [key, value] of parsed.searchParams.entries()) {
        const isExcludedKey = /pubkey|public_key|publickey|sitekey|recaptcha/i.test(key);
        if (!isExcludedKey && /token|key|secret|password|auth|session|jwt/i.test(key) && value.length > 10) {
          const issueKey = `token_querystring_${key}`;
          if (!reportedIssues.has(issueKey)) {
            reportedIssues.add(issueKey);
            findings.push({
              type: 'exposed_secret',
              severity: 'HIGH',
              title: `Token de autenticação enviado na URL: "${key}"`,
              description: `Um token/chave está sendo passado como parâmetro de query (${key}=${value.substring(0, 15)}...). Parâmetros de query ficam em logs, histórico e proxies.`,
              location: req.url.substring(0, 100) + '...',
              remediation: 'Envie tokens no header Authorization ao invés de parâmetros de URL.',
              metadata: {
                parameter: key, method: req.method,
                ai_prompt:
                  `O parâmetro '${key}' está sendo enviado na URL como query string. ` +
                  'Mova para o header Authorization: Bearer <token>. ' +
                  'Se usar Supabase, garanta que o SDK está enviando a chave no header apikey.',
              },
            });
          }
        }
      }
    } catch {}

    if (req.url.startsWith('http://') && !req.url.includes('localhost') && !req.url.includes('127.0.0.1')) {
      const issueKey = `insecure_http_${new URL(req.url).hostname}`;
      if (!reportedIssues.has(issueKey)) {
        reportedIssues.add(issueKey);
        const hasAuth = !!req.headers['authorization'] || !!req.headers['cookie'];
        findings.push({
          type: 'insecure_header',
          severity: hasAuth ? 'CRITICAL' : 'MEDIUM',
          title: `Requisição HTTP insegura${hasAuth ? ' com credenciais' : ''}`,
          description: `Requisição para ${req.url.substring(0, 80)} usa HTTP puro. ${hasAuth ? 'Credenciais estão sendo enviadas sem criptografia!' : 'Dados podem ser interceptados.'}`,
          location: url,
          remediation: 'Garanta que todas as chamadas de API usem HTTPS.',
          metadata: {
            targetUrl: req.url.substring(0, 100), hasCredentials: hasAuth,
            ai_prompt:
              'Foram detectadas requisições HTTP (sem criptografia). ' +
              'Altere todas as URLs de API para usar https://. Configure o header HSTS.',
          },
        });
      }
    }

    const authHeader = req.headers['authorization'];
    if (authHeader) {
      const bearerMatch = authHeader.match(/Bearer\s+(.+)/i);
      if (bearerMatch) {
        try {
          const payload = JSON.parse(Buffer.from(bearerMatch[1].split('.')[1], 'base64url').toString());
          if (payload.role === 'service_role') {
            findings.push({
              type: 'exposed_secret',
              severity: 'CRITICAL',
              title: '🚨 Chave service_role enviada pelo navegador!',
              description: `Um JWT service_role do Supabase está sendo enviado em uma requisição do navegador para ${req.url.substring(0, 60)}.`,
              location: url,
              remediation: 'Chaves service_role NUNCA devem ser usadas no frontend.',
              metadata: {
                targetUrl: req.url.substring(0, 100),
                ai_prompt:
                  'URGENTE: A chave service_role do Supabase está sendo enviada pelo navegador. ' +
                  '1) Remova a variável VITE_SUPABASE_SERVICE_ROLE do .env do frontend. ' +
                  '2) Rotacione a chave no Supabase Dashboard > Settings > API. ' +
                  '3) O frontend deve usar APENAS a chave anon. ' +
                  '4) Para operações privilegiadas, crie uma Supabase Edge Function.',
              },
            });
          }
        } catch {}
      }
    }
  }

  const thirdPartyAPIs = new Map<string, { count: number; hasAuth: boolean }>();
  for (const req of capture.requests) {
    try {
      const hostname = new URL(req.url).hostname;
      const pageHostname = new URL(url).hostname;
      if (hostname === pageHostname) continue;
      if (/cdn|static|assets|fonts|analytics|google-analytics|googletagmanager/.test(hostname)) continue;
      if (!thirdPartyAPIs.has(hostname)) thirdPartyAPIs.set(hostname, { count: 0, hasAuth: false });
      const entry = thirdPartyAPIs.get(hostname)!;
      entry.count++;
      if (req.headers['authorization'] || req.headers['x-api-key']) entry.hasAuth = true;
    } catch {}
  }

  for (const [hostname, info] of thirdPartyAPIs) {
    if (info.hasAuth && !hostname.includes('supabase.co')) {
      findings.push({
        type: 'exposed_secret',
        severity: 'MEDIUM',
        title: `Chamadas API autenticadas para terceiro: ${hostname}`,
        description: `${info.count} requisição(ões) para ${hostname} incluem headers de autenticação.`,
        location: url,
        remediation: 'Considere encaminhar chamadas autenticadas a APIs de terceiros pelo seu backend.',
        metadata: {
          hostname, requestCount: info.count,
          ai_prompt:
            `A aplicação está fazendo chamadas autenticadas diretamente do navegador para ${hostname}. ` +
            'Crie uma rota de API server-side que intermedie estas chamadas.',
        },
      });
    }
  }

  return findings;
}
