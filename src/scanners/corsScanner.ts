import { Page } from 'puppeteer';
import { Finding } from '../types/findings';

export async function scanCors(page: Page, url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const corsResults = await page.evaluate(async (targetUrl: string) => {
    const results: {
      origin: string;
      allowOrigin: string | null;
      allowCredentials: string | null;
      allowMethods: string | null;
      error?: string;
    }[] = [];

    const testOrigins = ['https://evil.com', 'https://attacker.example.com', 'null'];

    for (const origin of testOrigins) {
      try {
        const res = await fetch(targetUrl, {
          method: 'OPTIONS', headers: { Origin: origin }, mode: 'cors',
        });
        results.push({
          origin,
          allowOrigin: res.headers.get('access-control-allow-origin'),
          allowCredentials: res.headers.get('access-control-allow-credentials'),
          allowMethods: res.headers.get('access-control-allow-methods'),
        });
      } catch {
        try {
          const res = await fetch(targetUrl, {
            method: 'GET', headers: { Origin: origin }, mode: 'cors',
          });
          results.push({
            origin,
            allowOrigin: res.headers.get('access-control-allow-origin'),
            allowCredentials: res.headers.get('access-control-allow-credentials'),
            allowMethods: res.headers.get('access-control-allow-methods'),
          });
        } catch (err2: unknown) {
          results.push({
            origin, allowOrigin: null, allowCredentials: null, allowMethods: null,
            error: err2 instanceof Error ? err2.message : String(err2),
          });
        }
      }
    }
    return results;
  }, url);

  for (const result of corsResults) {
    if (!result.allowOrigin) continue;

    if (result.allowOrigin === '*') {
      findings.push({
        type: 'cors_misconfiguration',
        severity: result.allowCredentials === 'true' ? 'CRITICAL' : 'HIGH',
        title: 'CORS permite qualquer origem (wildcard *)',
        description: `Access-Control-Allow-Origin: * permite que qualquer site leia respostas.${
          result.allowCredentials === 'true' ? ' Combinado com Allow-Credentials: true, isso é CRÍTICO.' : ''
        }`,
        location: url,
        remediation: 'Substitua o wildcard por uma lista de origens confiáveis.',
        metadata: {
          origin: result.origin, allowOrigin: result.allowOrigin, allowCredentials: result.allowCredentials,
          ai_prompt:
            'A configuração de CORS está usando Access-Control-Allow-Origin: * (wildcard), permitindo que qualquer site leia as respostas da API. ' +
            "Corrija para aceitar apenas as origens da sua aplicação. Se Express, configure o middleware cors com origin: ['https://meusite.com'].",
        },
      });
      break;
    }

    if (result.allowOrigin === result.origin) {
      findings.push({
        type: 'cors_misconfiguration',
        severity: 'CRITICAL',
        title: 'CORS reflete origem arbitrária',
        description: `O servidor reflete o header Origin (${result.origin}) no Access-Control-Allow-Origin.`,
        location: url,
        remediation: 'Valide o header Origin contra uma lista de domínios confiáveis.',
        metadata: {
          origin: result.origin, allowOrigin: result.allowOrigin,
          ai_prompt:
            `O servidor está refletindo qualquer Origin recebido no header Access-Control-Allow-Origin (testado com ${result.origin}). ` +
            'Corrija validando o Origin contra uma whitelist fixa de domínios permitidos antes de incluí-lo na resposta.',
        },
      });
      break;
    }

    if (result.origin === 'null' && result.allowOrigin === 'null') {
      findings.push({
        type: 'cors_misconfiguration',
        severity: 'HIGH',
        title: 'CORS permite origem null',
        description: 'O servidor permite Origin: null, que pode ser disparado por iframes sandboxed.',
        location: url,
        remediation: 'Não permita null como origem válida.',
        metadata: {
          origin: result.origin, allowOrigin: result.allowOrigin,
          ai_prompt: 'A configuração de CORS aceita Origin: null. Remova null da lista de origens permitidas.',
        },
      });
    }
  }

  return findings;
}
