import { Page } from 'puppeteer';
import { Finding, SecretPattern } from '../types/findings';

interface SecretPatternWithPrompt extends SecretPattern {
  aiPrompt: string;
}

const SECRET_PATTERNS: readonly SecretPatternWithPrompt[] = [
  {
    name: 'AWS_ACCESS_KEY', regex: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL',
    remediation: 'Rotacione a chave AWS imediatamente e remova do frontend.',
    aiPrompt:
      'Foi encontrada uma chave AWS Access Key (AKIA...) exposta no código client-side. ' +
      'Remova imediatamente qualquer referência a esta chave no frontend. ' +
      'Se precisar chamar serviços AWS, crie uma Edge Function ou rota de API server-side que ' +
      'use a chave como variável de ambiente e exponha apenas um endpoint seguro para o frontend.',
  },
  {
    name: 'AWS_SECRET_KEY', regex: /(?:aws_secret_access_key|AWS_SECRET)['": \s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'CRITICAL',
    remediation: 'Rotacione a chave secreta AWS e mova para server-side.',
    aiPrompt:
      'A chave secreta AWS (aws_secret_access_key) está exposta no código client-side. ' +
      'Remova-a completamente do frontend. Nunca inclua chaves secretas AWS em código que roda no navegador. ' +
      'Use variáveis de ambiente server-side e crie uma API intermediária.',
  },
  {
    name: 'GOOGLE_API_KEY', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'HIGH',
    remediation: 'Restrinja a chave Google no Console de APIs.',
    aiPrompt:
      'Foi encontrada uma chave de API do Google (AIza...) no frontend. ' +
      'Acesse o Google Cloud Console > Credentials e restrinja esta chave: ' +
      '1) Limite a domínios HTTP específicos (seus domínios). ' +
      '2) Restrinja a APIs específicas que o frontend realmente usa. ' +
      'Se a chave é usada para serviços sensíveis (Gemini, Cloud Functions), mova para o backend.',
  },
  {
    name: 'FIREBASE_CONFIG', regex: /firebase[A-Za-z]*\.initializeApp\s*\(\s*\{[^}]*apiKey\s*:\s*['"]([^'"]+)['"]/gi, severity: 'MEDIUM',
    remediation: 'Chaves Firebase são públicas por design, mas garanta as regras de segurança.',
    aiPrompt:
      'A configuração do Firebase (apiKey) foi encontrada no frontend. Isso é normal e esperado. ' +
      'Porém, garanta que as Firebase Security Rules estão configuradas corretamente no Firestore, ' +
      'Realtime Database e Storage para impedir acesso não autorizado. ' +
      'Verifique: Firebase Console > Firestore > Rules.',
  },
  {
    name: 'SUPABASE_JWT', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: 'HIGH',
    remediation: 'Verifique se é service_role (acesso total) ou anon (seguro).',
    aiPrompt:
      'Foi encontrado um JWT do Supabase no código client-side. Verifique se é uma chave service_role ' +
      '(que ignora todo o RLS e dá acesso total ao banco). Se for service_role: ' +
      '1) Remova do frontend imediatamente. 2) Rotacione no Supabase Dashboard > Settings > API. ' +
      '3) Mova para uma Edge Function que use a chave como variável de ambiente. ' +
      'Se for chave anon: é segura para uso no frontend, mas certifique-se de que o RLS está ativo em todas as tabelas.',
  },
  {
    name: 'STRIPE_SECRET', regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'CRITICAL',
    remediation: 'Rotacione a chave secreta Stripe IMEDIATAMENTE.',
    aiPrompt:
      'URGENTE: A chave secreta do Stripe (sk_live_...) está exposta no frontend. ' +
      'Com esta chave, qualquer pessoa pode fazer cobranças, reembolsos e acessar dados de pagamento. ' +
      '1) Rotacione a chave no Stripe Dashboard > Developers > API Keys. ' +
      '2) Remova toda referência a sk_live do código client-side. ' +
      '3) Crie uma rota de API server-side para processar pagamentos. ' +
      'O frontend deve usar apenas a chave pública (pk_live).',
  },
  {
    name: 'STRIPE_PUBLIC', regex: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'LOW',
    remediation: 'Chaves públicas Stripe (pk_live) são seguras para uso no frontend.',
    aiPrompt: '',
  },
  {
    name: 'PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'CRITICAL',
    remediation: 'Remova a chave privada do frontend IMEDIATAMENTE.',
    aiPrompt:
      'CRÍTICO: Foi encontrada uma chave privada (-----BEGIN PRIVATE KEY-----) no código client-side. ' +
      'Chaves privadas NUNCA devem existir no frontend. Remova completamente e mova para variáveis de ambiente server-side. ' +
      'Se esta chave é usada para assinar tokens ou autenticação, rotacione-a imediatamente gerando um novo par de chaves.',
  },
  {
    name: 'GENERIC_API_KEY', regex: /(?:api[_-]?key|apikey|api[_-]?secret)['": \s]*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"]?/gi, severity: 'HIGH',
    remediation: 'Mova a chave de API para o backend.',
    aiPrompt:
      'Foi encontrada uma chave de API genérica exposta no código client-side. ' +
      'Mova esta chave para variáveis de ambiente server-side. ' +
      'Crie uma rota de API (Edge Function ou backend) que use a chave internamente e ' +
      'exponha apenas o resultado para o frontend via um endpoint autenticado.',
  },
  {
    name: 'GENERIC_SECRET', regex: /(?:secret|token|password|passwd|pwd)['": \s]*[=:]\s*['"]([a-zA-Z0-9_\-!@#$%^\&*]{8,})['"]?/gi, severity: 'MEDIUM',
    remediation: 'Verifique se é uma credencial real e mova para server-side.',
    aiPrompt:
      'Foi encontrado um possível segredo (secret/token/password) no código client-side. ' +
      'Verifique se é uma credencial real ou apenas um placeholder. Se for real: ' +
      '1) Remova do código frontend. 2) Mova para variável de ambiente server-side. ' +
      '3) Se é um token de API, crie uma rota backend para intermediar as chamadas.',
  },
];

function isServiceRoleJWT(token: string): boolean {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    return payload.role === 'service_role';
  } catch {
    return false;
  }
}

export async function scanSecrets(page: Page, url: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const pageContent = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script'))
      .map((s) => s.textContent || '')
      .join('\n');
    const metas = Array.from(document.querySelectorAll('meta'))
      .map((m) => `${m.getAttribute('name')}=${m.getAttribute('content')}`)
      .join('\n');
    return { scripts, metas, html: document.documentElement.outerHTML };
  });

  const allContent = `${pageContent.scripts}\n${pageContent.metas}\n${pageContent.html}`;

  const scriptSources: string[] = [];
  try {
    const scriptUrls = await page.evaluate(() =>
      Array.from(document.querySelectorAll('script[src]'))
        .map((s) => s.getAttribute('src'))
        .filter(Boolean) as string[]
    );
    for (const src of scriptUrls.slice(0, 10)) {
      try {
        const absoluteUrl = new URL(src, url).href;
        const response = await page.evaluate(async (u) => {
          try {
            const res = await fetch(u);
            return await res.text();
          } catch { return ''; }
        }, absoluteUrl);
        if (response) scriptSources.push(response);
      } catch {}
    }
  } catch {}

  const fullContent = allContent + '\n' + scriptSources.join('\n');

  for (const pattern of SECRET_PATTERNS) {
    const matches = fullContent.matchAll(pattern.regex);
    const seen = new Set<string>();

    for (const match of matches) {
      const value = match[1] || match[0];
      if (seen.has(value)) continue;
      seen.add(value);

      if (pattern.name === 'SUPABASE_JWT') {
        if (!isServiceRoleJWT(match[0])) continue;
      }

      if (value.length < 10) continue;
      if (/^(true|false|null|undefined|none|test|example|demo|placeholder)$/i.test(value)) continue;

      // ── False positive filters for GENERIC patterns ──
      if (pattern.name === 'GENERIC_SECRET' || pattern.name === 'GENERIC_API_KEY') {
        // Skip common programming identifiers (not real secrets)
        if (/^(access_token|refresh_token|id_token|csrf_token|auth_token|session_token|token_type|password_hash|password_reset|secret_key|secret_name|api_key_id|apikey_header)$/i.test(value)) continue;

        // Skip values that look like common env var references or SDK method names
        if (/^(VITE_|NEXT_PUBLIC_|REACT_APP_|process\.env)/i.test(value)) continue;

        // Skip HTML form field attribute values (type="password", name="token", placeholder="Enter your secret")
        const matchContext = fullContent.substring(
          Math.max(0, (match.index ?? 0) - 80),
          Math.min(fullContent.length, (match.index ?? 0) + match[0].length + 30)
        );
        if (/(?:type|name|placeholder|autocomplete|id|for|aria-label)\s*=\s*["'][^"']*$/i.test(
          matchContext.substring(0, matchContext.indexOf(match[0]))
        )) continue;

        // Skip common UI/label strings
        if (/^(password|token|secret|confirm_password|new_password|old_password|current_password|reset_password|forgot_password)$/i.test(value)) continue;

        // Skip values that are just repeated characters or sequential
        if (/^(.)\1+$/.test(value)) continue; // "aaaaaaaaaa"
        if (/^(0123456789|abcdefghij|1234567890)/.test(value)) continue;

        // Skip common Supabase/Firebase public key names
        if (/^(supabase_url|supabase_key|supabase_anon|publishable_key|public_key|anon_key)$/i.test(value)) continue;
      }

      findings.push({
        type: 'exposed_secret',
        severity: pattern.severity,
        title: `${pattern.name} exposta no frontend`,
        description: `Encontrada potencial ${pattern.name} no código client-side: ${value.substring(0, 20)}...`,
        location: url,
        remediation: pattern.remediation,
        metadata: {
          pattern: pattern.name,
          snippet: value.substring(0, 40),
          ai_prompt: pattern.aiPrompt || undefined,
        },
      });
    }
  }

  return findings;
}
