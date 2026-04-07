import { Page, HTTPRequest, HTTPResponse } from 'puppeteer';
import {
  Finding,
  Severity,
  SupabaseInstance,
  JWTInfo,
  TableProbeResult,
  RedactedRow,
} from '../types/findings';

// ────────────────── Phase 1: Network Interception ──────────────────

/**
 * Intercepta requests/responses para encontrar URLs e chaves Supabase.
 * 
 * 🔴 FIX P0: O buffer de scripts agora é LOCAL (closure), não global.
 * Cada chamada de setupNetworkCapture cria seu próprio array isolado,
 * eliminando a race condition entre jobs concorrentes no BrowserPool.
 */
export function setupNetworkCapture(page: Page) {
  const instances: SupabaseInstance[] = [];
  const seenUrls = new Set<string>();
  const capturedRequests: { url: string; auth: string | null; body: string | null }[] = [];
  const localScriptContents: string[] = [];
  const localScriptUrls: string[] = [];

  const requestHandler = (req: HTTPRequest) => {
    const url = req.url();

    // Captura requests para Supabase
    if (url.includes('.supabase.co')) {
      const auth = req.headers()['authorization'] || req.headers()['apikey'] || null;
      let body: string | null = null;
      try { body = req.postData() || null; } catch { }

      capturedRequests.push({ url, auth, body });

      // Extrai project URL
      const match = url.match(/(https:\/\/[a-z0-9]+\.supabase\.co)/);
      if (match && !seenUrls.has(match[1])) {
        seenUrls.add(match[1]);

        // Extrai anon key do Authorization header
        let anonKey: string | null = null;
        if (auth) {
          const bearerMatch = auth.match(/Bearer\s+(.+)/i);
          anonKey = bearerMatch ? bearerMatch[1] : auth;
        }

        // Tenta pegar apikey do query param
        if (!anonKey) {
          try {
            const parsed = new URL(url);
            anonKey = parsed.searchParams.get('apikey');
          } catch { }
        }

        instances.push({
          projectUrl: match[1],
          anonKey,
          source: 'network_request',
        });
      }
    }
  };

  // Captura conteúdo das responses de scripts JS (onde ficam as credenciais em SPAs)
  const responseHandler = async (res: HTTPResponse) => {
    try {
      const url = res.url();
      const contentType = res.headers()['content-type'] || '';
      // Captura .js bundles e respostas com content-type javascript
      if (url.endsWith('.js') || url.endsWith('.mjs') || contentType.includes('javascript')) {
        const text = await res.text().catch(() => '');
        if (text && text.length < 10_000_000) { // Max 10MB por script
          localScriptContents.push(text);
          localScriptUrls.push(url);
        }
      }
    } catch { }
  };

  page.on('request', requestHandler);
  page.on('response', responseHandler);

  return {
    getInstances: () => instances,
    getCapturedRequests: () => capturedRequests,
    getCapturedScripts: () => localScriptContents,
    getCapturedScriptUrls: () => localScriptUrls,
    cleanup: () => {
      page.off('request', requestHandler);
      page.off('response', responseHandler);
    },
  };
}

// ────────────────── Phase 2: Source Code Extraction ──────────────────

/**
 * Busca Supabase URLs e keys no código-fonte da página (JS bundles, inline scripts, meta tags).
 */
async function extractFromSourceCode(page: Page, scriptContents: string[] = []): Promise<SupabaseInstance[]> {
  const instances: SupabaseInstance[] = [];

  // Phase A: Buscar no DOM (HTML inline + scripts inline)
  const extracted = await page.evaluate(() => {
    const results: { url: string; key: string | null; source: string }[] = [];

    // 1. HTML + inline scripts
    const allText = document.documentElement.outerHTML;

    // Supabase URLs
    const urlPattern = /https:\/\/([a-z0-9]+)\.supabase\.co/g;
    const urls = new Set<string>();
    let urlMatch;
    while ((urlMatch = urlPattern.exec(allText)) !== null) {
      urls.add(`https://${urlMatch[1]}.supabase.co`);
    }

    // Supabase anon keys (JWT pattern: header.payload.signature)
    const jwtPattern = /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    const keys: string[] = [];
    let keyMatch;
    while ((keyMatch = jwtPattern.exec(allText)) !== null) {
      keys.push(keyMatch[0]);
    }

    // 2. window.__NEXT_DATA__, __NUXT__, etc.
    try {
      const win = window as unknown as Record<string, unknown>;
      const nextData = JSON.stringify(win.__NEXT_DATA__ || {});
      const nuxtData = JSON.stringify(win.__NUXT__ || {});
      for (const data of [nextData, nuxtData]) {
        let m;
        const up = /https:\/\/([a-z0-9]+)\.supabase\.co/g;
        while ((m = up.exec(data)) !== null) urls.add(`https://${m[1]}.supabase.co`);
        const kp = /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
        let km;
        while ((km = kp.exec(data)) !== null) keys.push(km[0]);
      }
    } catch { }

    // Combine
    for (const url of urls) {
      const matchingKey = keys.length > 0 ? keys[0] : null;
      results.push({ url, key: matchingKey, source: 'inline_html' });
    }

    return results;
  });

  for (const item of extracted) {
    instances.push({
      projectUrl: item.url,
      anonKey: item.key,
      source: item.source,
    });
  }

  // Phase C: Proactively fetch JS chunks that contain "supabase" in filename
  // (Vite/React code-split apps lazy-load these, so network capture may miss them)
  try {
    const supabaseScriptUrls = await page.evaluate(() => {
      const urls: string[] = [];
      // Check script tags
      document.querySelectorAll('script[src]').forEach(s => {
        const src = s.getAttribute('src') || '';
        if (src.toLowerCase().includes('supabase')) {
          urls.push(src.startsWith('http') ? src : new URL(src, window.location.origin).href);
        }
      });
      // Also check modulepreload links (Vite uses these)
      document.querySelectorAll('link[rel="modulepreload"][href]').forEach(l => {
        const href = l.getAttribute('href') || '';
        if (href.toLowerCase().includes('supabase')) {
          urls.push(href.startsWith('http') ? href : new URL(href, window.location.origin).href);
        }
      });
      return urls;
    });

    if (supabaseScriptUrls.length > 0) {
      console.log(`    [supabase] Found ${supabaseScriptUrls.length} Supabase-related script(s), fetching...`);
      for (const scriptUrl of supabaseScriptUrls) {
        try {
          const resp = await page.evaluate(async (url: string) => {
            const r = await fetch(url);
            return await r.text();
          }, scriptUrl);
          if (resp && resp.length < 5_000_000) {
            scriptContents.push(resp);
            console.log(`    [supabase] Fetched ${scriptUrl.split('/').pop()} (${(resp.length / 1024).toFixed(0)}KB)`);
          }
        } catch { }
      }
    }
  } catch { }

  // Phase B: Buscar nos JS bundles capturados (onde SPAs guardam as credenciais)
  const allUrls = new Set<string>(instances.map(i => i.projectUrl));
  const allKeys: string[] = instances.filter(i => i.anonKey).map(i => i.anonKey!);

  for (const scriptText of scriptContents) {
    // Pattern 1: Direct Supabase URLs
    const urlPattern = /https:\/\/([a-z0-9]+)\.supabase\.co/g;
    let m;
    while ((m = urlPattern.exec(scriptText)) !== null) {
      const u = `https://${m[1]}.supabase.co`;
      if (!allUrls.has(u)) {
        allUrls.add(u);
      }
    }

    // Pattern 2: Supabase URLs in minified/escaped strings (e.g., "https:\/\/xxx.supabase.co")
    const escapedUrlPattern = /https:\\?\/?\\?\/?([a-z0-9]+)\.supabase\.co/g;
    while ((m = escapedUrlPattern.exec(scriptText)) !== null) {
      const u = `https://${m[1]}.supabase.co`;
      if (!allUrls.has(u)) {
        allUrls.add(u);
      }
    }

    // Pattern 3: Concatenated URLs (e.g., "https://"+projectRef+".supabase.co")
    // Look for .supabase.co fragments and try to extract the project ref nearby
    const fragPattern = /["']([a-z0-9]{20,})["'].*?\.supabase\.co|\.supabase\.co.*?["']([a-z0-9]{20,})["']/g;
    while ((m = fragPattern.exec(scriptText)) !== null) {
      const ref = m[1] || m[2];
      if (ref) {
        const u = `https://${ref}.supabase.co`;
        if (!allUrls.has(u)) {
          allUrls.add(u);
        }
      }
    }

    // Pattern 4: Look for Supabase project refs as standalone strings near createClient or SUPABASE
    const contextPattern = /(?:SUPABASE|supabase|createClient)[^"']*["']([a-z0-9]{20,})["']/gi;
    while ((m = contextPattern.exec(scriptText)) !== null) {
      // Check if this looks like a project ref (lowercase alphanumeric, 20+ chars)
      if (/^[a-z0-9]{20,}$/.test(m[1])) {
        const u = `https://${m[1]}.supabase.co`;
        if (!allUrls.has(u)) {
          allUrls.add(u);
        }
      }
    }

    // JWT tokens nos bundles
    const jwtPattern = /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
    while ((m = jwtPattern.exec(scriptText)) !== null) {
      if (!allKeys.includes(m[0])) {
        allKeys.push(m[0]);
      }
    }
  }

  // Reconstruir instances com URLs/keys unificadas
  const seenProjectUrls = new Set<string>(instances.map(i => i.projectUrl));
  for (const url of allUrls) {
    if (!seenProjectUrls.has(url)) {
      seenProjectUrls.add(url);
      instances.push({
        projectUrl: url,
        anonKey: allKeys.length > 0 ? allKeys[0] : null,
        source: 'js_bundle',
      });
    }
  }

  // Se encontrou keys mas não associou a nenhuma instance, atualizar
  if (allKeys.length > 0) {
    for (const inst of instances) {
      if (!inst.anonKey) {
        inst.anonKey = allKeys[0];
      }
    }
  }

  if (scriptContents.length > 0) {
    console.log(`    [supabase] Analyzed ${scriptContents.length} JS bundles, found ${allUrls.size} URLs and ${allKeys.length} keys`);
  }

  return instances;
}

// ────────────────── Phase 3: Table Probing ──────────────────

// Tabelas comuns em apps Supabase / vibe-coded
const COMMON_TABLES = [
  // Auth-adjacent
  'users', 'profiles', 'accounts', 'user_profiles', 'user_settings',
  // Business data
  'posts', 'comments', 'messages', 'notifications', 'orders',
  'products', 'items', 'categories', 'tags',
  'projects', 'tasks', 'documents', 'files',
  // Payment
  'payments', 'subscriptions', 'invoices', 'plans',
  // App-specific
  'scans', 'findings', 'reports', 'logs', 'events', 'analytics',
  'teams', 'organizations', 'members', 'invitations', 'roles',
  'settings', 'configurations', 'secrets',
  // Content
  'articles', 'pages', 'media', 'uploads', 'attachments',
  // Chat
  'conversations', 'chat_messages', 'channels',
];

// Helper: fetch com timeout de 3 segundos
function fetchWithTimeout(url: string, opts: RequestInit, timeoutMs = 3000): Promise<Response> {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(timeoutMs) });
}

/**
 * Redacta um valor individual para exibição segura em findings.
 * Função pura, sem side effects.
 */
function redactValue(val: unknown): string | number | boolean | null {
  if (val === null || val === undefined) return null;
  if (typeof val === 'string') return val.length > 30 ? `${val.substring(0, 25)}...` : val;
  if (typeof val === 'number' || typeof val === 'boolean') return val;
  if (Array.isArray(val)) return `[Array(${val.length})]`;
  if (typeof val === 'object') return JSON.stringify(val).substring(0, 50);
  return String(val).substring(0, 30);
}

/**
 * Constrói array de linhas redactadas a partir de dados brutos.
 * Retorna no máximo 3 linhas para inclusão no finding.
 */
function buildSampleRows(data: unknown[]): readonly RedactedRow[] {
  return data.slice(0, 3).map((row) => {
    const typed = row as Record<string, unknown>;
    const redacted: Record<string, string | number | boolean | null> = {};
    for (const [key, val] of Object.entries(typed)) {
      redacted[key] = redactValue(val);
    }
    return redacted as RedactedRow;
  });
}

/**
 * Probe uma única tabela (SELECT, INSERT, UPDATE, DELETE).
 */
async function probeSingleTable(
  restBase: string,
  table: string,
  headers: Record<string, string>,
): Promise<TableProbeResult | null> {
  const probe: TableProbeResult = {
    table,
    select: { allowed: false, rowCount: 0, sample: null },
    insert: { allowed: false, error: null },
    update: { allowed: false, error: null },
    delete: { allowed: false, error: null },
  };

  // SELECT — fast check first
  try {
    const res = await fetchWithTimeout(`${restBase}/${table}?limit=3`, {
      method: 'GET', headers,
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) {
        probe.select.allowed = true;
        probe.select.rowCount = data.length;
        if (data.length > 0) {
          probe.select.sample = buildSampleRows(data);
        }
      }
    } else if (res.status === 404) {
      // Table doesn't exist — skip entirely (no need to test write ops)
      return null;
    }
  } catch { return null; } // Timeout or network error — skip

  // Only test write ops if SELECT succeeded (table exists and is partially exposed)
  // Or if we know the table exists from OpenAPI schema
  const [insertRes, updateRes, deleteRes] = await Promise.allSettled([
    // INSERT
    fetchWithTimeout(`${restBase}/${table}`, {
      method: 'POST',
      headers: { ...headers, 'Prefer': 'return=minimal' },
      body: JSON.stringify({ _probe: true }),
    }),
    // UPDATE (with impossible filter)
    fetchWithTimeout(`${restBase}/${table}?id=eq.00000000-0000-0000-0000-000000000000`, {
      method: 'PATCH', headers,
      body: JSON.stringify({ _probe: true }),
    }),
    // DELETE (with impossible filter)
    fetchWithTimeout(`${restBase}/${table}?id=eq.00000000-0000-0000-0000-000000000000`, {
      method: 'DELETE', headers,
    }),
  ]);

  if (insertRes.status === 'fulfilled' && insertRes.value.status === 201) {
    probe.insert.allowed = true;
  }
  if (updateRes.status === 'fulfilled' && (updateRes.value.status === 204 || updateRes.value.status === 200)) {
    probe.update.allowed = true;
  }
  if (deleteRes.status === 'fulfilled' && (deleteRes.value.status === 204 || deleteRes.value.status === 200)) {
    probe.delete.allowed = true;
  }

  // Only report accessible tables
  if (probe.select.allowed || probe.insert.allowed || probe.update.allowed || probe.delete.allowed) {
    return probe;
  }
  return null;
}

/**
 * Testa acesso a tabelas via PostgREST API.
 * Otimizado com: timeout por request, concorrência (5 por vez), OpenAPI schema priority.
 */
async function probeTablesREST(
  projectUrl: string,
  anonKey: string,
): Promise<TableProbeResult[]> {
  const results: TableProbeResult[] = [];
  const restBase = `${projectUrl}/rest/v1`;
  const headers: Record<string, string> = {
    'apikey': anonKey,
    'Authorization': `Bearer ${anonKey}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=minimal',
  };

  // 1. Tentar listar tabelas via OpenAPI schema
  let discoveredTables: string[] = [];
  try {
    const schemaRes = await fetchWithTimeout(`${restBase}/`, {
      method: 'GET',
      headers: { 'apikey': anonKey },
    }, 5000);
    if (schemaRes.ok) {
      const schema = await schemaRes.json();
      if (schema.paths) {
        discoveredTables = Object.keys(schema.paths)
          .map((p) => p.replace(/^\//, ''))
          .filter((t) => !t.startsWith('rpc/'));
      }
    }
  } catch { }

  // If we discovered tables via schema, use those + common tables
  // If schema failed, fallback to common tables only
  const allTables = discoveredTables.length > 0
    ? [...new Set([...discoveredTables, ...COMMON_TABLES])]
    : COMMON_TABLES;

  console.log(`    [supabase] Probing ${allTables.length} tables (${discoveredTables.length} from schema)...`);

  // Probe tables in batches of 5 for concurrency
  const BATCH_SIZE = 5;
  for (let i = 0; i < allTables.length; i += BATCH_SIZE) {
    const batch = allTables.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(table => probeSingleTable(restBase, table, headers))
    );
    for (const result of batchResults) {
      if (result) results.push(result);
    }
  }

  return results;
}

// ────────────────── Phase 4: JWT Analysis ──────────────────

function analyzeJWT(token: string): JWTInfo | null {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    return {
      role: payload.role || 'unknown',
      isServiceRole: payload.role === 'service_role',
      projectRef: payload.ref || 'unknown',
      issuer: payload.iss || 'unknown',
      expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'unknown',
    };
  } catch {
    return null;
  }
}

// ────────────────── Phase 5: Finding Builders (Domain Logic) ──────────────────

/**
 * Determina a severidade de uma tabela exposta baseado nas operações permitidas.
 * Função pura de regra de negócio — sem side effects.
 */
function determineSeverity(probe: TableProbeResult): Severity {
  const isSensitiveTable = /user|profile|secret|password|token|session|payment|order|invoice|credential/i
    .test(probe.table);

  if (probe.insert.allowed || probe.delete.allowed) return 'CRITICAL';
  if (probe.update.allowed) return 'HIGH';
  if (probe.select.allowed && isSensitiveTable && probe.select.rowCount > 0) return 'HIGH';
  if (probe.select.allowed && probe.select.rowCount > 0) return 'MEDIUM';
  // SELECT allowed but 0 rows → likely RLS is active and filtering (informational)
  if (probe.select.allowed && probe.select.rowCount === 0) return 'INFO';
  if (probe.select.allowed) return 'LOW';
  return 'MEDIUM';
}

/**
 * Constrói um Finding completo a partir de um TableProbeResult.
 * Encapsula construção de descrição, sample text e remediation.
 */
function buildTableFinding(
  probe: TableProbeResult,
  instance: SupabaseInstance,
  pageUrl: string,
): Finding {
  const operations: string[] = [];
  if (probe.select.allowed) operations.push(`SELECT (${probe.select.rowCount} linhas)`);
  if (probe.insert.allowed) operations.push('INSERT');
  if (probe.update.allowed) operations.push('UPDATE');
  if (probe.delete.allowed) operations.push('DELETE');

  const severity = determineSeverity(probe);

  // Build data sample for the description
  let sampleText = '';
  if (probe.select.sample && probe.select.sample.length > 0) {
    const columns = Object.keys(probe.select.sample[0]);
    sampleText = `\n\nColunas expostas: ${columns.join(', ')}`;
    sampleText += `\n\n📊 Amostra de dados expostos (${probe.select.sample.length} linha${probe.select.sample.length > 1 ? 's' : ''}):`;
    for (let i = 0; i < probe.select.sample.length; i++) {
      sampleText += `\n\nLinha ${i + 1}:`;
      sampleText += `\n${JSON.stringify(probe.select.sample[i], null, 2)}`;
    }
  }

  const description = [
    `Tabela "${probe.table}" está acessível com a chave anon.`,
    `Operações permitidas: ${operations.join(', ')}.`,
    probe.select.rowCount > 0
      ? `Contém dados (${probe.select.rowCount}+ linhas visíveis).`
      : 'Tabela aparenta estar vazia ou não retorna linhas.',
  ].filter(Boolean).join(' ') + sampleText;

  const hasWriteAccess = probe.insert.allowed || probe.update.allowed || probe.delete.allowed;

  const aiPrompt = hasWriteAccess
    ? `URGENTE: A tabela '${probe.table}' do Supabase está exposta com permissões de escrita (${operations.join(', ')}). ` +
      `Qualquer visitante pode modificar dados. Execute as seguintes queries SQL no Supabase SQL Editor:\n` +
      `1) ALTER TABLE ${probe.table} ENABLE ROW LEVEL SECURITY;\n` +
      `2) CREATE POLICY "Apenas dono pode ler" ON ${probe.table} FOR SELECT USING (auth.uid() = user_id);\n` +
      `3) CREATE POLICY "Apenas dono pode inserir" ON ${probe.table} FOR INSERT WITH CHECK (auth.uid() = user_id);\n` +
      `4) CREATE POLICY "Apenas dono pode atualizar" ON ${probe.table} FOR UPDATE USING (auth.uid() = user_id);\n` +
      `5) CREATE POLICY "Apenas dono pode deletar" ON ${probe.table} FOR DELETE USING (auth.uid() = user_id);\n` +
      `Ajuste 'user_id' para o nome real da coluna que referencia o usuário.`
    : `A tabela '${probe.table}' do Supabase está acessível publicamente via chave anon (${operations.join(', ')}). ` +
      `Se o acesso anônimo de leitura NÃO é intencional, ative o RLS:\n` +
      `1) ALTER TABLE ${probe.table} ENABLE ROW LEVEL SECURITY;\n` +
      `2) CREATE POLICY "Leitura autenticada" ON ${probe.table} FOR SELECT USING (auth.uid() IS NOT NULL);\n` +
      `Isso garante que apenas usuários logados possam ler os dados.`;

  return {
    type: 'insecure_storage',
    severity,
    title: `Tabela "${probe.table}" exposta via chave anon [${operations.join('+')}]`,
    description,
    location: `${instance.projectUrl}/rest/v1/${probe.table}`,
    remediation: hasWriteAccess
      ? `CRÍTICO: A tabela "${probe.table}" permite escrita sem autenticação. Ative o RLS imediatamente.`
      : `A tabela "${probe.table}" permite leitura anônima. Verifique se é intencional.`,
    metadata: {
      table: probe.table,
      select: probe.select.allowed,
      insert: probe.insert.allowed,
      update: probe.update.allowed,
      delete: probe.delete.allowed,
      rowCount: probe.select.rowCount,
      columns: probe.select.sample && probe.select.sample.length > 0
        ? Object.keys(probe.select.sample[0])
        : [],
      dataSample: probe.select.sample || null,
      ai_prompt: aiPrompt,
    },
  };
}

// ────────────────── Phase 6: Authenticated Probing (IDOR/RLS) ──────────────────

/**
 * Testa acesso a tabelas com o token do usuário autenticado.
 * Compara com resultados do probing anon para detectar IDOR/RLS falho.
 */
async function probeTablesAuthenticated(
  projectUrl: string,
  authenticatedToken: string,
  anonResults: TableProbeResult[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const restBase = `${projectUrl}/rest/v1`;
  const headers: Record<string, string> = {
    'apikey': authenticatedToken,
    'Authorization': `Bearer ${authenticatedToken}`,
    'Content-Type': 'application/json',
  };

  // Only probe tables that were accessible with anon key
  // We want to detect if an authenticated user sees MORE data (IDOR)
  for (const anonProbe of anonResults) {
    if (!anonProbe.select.allowed) continue;

    try {
      const res = await fetchWithTimeout(`${restBase}/${anonProbe.table}?limit=5`, {
        method: 'GET', headers,
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > anonProbe.select.rowCount) {
          findings.push({
            type: 'supabase_rls_violation',
            severity: 'HIGH',
            title: `Possível IDOR na tabela "${anonProbe.table}" — usuário autenticado vê mais dados`,
            description:
              `Com chave anon: ${anonProbe.select.rowCount} linhas visíveis. ` +
              `Com token autenticado: ${data.length}+ linhas visíveis. ` +
              `Isso pode indicar que o RLS não filtra por user_id, permitindo que um usuário veja dados de outros.`,
            location: `${projectUrl}/rest/v1/${anonProbe.table}`,
            remediation: `Possível falha de isolamento de dados (IDOR) na tabela "${anonProbe.table}". Corrija o RLS para filtrar por user_id.`,
            metadata: {
              table: anonProbe.table,
              anonRowCount: anonProbe.select.rowCount,
              authRowCount: data.length,
              ai_prompt:
                `A tabela '${anonProbe.table}' retorna mais dados para um usuário autenticado do que para acesso anônimo, ` +
                `mas sem filtrar por usuário. Corrija criando uma política RLS:\n` +
                `ALTER TABLE ${anonProbe.table} ENABLE ROW LEVEL SECURITY;\n` +
                `CREATE POLICY "Isolamento por usuário" ON ${anonProbe.table} ` +
                `FOR SELECT USING (auth.uid() = user_id);\n` +
                `Ajuste 'user_id' para o nome real da coluna que referencia o usuário.`,
            },
          });
        }
      }
    } catch { /* timeout or error — skip */ }
  }

  return findings;
}

// ────────────────── Main Scanner ──────────────────

/**
 * Scanner completo de Supabase:
 * 1. Intercepta network para encontrar Supabase URLs + keys
 * 2. Busca no source code (inline JS, env vars, bundles)
 * 3. Analisa JWT (anon vs service_role)
 * 4. Enumera tabelas via REST API
 * 5. Testa RLS (SELECT, INSERT, UPDATE, DELETE)
 * 6. Probing autenticado (IDOR/RLS) se token disponível
 */
export async function scanSupabase(
  page: Page,
  url: string,
  externalScripts?: string[],
  networkInstances?: SupabaseInstance[],
  authenticatedToken?: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Use scripts passados pelo orchestrator (capturados durante toda a navegação)
  const scripts = externalScripts ?? [];

  // Phase 1: Extract from source code + JS bundles
  const sourceInstances = await extractFromSourceCode(page, scripts);

  // Phase 2: Merge source + network-captured instances
  const seen = new Set<string>();
  const allInstances: SupabaseInstance[] = [];

  // Add source instances first
  for (const inst of sourceInstances) {
    if (!seen.has(inst.projectUrl)) {
      seen.add(inst.projectUrl);
      allInstances.push(inst);
    }
  }

  // Then add network-captured instances (from request headers — catches runtime SDK configs)
  if (networkInstances) {
    for (const inst of networkInstances) {
      if (!seen.has(inst.projectUrl)) {
        seen.add(inst.projectUrl);
        allInstances.push(inst);
      } else {
        // If we already have this URL but no key, and network has one, update
        const existing = allInstances.find(i => i.projectUrl === inst.projectUrl);
        if (existing && !existing.anonKey && inst.anonKey) {
          existing.anonKey = inst.anonKey;
          existing.source = inst.source + '+' + existing.source;
        }
      }
    }
  }

  console.log(`    [supabase] Found ${allInstances.length} Supabase instances`);

  if (allInstances.length === 0) {
    return findings; // No Supabase detected
  }

  // Phase 3: For each Supabase instance found
  for (const instance of allInstances) {
    // Finding: Supabase project URL exposed (informational — public by design)
    findings.push({
      type: 'exposed_secret',
      severity: 'INFO',
      title: `URL do projeto Supabase: ${instance.projectUrl}`,
      description: `URL do projeto Supabase encontrada em ${instance.source}. Ref do projeto: ${instance.projectUrl.split('//')[1]?.split('.')[0]}`,
      location: url,
      remediation: 'URLs de projeto Supabase são públicas por design. Garanta que o RLS está ativo em todas as tabelas.',
      metadata: { projectUrl: instance.projectUrl, source: instance.source, byDesign: true },
    });

    // Phase 4: Analyze JWT
    if (instance.anonKey) {
      const jwtInfo = analyzeJWT(instance.anonKey);

      if (jwtInfo?.isServiceRole) {
        findings.push({
          type: 'exposed_secret',
          severity: 'CRITICAL',
          title: '🚨 Chave SERVICE_ROLE do Supabase exposta no frontend!',
          description: `Uma chave service_role foi encontrada no código client-side. Esta chave ignora TODA a Row Level Security e tem acesso COMPLETO ao banco de dados. Projeto: ${jwtInfo.projectRef}\n\n🔑 Chave: ${instance.anonKey}`,
          location: url,
          remediation: 'IMEDIATAMENTE rotacione esta chave em Supabase Dashboard > Settings > API e remova do frontend.',
          metadata: {
            role: jwtInfo.role,
            projectRef: jwtInfo.projectRef,
            expiresAt: jwtInfo.expiresAt,
            key: instance.anonKey,
            ai_prompt:
              'Foi detectado um vazamento CRÍTICO de segurança. O código atual está expondo a chave SUPABASE_SERVICE_ROLE (ou VITE_SUPABASE_SERVICE_ROLE) no frontend. ' +
              'Esta chave ignora TODAS as regras de segurança do banco de dados. Por favor: ' +
              '1) Remova qualquer menção a esta chave no código client-side. ' +
              '2) O frontend deve usar APENAS a chave anon (VITE_SUPABASE_ANON_KEY). ' +
              '3) Se houver funções que exigem privilégios elevados (ex: criar usuários, enviar emails), mova-as para uma Supabase Edge Function ' +
              'que use a service_role como variável de ambiente, e chame essa função a partir do frontend via supabase.functions.invoke().',
          },
        });
      } else if (jwtInfo) {
        // Anon key is public by design — informational only
        findings.push({
          type: 'exposed_secret',
          severity: 'INFO',
          title: `Chave anon do Supabase encontrada (role: ${jwtInfo.role})`,
          description: `Chave anon detectada para o projeto ${jwtInfo.projectRef}. Isso é esperado para uso client-side — a segurança depende do RLS estar ativo.`,
          location: url,
          remediation: 'Chaves anon são públicas por design. Garanta que o RLS está habilitado em todas as tabelas.',
          metadata: {
            role: jwtInfo.role,
            projectRef: jwtInfo.projectRef,
            key: instance.anonKey,
            byDesign: true,
            ai_prompt:
              'A chave anon do Supabase foi encontrada no frontend. Isso é esperado e seguro, desde que o Row Level Security (RLS) esteja ' +
              'habilitado em TODAS as tabelas do banco. Verifique executando no SQL Editor: ' +
              "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public';. " +
              'Para qualquer tabela com rowsecurity = false, ative com: ALTER TABLE nome_tabela ENABLE ROW LEVEL SECURITY; ' +
              'e crie as políticas adequadas.',
          },
        });
      }

      // Phase 5: Table enumeration & RLS testing
      console.log(`    [supabase] Probing tables at ${instance.projectUrl}...`);
      const tableResults = await probeTablesREST(instance.projectUrl, instance.anonKey);

      for (const probe of tableResults) {
        findings.push(buildTableFinding(probe, instance, url));
      }

      if (tableResults.length === 0) {
        console.log(`    [supabase] ✅ Nenhuma tabela acessível publicamente via chave anon (${COMMON_TABLES.length}+ testadas)`);
      }

      // Phase 6: Authenticated probing (IDOR/RLS)
      if (authenticatedToken && tableResults.length > 0) {
        console.log(`    [supabase] Running authenticated probing for IDOR/RLS...`);
        const idorFindings = await probeTablesAuthenticated(
          instance.projectUrl,
          authenticatedToken,
          tableResults,
        );
        findings.push(...idorFindings);
        if (idorFindings.length > 0) {
          console.log(`    [supabase] ⚠ Found ${idorFindings.length} potential IDOR/RLS issues`);
        } else {
          console.log(`    [supabase] ✅ No IDOR/RLS issues detected with authenticated token`);
        }
      }

      // Phase 7: Auth enumeration
      if (instance.anonKey) {
        const authFindings = await probeAuthEnumeration(instance.projectUrl, instance.anonKey, url);
        findings.push(...authFindings);
      }

      // Phase 8: Storage buckets
      if (instance.anonKey) {
        const storageFindings = await probeStorageBuckets(instance.projectUrl, instance.anonKey, url);
        findings.push(...storageFindings);
      }

      // Phase 9: Edge Functions
      const edgeFunctions = await probeEdgeFunctions(instance.projectUrl, instance.anonKey, scripts, url);
      findings.push(...edgeFunctions);

      // Phase 10: Privilege escalation (requires authenticated session)
      if (authenticatedToken) {
        const privFindings = await probePrivilegeEscalation(instance.projectUrl, authenticatedToken, url);
        findings.push(...privFindings);
      }
    }
  }

  return findings;
}

// ────────────────── Phase 7: Auth Enumeration ──────────────────

/**
 * Testa se o endpoint de signup vaza informações sobre usuários existentes.
 */
async function probeAuthEnumeration(
  projectUrl: string,
  anonKey: string,
  pageUrl: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  console.log(`    [supabase] Probing auth enumeration...`);

  const probeEmail = `securescan-probe-${Date.now()}@test.invalid`;
  const probePassword = 'Pr0be!SecureScan2024#';

  try {
    // Test 1: Try signup with a fake email
    const signupRes = await fetchWithTimeout(
      `${projectUrl}/auth/v1/signup`,
      {
        method: 'POST',
        headers: {
          'apikey': anonKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: probeEmail, password: probePassword }),
      },
      5000,
    );

    const signupBody = await signupRes.json().catch(() => ({})) as Record<string, unknown>;

    if (signupRes.status === 200 && signupBody['id']) {
      // Account was actually created — open signup with no email confirmation
      findings.push({
        type: 'exposed_secret',
        severity: 'HIGH',
        title: 'Signup aberto sem confirmação de email',
        description:
          'Qualquer pessoa pode criar uma conta no Supabase sem confirmação de email. ' +
          'Isso pode ser explorado para spam, abuso de recursos ou criação massiva de contas.',
        location: `${projectUrl}/auth/v1/signup`,
        remediation: 'Habilite "Confirm email" nas configurações de autenticação do Supabase: ' +
          'Dashboard → Authentication → Providers → Email → Confirm email.',
        metadata: {
          endpoint: `${projectUrl}/auth/v1/signup`,
          status: signupRes.status,
          ai_prompt:
            'O Supabase está permitindo criação de contas sem confirmação de email. ' +
            'Para corrigir: No Supabase Dashboard → Authentication → Providers → Email, ' +
            'ative "Confirm email". Isso exige que usuários confirmem o email antes de acessar a aplicação.',
        },
      });

      // Cleanup: try to delete the test account (best effort)
      try {
        await fetchWithTimeout(
          `${projectUrl}/auth/v1/user`,
          {
            method: 'DELETE',
            headers: { 'apikey': anonKey, 'Authorization': `Bearer ${(signupBody['access_token'] as string) || ''}` },
          },
          3000,
        );
      } catch { /* cleanup failed, not critical */ }

    } else if (signupRes.status === 422) {
      const msg = String(signupBody['msg'] || signupBody['message'] || '');
      if (msg.toLowerCase().includes('already registered') || msg.toLowerCase().includes('already exists')) {
        // Signup open but email already exists — enumeration possible
        findings.push({
          type: 'exposed_secret',
          severity: 'MEDIUM',
          title: 'Enumeração de usuários possível via endpoint de signup',
          description:
            'O endpoint /auth/v1/signup retorna mensagens diferentes para emails já cadastrados vs novos. ' +
            'Um atacante pode usar isso para descobrir quais emails têm conta na aplicação.',
          location: `${projectUrl}/auth/v1/signup`,
          remediation: 'Habilite "Confirm email" para que o Supabase retorne mensagens genéricas independente do email.',
          metadata: {
            endpoint: `${projectUrl}/auth/v1/signup`,
            message: msg.substring(0, 100),
            ai_prompt:
              'O endpoint de signup está vazando informações sobre usuários cadastrados. ' +
              'Para mitigar: ative "Confirm email" no Supabase Dashboard → Authentication → Providers → Email. ' +
              'Isso fará com que o Supabase retorne sempre a mesma mensagem genérica.',
          },
        });
      } else if (msg.toLowerCase().includes('disabled') || msg.toLowerCase().includes('not allowed')) {
        // Signup disabled — good
        console.log(`    [supabase] ✅ Auth signup desabilitado`);
      }
    } else if (signupRes.status === 429) {
      // Rate limited — good sign
      console.log(`    [supabase] ✅ Auth endpoint com rate limiting`);
    }
  } catch (e) {
    console.warn(`    [supabase] Auth enumeration probe failed: ${e}`);
  }

  return findings;
}

// ────────────────── Phase 8: Storage Buckets ──────────────────

/**
 * Testa acesso a Storage buckets do Supabase via anon key.
 */
async function probeStorageBuckets(
  projectUrl: string,
  anonKey: string,
  pageUrl: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  console.log(`    [supabase] Probing storage buckets...`);

  const headers = {
    'apikey': anonKey,
    'Authorization': `Bearer ${anonKey}`,
    'Content-Type': 'application/json',
  };

  try {
    const bucketsRes = await fetchWithTimeout(
      `${projectUrl}/storage/v1/bucket`,
      { method: 'GET', headers },
      5000,
    );

    if (!bucketsRes.ok) {
      console.log(`    [supabase] ✅ Storage API não acessível anonimamente (${bucketsRes.status})`);
      return findings;
    }

    const buckets = await bucketsRes.json().catch(() => []) as Array<Record<string, unknown>>;
    if (!Array.isArray(buckets) || buckets.length === 0) {
      console.log(`    [supabase] ✅ Nenhum bucket de storage encontrado`);
      return findings;
    }

    console.log(`    [supabase] Found ${buckets.length} storage bucket(s), testing access...`);

    for (const bucket of buckets) {
      const bucketId = String(bucket['id'] || bucket['name'] || '');
      const isPublic = bucket['public'] === true;

      if (!bucketId) continue;

      // Test file listing (even in private buckets via anon key)
      const listRes = await fetchWithTimeout(
        `${projectUrl}/storage/v1/object/list/${bucketId}`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({ prefix: '', limit: 5 }),
        },
        5000,
      ).catch(() => null);

      const files = listRes?.ok
        ? (await listRes.json().catch(() => [])) as Array<Record<string, unknown>>
        : [];

      const hasFiles = Array.isArray(files) && files.length > 0;
      const hasSensitiveFiles = hasFiles && files.some((f) => {
        const name = String(f['name'] || '').toLowerCase();
        return /\.(pdf|doc|docx|xls|xlsx|csv|json|sql|key|pem|cert)$/i.test(name);
      });

      // Test anonymous upload
      let canUpload = false;
      try {
        const uploadRes = await fetchWithTimeout(
          `${projectUrl}/storage/v1/object/${bucketId}/securescan-probe-${Date.now()}.txt`,
          {
            method: 'POST',
            headers: { ...headers, 'Content-Type': 'text/plain', 'x-upsert': 'true' },
            body: 'securescan-probe-file',
          },
          5000,
        );
        canUpload = uploadRes.status === 200 || uploadRes.status === 201;
        if (canUpload) {
          // Cleanup the probe file
          await fetchWithTimeout(
            `${projectUrl}/storage/v1/object/${bucketId}/securescan-probe-${Date.now()}.txt`,
            { method: 'DELETE', headers },
            3000,
          ).catch(() => { /* cleanup failed */ });
        }
      } catch { /* upload test failed */ }

      if (canUpload) {
        findings.push({
          type: 'insecure_storage',
          severity: 'CRITICAL',
          title: `Bucket de storage "${bucketId}" aceita upload anônimo`,
          description:
            `O bucket "${bucketId}" do Supabase Storage aceita uploads de arquivos sem autenticação. ` +
            `Qualquer pessoa pode fazer upload de conteúdo malicioso.`,
          location: `${projectUrl}/storage/v1/bucket/${bucketId}`,
          remediation: 'Adicione políticas de RLS ao bucket para restringir uploads somente a usuários autenticados.',
          metadata: {
            bucket: bucketId,
            isPublic,
            ai_prompt:
              `O bucket "${bucketId}" do Supabase Storage está aceitando uploads sem autenticação. ` +
              'No SQL Editor do Supabase, execute: ' +
              `CREATE POLICY "Autenticado pode fazer upload" ON storage.objects FOR INSERT WITH CHECK (auth.uid() IS NOT NULL AND bucket_id = '${bucketId}');`,
          },
        });
      } else if (isPublic && hasSensitiveFiles) {
        findings.push({
          type: 'insecure_storage',
          severity: 'HIGH',
          title: `Bucket público "${bucketId}" contém arquivos sensíveis`,
          description:
            `O bucket "${bucketId}" é público e contém ${files.length} arquivo(s), incluindo tipos sensíveis (PDF, DOC, XLS, etc.).`,
          location: `${projectUrl}/storage/v1/object/public/${bucketId}`,
          remediation: 'Revise os arquivos no bucket. Mude o bucket para privado se os arquivos não devem ser públicos.',
          metadata: {
            bucket: bucketId,
            fileCount: files.length,
            sampleFiles: files.slice(0, 3).map((f) => f['name']),
            ai_prompt:
              `O bucket "${bucketId}" é público e contém arquivos possivelmente sensíveis. ` +
              'Para torná-lo privado: Supabase Dashboard → Storage → selecione o bucket → Edit → desative "Public bucket". ' +
              'Adicione políticas de acesso adequadas.',
          },
        });
      } else if (isPublic) {
        // Public bucket with only assets — informational
        findings.push({
          type: 'insecure_storage',
          severity: 'INFO',
          title: `Bucket público: "${bucketId}"`,
          description: `O bucket "${bucketId}" está configurado como público (por design).`,
          location: `${projectUrl}/storage/v1/object/public/${bucketId}`,
          remediation: 'Verifique se todos os arquivos neste bucket podem ser acessados publicamente.',
          metadata: { bucket: bucketId, isPublic: true, byDesign: true },
        });
      }
    }

    if (findings.filter((f) => f.severity !== 'INFO').length === 0) {
      console.log(`    [supabase] ✅ Storage buckets sem problemas críticos`);
    }
  } catch (e) {
    console.warn(`    [supabase] Storage probe failed: ${e}`);
  }

  return findings;
}

// ────────────────── Phase 9: Edge Functions ──────────────────

/** Common edge function names to probe when not found in bundles. */
const COMMON_EDGE_FUNCTION_NAMES = [
  // Auth / User
  'stripe-webhook', 'webhook', 'send-email', 'create-user', 'process-payment',
  'auth-callback', 'notify', 'upload', 'resize-image', 'generate-pdf',
  'send-notification', 'sync', 'import', 'export', 'create-checkout',
  'verify-email', 'reset-password', 'delete-user', 'invite-user', 'cron',
  'health', 'ping', 'status',
  // OAuth integrations — common in vibe-coded apps
  'google-ads-list-accounts', 'google-ads-list-campaigns', 'google-ads-metrics',
  'google-ads-report', 'google-ads-auth', 'google-ads-callback',
  'facebook-discover-accounts', 'facebook-ads-accounts', 'meta-ads-list-accounts',
  'meta-ads-campaigns', 'facebook-callback', 'meta-callback',
  'google-analytics', 'analytics-report', 'ga4-report',
  'shared-query-cache', 'query-cache',
];

/**
 * Descobre e testa Edge Functions do Supabase sem JWT verification.
 */
async function probeEdgeFunctions(
  projectUrl: string,
  anonKey: string | null,
  capturedScripts: string[],
  pageUrl: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  console.log(`    [supabase] Probing edge functions...`);

  // Discovery: extract function names from JS bundles
  const discoveredNames = new Set<string>();
  const bundleContent = capturedScripts.join('\n');

  // Pattern: supabase.functions.invoke('function-name', ...)
  const invokePattern = /functions\.invoke\(['"`]([a-z0-9-_]+)['"`]/gi;
  let match;
  while ((match = invokePattern.exec(bundleContent)) !== null) {
    discoveredNames.add(match[1]);
  }

  // Pattern: /functions/v1/function-name in URLs
  const urlPattern = /\/functions\/v1\/([a-z0-9-_]+)/gi;
  while ((match = urlPattern.exec(bundleContent)) !== null) {
    discoveredNames.add(match[1]);
  }

  // Merge discovered + common names
  const toProbe = [
    ...Array.from(discoveredNames),
    ...COMMON_EDGE_FUNCTION_NAMES.filter((n) => !discoveredNames.has(n)),
  ].slice(0, 30); // Max 30 probes

  let openFunctions = 0;

  for (const funcName of toProbe) {
    try {
      const funcUrl = `${projectUrl}/functions/v1/${funcName}`;
      const baseHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(anonKey ? { 'apikey': anonKey } : {}),
      };
      const isSensitiveFunction =
        /google|meta|facebook|stripe|payment|oauth|token|webhook|export|report|analytics|ads|crm|hubspot|salesforce|zapier|slack|twilio/i
          .test(funcName);

      // ── Step 1: GET probe ──
      const resGet = await fetchWithTimeout(funcUrl, { method: 'GET', headers: baseHeaders }, 10000);
      if (resGet.status === 404) continue;
      if (resGet.status === 401 || resGet.status === 403) continue;

      // ── Step 2: POST with empty body ──
      let finalRes = resGet;
      let finalBody = '';
      let finalPayload: Record<string, unknown> = {};

      const resPost = await fetchWithTimeout(funcUrl, {
        method: 'POST', headers: baseHeaders, body: JSON.stringify({}),
      }, 10000);

      if (resPost.status !== 401 && resPost.status !== 403 && resPost.status !== 404) {
        finalRes = resPost;
        finalBody = await resPost.text().catch(() => '');

        // ── Step 3: Adaptive — infer required fields from error and retry ──
        if (finalBody && !finalBody.includes('"accounts"') && !finalBody.includes('"data"')) {
          const inferredFields: Record<string, unknown> = {};

          // Extract field names from error patterns:
          // "Missing field: workspace_id" / "'workspace_id' is required" / "provide user_id"
          const fieldPatterns = [
            /missing[:\s]+['"` + '`' + `]?(\w+)['"` + '`' + `]?/gi,
            /required[:\s]+['"` + '`' + `]?(\w+)['"` + '`' + `]?/gi,
            /['"` + '`' + `](\w+)['"` + '`' + `]?\s+is required/gi,
            /provide[:\s]+['"` + '`' + `]?(\w+)['"` + '`' + `]?/gi,
          ];
          for (const pat of fieldPatterns) {
            let m;
            while ((m = pat.exec(finalBody)) !== null) {
              const f = m[1].toLowerCase();
              inferredFields[f] = /id$/.test(f) ? '00000000-0000-0000-0000-000000000000' : 'test';
            }
          }

          // Also try common fields by function name context
          if (/workspace/.test(funcName)) inferredFields['workspace_id'] = '00000000-0000-0000-0000-000000000000';
          if (/user/.test(funcName)) inferredFields['user_id'] = '00000000-0000-0000-0000-000000000000';

          if (Object.keys(inferredFields).length > 0) {
            const resAdaptive = await fetchWithTimeout(funcUrl, {
              method: 'POST', headers: baseHeaders, body: JSON.stringify(inferredFields),
            }, 10000);

            if (resAdaptive.status !== 401 && resAdaptive.status !== 403 && resAdaptive.status !== 404) {
              finalRes = resAdaptive;
              finalBody = await resAdaptive.text().catch(() => '');
              finalPayload = inferredFields;
            }
          }
        }
      } else {
        finalBody = await resGet.text().catch(() => '');
      }

      // ── Classify ──
      if (finalRes.status === 401 || finalRes.status === 403) continue;
      const hasJwtError = /jwt|token required|unauthorized|missing authorization|não autenticado|permissão|invalid token|acesso negado/i.test(finalBody);
      if (hasJwtError) continue;

      const is2xx = finalRes.status >= 200 && finalRes.status < 300;
      const isBusinessError = !hasJwtError &&
        (finalBody.includes('"error"') || finalBody.includes('"message"') || finalBody.includes('"accounts"'));
      if (!is2xx && !isBusinessError) continue;

      // ── Report ──
      const isDiscovered = discoveredNames.has(funcName);
      const severity: Severity = isSensitiveFunction ? 'CRITICAL' : (isDiscovered ? 'HIGH' : 'MEDIUM');
      openFunctions++;

      const leakedData = is2xx && finalBody.length > 10 ? finalBody.substring(0, 400) : undefined;
      const payloadNote = Object.keys(finalPayload).length > 0
        ? ` Payload adaptativo: ${JSON.stringify(finalPayload)}.` : '';

      console.log(
        `    [supabase] ⚠ Edge Function exposta: ${funcName} (HTTP ${finalRes.status})` +
        (leakedData ? ' — dados vazados!' : '')
      );

      findings.push({
        type: 'exposed_secret',
        severity,
        title: `Edge Function sem verificação JWT: ${funcName}`,
        description:
          `A Edge Function "${funcName}" respondeu com HTTP ${finalRes.status} sem JWT válido.` +
          payloadNote +
          (leakedData
            ? ` Dados retornados sem autenticação: ${leakedData}`
            : ` Lógica executou sem auth: ${finalBody.substring(0, 150)}`),
        location: funcUrl,
        remediation: 'Habilite verify_jwt = true ou implemente verificação manual no início da função.',
        metadata: {
          function: funcName,
          status: finalRes.status,
          discovered: isDiscovered,
          sensitive: isSensitiveFunction,
          leaked_data: leakedData,
          payload_used: finalPayload,
          ai_prompt:
            `A Edge Function "${funcName}" está acessível sem autenticação. ` +
            'Para corrigir: no supabase/config.toml, certifique-se que verify_jwt = true. ' +
            'Ou adicione no início da função: ' +
            'const authHeader = req.headers.get("Authorization"); ' +
            'if (!authHeader) return new Response("Unauthorized", { status: 401 });',
        },
      });
    } catch { /* timeout or network error — skip */ }
  }

  if (openFunctions === 0) {
    console.log(`    [supabase] ✅ Nenhuma Edge Function acessível sem JWT`);
  } else {
    console.log(`    [supabase] ⚠ ${openFunctions} Edge Function(s) sem JWT verification`);
  }

  return findings;
}

// ────────────────── Phase 10: Privilege Escalation ──────────────────


/** Fields commonly used for role/privilege in Supabase apps. */
const PRIVILEGE_FIELDS = [
  { field: 'role', escalatedValue: 'admin', sensitiveValues: ['admin', 'superadmin', 'owner', 'moderator'] },
  { field: 'is_admin', escalatedValue: true, sensitiveValues: [true] },
  { field: 'admin', escalatedValue: true, sensitiveValues: [true] },
  { field: 'permissions', escalatedValue: 'admin', sensitiveValues: ['admin', 'superadmin'] },
  { field: 'tier', escalatedValue: 'enterprise', sensitiveValues: ['enterprise', 'premium'] },
  { field: 'plan', escalatedValue: 'enterprise', sensitiveValues: ['enterprise', 'premium', 'pro'] },
];

/** Common profile table names in Supabase apps. */
const PROFILE_TABLES = ['profiles', 'users', 'user_profiles', 'members', 'accounts'];

/**
 * Testa escalação de privilégio via PATCH em tabelas de perfil.
 * Requer token autenticado. Realiza PATCH + rollback.
 */
async function probePrivilegeEscalation(
  projectUrl: string,
  authenticatedToken: string,
  pageUrl: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  console.log(`    [supabase] Probing privilege escalation...`);

  const restBase = `${projectUrl}/rest/v1`;
  const headers = {
    'Authorization': `Bearer ${authenticatedToken}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation',
  };

  // 1. Discover which profile table exists
  let profileTable: string | null = null;
  let userProfile: Record<string, unknown> | null = null;
  let userId: string | null = null;

  for (const table of PROFILE_TABLES) {
    try {
      const res = await fetchWithTimeout(
        `${restBase}/${table}?limit=1&select=*`,
        { method: 'GET', headers },
        4000,
      );

      if (res.ok) {
        const data = await res.json() as unknown[];
        if (Array.isArray(data) && data.length > 0) {
          profileTable = table;
          userProfile = data[0] as Record<string, unknown>;
          userId = String(userProfile['id'] || userProfile['user_id'] || '');
          break;
        } else if (res.ok) {
          // Table exists but empty or RLS filtered — still try
          profileTable = table;
          break;
        }
      } else if (res.status === 404) {
        continue;
      }
    } catch { continue; }
  }

  if (!profileTable || !userId) {
    console.log(`    [supabase] No profile table found for privilege escalation test`);
    return findings;
  }

  // 2. Check for IDOR (can user read other profiles?)
  try {
    const idorRes = await fetchWithTimeout(
      `${restBase}/${profileTable}?limit=5&select=id`,
      { method: 'GET', headers },
      4000,
    );
    if (idorRes.ok) {
      const rows = await idorRes.json() as unknown[];
      if (Array.isArray(rows) && rows.length > 1) {
        findings.push({
          type: 'supabase_rls_violation',
          severity: 'MEDIUM',
          title: `IDOR: usuário pode ler perfis de outros usuários (tabela "${profileTable}")`,
          description:
            `Um usuário autenticado conseguiu ler ${rows.length} perfis na tabela "${profileTable}". ` +
            `A política de RLS deveria restringir SELECT apenas ao próprio perfil.`,
          location: `${projectUrl}/rest/v1/${profileTable}`,
          remediation:
            `Adicione uma política RLS de SELECT restritiva: ` +
            `CREATE POLICY "Apenas próprio perfil" ON ${profileTable} FOR SELECT USING (auth.uid() = id);`,
          metadata: {
            table: profileTable,
            rowsVisible: rows.length,
            ai_prompt:
              `A tabela "${profileTable}" está permitindo que usuários leiam perfis de outros. ` +
              `Execute no SQL Editor: ALTER TABLE ${profileTable} ENABLE ROW LEVEL SECURITY; ` +
              `CREATE POLICY "Apenas próprio perfil" ON ${profileTable} FOR SELECT USING (auth.uid() = id);`,
          },
        });
      }
    }
  } catch { /* skip */ }

  // 3. Test privilege escalation via PATCH
  if (!userProfile) return findings;

  for (const { field, escalatedValue } of PRIVILEGE_FIELDS) {
    if (!(field in userProfile)) continue; // Skip fields that don't exist in this table

    const originalValue = userProfile[field];

    try {
      const patchRes = await fetchWithTimeout(
        `${restBase}/${profileTable}?id=eq.${userId}`,
        {
          method: 'PATCH',
          headers,
          body: JSON.stringify({ [field]: escalatedValue }),
        },
        4000,
      );

      if (patchRes.status === 200 || patchRes.status === 204) {
        // ESCALATION SUCCEEDED — immediately rollback
        let rollbackSuccess = false;
        try {
          const rollbackRes = await fetchWithTimeout(
            `${restBase}/${profileTable}?id=eq.${userId}`,
            {
              method: 'PATCH',
              headers,
              body: JSON.stringify({ [field]: originalValue }),
            },
            4000,
          );
          rollbackSuccess = rollbackRes.ok;
        } catch { /* rollback failed */ }

        findings.push({
          type: 'supabase_rls_violation',
          severity: 'CRITICAL',
          title: `Escalação de privilégio: usuário pode alterar campo "${field}" (tabela "${profileTable}")`,
          description:
            `Um usuário autenticado conseguiu alterar o campo "${field}" para "${escalatedValue}" na tabela "${profileTable}". ` +
            `Isso permite que qualquer usuário escale seus próprios privilégios.` +
            (rollbackSuccess ? ' O campo foi restaurado ao valor original pelo scanner.' : ' ⚠️ O rollback falhou — verifique o campo manualmente.'),
          location: `${projectUrl}/rest/v1/${profileTable}`,
          remediation: `Adicione uma política RLS de UPDATE que impeça alteração de campos de privilégio.`,
          metadata: {
            table: profileTable,
            field,
            originalValue,
            escalatedValue,
            rollbackSuccess,
            ai_prompt:
              `URGENTE: Usuários podem escalar seus próprios privilégios alterando o campo "${field}". ` +
              `Execute no SQL Editor do Supabase: ` +
              `CREATE POLICY "Não pode alterar próprio role" ON ${profileTable} FOR UPDATE USING (auth.uid() = id) ` +
              `WITH CHECK (${field} = (SELECT ${field} FROM ${profileTable} WHERE id = auth.uid()));`,
          },
        });

        break; // One escalation finding is enough
      }
    } catch { continue; }
  }

  if (findings.length === 0) {
    console.log(`    [supabase] ✅ Privilege escalation não detectada`);
  }

  return findings;
}

