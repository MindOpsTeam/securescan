import { Page, BrowserContext, HTTPRequest } from 'puppeteer';
import { Finding, Severity } from '../types/findings';
import { scanSecrets } from './secretScanner';
import { scanHeaders } from './headerScanner';
import { scanStorage } from './storageScanner';
import { scanCors } from './corsScanner';
import { scanSupabase, setupNetworkCapture } from './supabaseScanner';
import { scanNetwork, NetworkCapture } from './networkScanner';
import { discoverRoutes, DiscoveredRoute } from './routeDiscovery';
import { scanExposures } from './exposureScanner';
import { scoreToGrade, calculateScore } from '../utils/scoring';

interface ScanResult {
  findings: Finding[];
  pageTitle: string | null;
  summary: ScanSummary | null;
  metadata: ScanMetadata;
}

interface ScanSummary {
  grade: string;
  score: number;
  routesDiscovered: number;
  routesProtected: number;
  routesExposed: number;
  tablesExposed: number;
  keysFound: number;
  serviceRoleExposed: boolean;
  severityCounts: Record<string, number>;
}

interface ScanMetadata {
  discovery: {
    routes: string[];
    tables: string[];
    keys: Array<{ type: string; source: string }>;
    edge_functions: string[];
    storage_buckets: string[];
  };
  tests: {
    routes_without_auth: string[];
    exposed_tables: string[];
    exposed_apis: string[];
    exposed_edge_functions: string[];
    auth_enumeration_open: boolean;
    privilege_escalation_detected: boolean;
    public_storage_buckets: string[];
  };
}

// Max routes to deep-scan (beyond the base URL)
const MAX_DEEP_SCAN_ROUTES = 15;
// Minimum sensitivity score to qualify for deep scan
const MIN_SENSITIVITY = 50;

/**
 * Run a deep scan on a specific route: navigate to it and inspect the page.
 * Creates a new page in the same browser context to avoid detached frame errors.
 */
async function deepScanRoute(
  browserContext: BrowserContext,
  route: DiscoveredRoute,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let deepPage: Page | null = null;

  try {
    console.log(`  [deep-scan] Navigating to ${route.fullUrl} (${route.reason})...`);

    deepPage = await browserContext.newPage();
    const response = await deepPage.goto(route.fullUrl, {
      waitUntil: 'domcontentloaded',
      timeout: 10000,
    });

    if (!response) {
      await deepPage.close().catch(() => {});
      return findings;
    }

    // Wait for SPA to render
    await new Promise(r => setTimeout(r, 1500));

    // Check if we got redirected to login (means this route is protected — good!)
    const currentUrl = deepPage.url();
    const redirectedToAuth = currentUrl.includes('/auth') || currentUrl.includes('/login') || currentUrl.includes('/signin');

    if (redirectedToAuth) {
      console.log(`  [deep-scan] ✅ Rota "${route.path}" requer autenticação (protegida)`);
    } else if (route.sensitivity >= 80) {
      // High sensitivity route did NOT redirect to auth — potential issue
      // Check what content is on the page
      const pageContent = await deepPage.evaluate(() => {
        return {
          bodyText: document.body?.innerText?.substring(0, 500) || '',
          hasPasswordField: document.querySelectorAll('input[type="password"]').length > 0,
          hasForms: document.querySelectorAll('form').length,
          hasTables: document.querySelectorAll('table').length,
          tableRows: Array.from(document.querySelectorAll('table')).reduce((sum, t) => sum + t.querySelectorAll('tr').length, 0),
          title: document.title,
        };
      });

      // If the page has actual content (not just a "404" or blank page), it's concerning
      const hasRealContent = pageContent.bodyText.length > 50 && 
        !pageContent.bodyText.includes('404') && 
        !pageContent.bodyText.includes('Not Found');

      if (hasRealContent) {
        findings.push({
          type: 'insecure_storage',
          severity: 'HIGH',
          title: `⚠ Rota sensível "${route.path}" acessível sem autenticação`,
          description: `A rota "${route.path}" (${route.reason}) NÃO redirecionou para login e contém conteúdo. Título da página: "${pageContent.title}". Pode estar expondo conteúdo protegido para usuários não autenticados.`,
          location: route.fullUrl,
          remediation: `Adicione guards de autenticação na rota "${route.path}".`,
          metadata: {
            route: route.path,
            sensitivity: route.sensitivity,
            reason: route.reason,
            protected: false,
            hasForms: pageContent.hasForms,
            hasTables: pageContent.hasTables,
            ai_prompt:
              `A rota '${route.path}' (${route.reason}) está acessível sem autenticação e contendo conteúdo real. ` +
              'Adicione um guard de autenticação nesta rota. Se estiver usando React Router, adicione um componente ProtectedRoute que verifique ' +
              'a sessão do Supabase antes de renderizar. Se a rota é um endpoint de API, adicione middleware que valide o JWT.',
          },
        });
      }
    }
  } catch (err) {
    console.log(`  [deep-scan] Error scanning ${route.path}: ${(err as Error).message}`);
  } finally {
    if (deepPage) {
      await deepPage.close().catch(() => {});
    }
  }

  return findings;
}

/**
 * Orchestrator principal:
 *
 * 1. Setup network capture (antes da navegação)
 * 2. Navigate to base URL
 * 3. Run route discovery (HTML links + JS bundles + sitemap/robots)
 * 4. Run full scanner suite on base URL
 * 5. Deep-scan top sensitive routes
 * 6. Build executive summary
 */
export async function runAllScanners(
  page: Page,
  url: string,
  authenticatedToken?: string,
): Promise<ScanResult> {
  const allFindings: Finding[] = [];

  // Tracking counters for executive summary
  let routesDiscovered = 0;
  let routesProtected = 0;
  let routesExposed = 0;
  let tablesTotal = 0;
  let tablesExposed = 0;
  let keysFound = 0;
  let serviceRoleExposed = false;

  // ── Setup network capture ANTES de navegar ──
  const networkData: NetworkCapture = { requests: [], responses: [] };

  const requestCapture = (req: HTTPRequest) => {
    try {
      networkData.requests.push({
        url: req.url(),
        method: req.method(),
        resourceType: req.resourceType(),
        headers: req.headers() || {},
        postData: req.postData() || null,
      });
    } catch {}
  };

  page.on('request', requestCapture);

  // Supabase network capture (intercepta responses de JS bundles)
  const supabaseCapture = setupNetworkCapture(page);

  // ── 1. Navigate to base URL (header scanner does this) ──
  console.log(`  [scanners] Running header scanner...`);
  const headerFindings = await scanHeaders(page, url);
  allFindings.push(...headerFindings);

  // Wait for SPA to fully initialize — Supabase SDK needs time to call getSession(), etc.
  // This ensures network capture picks up Supabase requests from runtime (not just source code)
  await new Promise(r => setTimeout(r, 3000));

  const pageTitle = await page.title().catch(() => null);

  // ── 2. Get captured scripts for analysis ──
  const capturedScripts = supabaseCapture.getCapturedScripts();

  // ── 3. Route Discovery ──
  const routes = await discoverRoutes(page, url, capturedScripts, MAX_DEEP_SCAN_ROUTES);
  routesDiscovered = routes.length;

  // ── 4. Full scanner suite on base URL ──
  console.log(`  [scanners] Running secret scanner...`);
  const secretFindings = await scanSecrets(page, url);
  allFindings.push(...secretFindings);

  console.log(`  [scanners] Running storage scanner...`);
  const storageFindings = await scanStorage(page, url);
  allFindings.push(...storageFindings);

  console.log(`  [scanners] Running CORS scanner...`);
  const corsFindings = await scanCors(page, url);
  allFindings.push(...corsFindings);

  console.log(`  [scanners] Running Supabase scanner...`);
  console.log(`  [scanners] Captured ${capturedScripts.length} JS bundles for analysis`);
  const networkInstances = supabaseCapture.getInstances();
  console.log(`  [scanners] Network captured ${networkInstances.length} Supabase instance(s) from HTTP requests`);
  const supabaseFindings = await scanSupabase(page, url, capturedScripts, networkInstances, authenticatedToken);
  allFindings.push(...supabaseFindings);

  // Count Supabase-specific metrics for summary
  for (const f of supabaseFindings) {
    if (f.type === 'insecure_storage' && f.metadata?.['table']) {
      tablesExposed++;
    }
    if (f.title.includes('SERVICE_ROLE')) serviceRoleExposed = true;
    if (f.type === 'exposed_secret' && f.metadata?.['key']) keysFound++;
  }

  // Stop network capturing
  page.off('request', requestCapture);
  supabaseCapture.cleanup();

  console.log(`  [scanners] Running network scanner...`);
  const networkFindings = await scanNetwork(page, url, networkData);
  allFindings.push(...networkFindings);

  console.log(`  [scanners] Running exposure scanner...`);
  const capturedBundleUrls = supabaseCapture.getCapturedScriptUrls();
  const exposureFindings = await scanExposures(page, url, capturedBundleUrls);
  allFindings.push(...exposureFindings);

  // ── 5. Deep-scan sensitive routes ──
  const sensitiveRoutes = routes.filter(r => r.sensitivity >= MIN_SENSITIVITY);
  if (sensitiveRoutes.length > 0) {
    console.log(`  [deep-scan] Scanning ${sensitiveRoutes.length} sensitive routes...`);
    const browserContext = page.browserContext();

    for (const route of sensitiveRoutes) {
      const routeFindings = await deepScanRoute(browserContext, route);
      allFindings.push(...routeFindings);

      // Count route protection metrics
      const isProtected = routeFindings.length === 0; // No finding = route is protected or innocuous
      const hasExposedFinding = routeFindings.some(f => f.title.includes('acessível sem autenticação'));
      if (hasExposedFinding) routesExposed++;
      else if (isProtected) routesProtected++;
    }
  }

  // ── Dedup findings by type + title + location ──
  const seenKeys = new Set<string>();
  const dedupedFindings = allFindings.filter(f => {
    const key = `${f.type}::${f.title}::${f.location || ''}`;
    if (seenKeys.has(key)) return false;
    seenKeys.add(key);
    return true;
  });

  // ── 6. Build Executive Summary (separate from findings) ──
  const score = calculateScore(dedupedFindings);
  const grade = scoreToGrade(score);
  const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of dedupedFindings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  }

  const summary: ScanSummary = {
    grade,
    score,
    routesDiscovered,
    routesProtected,
    routesExposed,
    tablesExposed,
    keysFound,
    serviceRoleExposed,
    severityCounts,
  };

  console.log(`  [scanners] Done. ${dedupedFindings.length} unique findings (${allFindings.length} total before dedup). Grade: ${grade}`);

  // ── 7. Build structured metadata for frontend ──
  const discoveredKeys: Array<{ type: string; source: string }> = [];
  const discoveredTables: string[] = [];
  const exposedTableNames: string[] = [];
  const exposedApis: string[] = [];
  const routesWithoutAuth: string[] = [];
  const exposedEdgeFunctions: string[] = [];
  const publicStorageBuckets: string[] = [];
  let authEnumerationOpen = false;
  let privilegeEscalationDetected = false;

  for (const f of dedupedFindings) {
    // Collect keys
    if (f.type === 'exposed_secret' && f.metadata?.['key']) {
      discoveredKeys.push({
        type: (f.metadata['role'] as string) || 'anon_key',
        source: (f.metadata['source'] as string) || 'js_bundle',
      });
    }
    // Collect tables
    if (f.metadata?.['table']) {
      const table = f.metadata['table'] as string;
      if (!discoveredTables.includes(table)) discoveredTables.push(table);
      if (f.type === 'insecure_storage' || f.type === 'supabase_rls_violation') {
        if (!exposedTableNames.includes(table)) exposedTableNames.push(table);
        if (f.metadata?.['select']) {
          const apiPath = `/rest/v1/${table}`;
          if (!exposedApis.includes(apiPath)) exposedApis.push(apiPath);
        }
      }
    }
    // Collect routes without auth
    if (f.metadata?.['protected'] === false && f.metadata?.['route']) {
      routesWithoutAuth.push(f.metadata['route'] as string);
    }
    // Collect edge functions without JWT
    if (f.metadata?.['function'] && f.title.includes('Edge Function')) {
      exposedEdgeFunctions.push(f.metadata['function'] as string);
    }
    // Collect public storage buckets
    if (f.metadata?.['bucket']) {
      const bucket = f.metadata['bucket'] as string;
      if (!publicStorageBuckets.includes(bucket)) publicStorageBuckets.push(bucket);
    }
    // Auth enumeration
    if (f.title.includes('Signup aberto') || f.title.includes('Enumeração de usuários')) {
      authEnumerationOpen = true;
    }
    // Privilege escalation
    if (f.title.includes('Escalação de privilégio')) {
      privilegeEscalationDetected = true;
    }
  }

  // Collect discovered edge function names from supabase findings
  const discoveredEdgeFunctions = dedupedFindings
    .filter(f => f.metadata?.['function'])
    .map(f => f.metadata!['function'] as string);

  // Collect storage buckets found
  const allStorageBuckets = dedupedFindings
    .filter(f => f.metadata?.['bucket'])
    .map(f => f.metadata!['bucket'] as string)
    .filter((v, i, a) => a.indexOf(v) === i);

  const scanMetadata: ScanMetadata = {
    discovery: {
      routes: routes.map(r => r.path),
      tables: discoveredTables,
      keys: discoveredKeys,
      edge_functions: [...new Set(discoveredEdgeFunctions)],
      storage_buckets: allStorageBuckets,
    },
    tests: {
      routes_without_auth: routesWithoutAuth,
      exposed_tables: exposedTableNames,
      exposed_apis: exposedApis,
      exposed_edge_functions: exposedEdgeFunctions,
      auth_enumeration_open: authEnumerationOpen,
      privilege_escalation_detected: privilegeEscalationDetected,
      public_storage_buckets: publicStorageBuckets,
    },
  };

  return {
    findings: dedupedFindings,
    pageTitle,
    summary,
    metadata: scanMetadata,
  };
}
