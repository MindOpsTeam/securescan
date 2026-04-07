import { Page } from 'puppeteer';

export interface DiscoveredRoute {
  path: string;
  fullUrl: string;
  source: string;      // 'html_link' | 'js_router' | 'sitemap' | 'robots'
  sensitivity: number; // 0-100, higher = more important to scan
  reason: string;      // why this route is interesting
}

// Patterns que indicam rotas sensíveis (regex + sensitivity score)
const SENSITIVE_PATTERNS: { pattern: RegExp; score: number; reason: string }[] = [
  // Auth & Sessions
  { pattern: /\/(auth|login|signin|sign-in|signup|sign-up|register)/i, score: 95, reason: 'Authentication page' },
  { pattern: /\/(logout|signout|sign-out)/i, score: 30, reason: 'Logout endpoint' },
  { pattern: /\/(forgot|reset|recover|password)/i, score: 85, reason: 'Password recovery' },
  { pattern: /\/(callback|oauth|sso)/i, score: 80, reason: 'OAuth callback' },
  { pattern: /\/(verify|confirm|activate)/i, score: 70, reason: 'Account verification' },

  // Admin & Management
  { pattern: /\/(admin|management|backoffice|back-office)/i, score: 100, reason: 'Admin panel' },
  { pattern: /\/(dashboard|painel|panel)/i, score: 90, reason: 'Dashboard - likely authenticated' },
  { pattern: /\/(settings|config|preferences|configuracoes)/i, score: 90, reason: 'Settings page' },
  { pattern: /\/(users|accounts|members|membros)/i, score: 85, reason: 'User management' },
  { pattern: /\/(roles|permissions|access)/i, score: 85, reason: 'Access control' },

  // Data & API
  { pattern: /\/(api|graphql|rest|v1|v2)/i, score: 95, reason: 'API endpoint' },
  { pattern: /\/(upload|import|export|download)/i, score: 75, reason: 'File handling' },
  { pattern: /\/(reports|analytics|metrics|dados)/i, score: 70, reason: 'Reports/analytics' },

  // Financial
  { pattern: /\/(billing|payment|checkout|subscription)/i, score: 90, reason: 'Payment/billing' },
  { pattern: /\/(invoice|fatura|order|pedido)/i, score: 85, reason: 'Financial transaction' },

  // Content Management
  { pattern: /\/(profile|account|minha-conta|my-account)/i, score: 80, reason: 'User profile' },
  { pattern: /\/(messages|inbox|notifications|chat)/i, score: 75, reason: 'Private messaging' },

  // Development/Debug (should never be in production)
  { pattern: /\/(debug|test|staging|dev|phpinfo|phpmyadmin|wp-admin)/i, score: 100, reason: 'Development/debug page in production' },
  { pattern: /\/(swagger|docs\/api|graphiql|playground)/i, score: 90, reason: 'API documentation' },
  { pattern: /\/(\._|\.env|\.git|\.config)/i, score: 100, reason: 'Exposed config file' },
];

/**
 * Calcula o score de sensibilidade de uma rota.
 */
function calculateSensitivity(path: string): { score: number; reason: string } {
  let maxScore = 10; // default: low priority
  let bestReason = 'Standard page';

  for (const { pattern, score, reason } of SENSITIVE_PATTERNS) {
    if (pattern.test(path) && score > maxScore) {
      maxScore = score;
      bestReason = reason;
    }
  }

  return { score: maxScore, reason: bestReason };
}

/**
 * Descobre rotas a partir do HTML da página (links <a>, <form>, etc.)
 */
async function extractRoutesFromHTML(page: Page, baseUrl: string): Promise<DiscoveredRoute[]> {
  const routes: DiscoveredRoute[] = [];
  const baseOrigin = new URL(baseUrl).origin;

  const links = await page.evaluate((origin: string) => {
    const results: string[] = [];
    const seen = new Set<string>();

    // <a href="...">
    document.querySelectorAll('a[href]').forEach((el) => {
      const href = (el as HTMLAnchorElement).href;
      if (href && !seen.has(href)) {
        seen.add(href);
        results.push(href);
      }
    });

    // <form action="...">
    document.querySelectorAll('form[action]').forEach((el) => {
      const action = (el as HTMLFormElement).action;
      if (action && !seen.has(action)) {
        seen.add(action);
        results.push(action);
      }
    });

    // <button data-href>, <div data-url>, etc.
    document.querySelectorAll('[data-href], [data-url]').forEach((el) => {
      const href = el.getAttribute('data-href') || el.getAttribute('data-url') || '';
      if (href && !seen.has(href)) {
        seen.add(href);
        results.push(href.startsWith('http') ? href : origin + href);
      }
    });

    return results;
  }, baseOrigin);

  for (const link of links) {
    try {
      const url = new URL(link);
      // Only same-origin routes
      if (url.origin !== baseOrigin) continue;
      // Skip hash-only, empty, and static files
      if (url.pathname === '/' || /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$/i.test(url.pathname)) continue;

      const { score, reason } = calculateSensitivity(url.pathname);
      routes.push({
        path: url.pathname,
        fullUrl: `${url.origin}${url.pathname}`,
        source: 'html_link',
        sensitivity: score,
        reason,
      });
    } catch {}
  }

  return routes;
}

/**
 * Busca rotas definidas em JS routers (React Router, Vue Router, Next.js, etc.)
 * Procura nos bundles JS capturados.
 */
function extractRoutesFromBundles(scriptContents: string[], baseUrl: string): DiscoveredRoute[] {
  const routes: DiscoveredRoute[] = [];
  const origin = new URL(baseUrl).origin;
  const seen = new Set<string>();

  for (const script of scriptContents) {
    // React Router patterns: path: "/dashboard", path: '/settings'
    const reactRouterPattern = /path\s*:\s*["'`](\/[a-zA-Z0-9\-_/:.]*?)["'`]/g;
    let match;
    while ((match = reactRouterPattern.exec(script)) !== null) {
      const path = match[1];
      if (!seen.has(path) && path !== '/' && !path.includes(':')) {
        seen.add(path);
        const { score, reason } = calculateSensitivity(path);
        routes.push({
          path,
          fullUrl: `${origin}${path}`,
          source: 'js_router',
          sensitivity: score,
          reason,
        });
      }
    }

    // Patterns como: "/dashboard", "/auth", "/settings" em strings JS
    const stringPattern = /["'`](\/(?:auth|login|admin|dashboard|settings|profile|billing|users|api|reports|scan|history|sessions|account|signup|register|forgot|reset|checkout|payment|messages|notifications|upload|import|export)[a-zA-Z0-9\-_/]*)["'`]/gi;
    while ((match = stringPattern.exec(script)) !== null) {
      const path = match[1];
      if (!seen.has(path) && !path.includes('${') && path.length < 100) {
        seen.add(path);
        const { score, reason } = calculateSensitivity(path);
        routes.push({
          path,
          fullUrl: `${origin}${path}`,
          source: 'js_router',
          sensitivity: score,
          reason,
        });
      }
    }

    // createBrowserRouter / createRoutesFromElements patterns
    const elementPattern = /Route\s+path=["'](\/[a-zA-Z0-9\-_/]*?)["']/g;
    while ((match = elementPattern.exec(script)) !== null) {
      const path = match[1];
      if (!seen.has(path) && path !== '/') {
        seen.add(path);
        const { score, reason } = calculateSensitivity(path);
        routes.push({
          path,
          fullUrl: `${origin}${path}`,
          source: 'js_router',
          sensitivity: score,
          reason,
        });
      }
    }
  }

  return routes;
}

/**
 * Tenta buscar rotas do sitemap.xml e robots.txt
 */
async function extractFromSitemapAndRobots(baseUrl: string): Promise<DiscoveredRoute[]> {
  const routes: DiscoveredRoute[] = [];
  const origin = new URL(baseUrl).origin;

  // robots.txt
  try {
    const robotsRes = await fetch(`${origin}/robots.txt`, { signal: AbortSignal.timeout(5000) });
    if (robotsRes.ok) {
      const text = await robotsRes.text();
      // Disallow lines often reveal sensitive paths
      const disallowPattern = /Disallow:\s*(\S+)/g;
      let match;
      while ((match = disallowPattern.exec(text)) !== null) {
        const path = match[1];
        if (path !== '/' && path.length > 1) {
          const { score, reason } = calculateSensitivity(path);
          routes.push({
            path,
            fullUrl: `${origin}${path}`,
            source: 'robots',
            // Disallowed paths are extra interesting — bump score
            sensitivity: Math.min(100, score + 20),
            reason: `Disallowed in robots.txt — ${reason}`,
          });
        }
      }
    }
  } catch {}

  // sitemap.xml
  try {
    const sitemapRes = await fetch(`${origin}/sitemap.xml`, { signal: AbortSignal.timeout(5000) });
    if (sitemapRes.ok) {
      const text = await sitemapRes.text();
      const locPattern = /<loc>(.*?)<\/loc>/g;
      let match;
      while ((match = locPattern.exec(text)) !== null) {
        try {
          const url = new URL(match[1]);
          if (url.origin === origin && url.pathname !== '/') {
            const { score, reason } = calculateSensitivity(url.pathname);
            routes.push({
              path: url.pathname,
              fullUrl: match[1],
              source: 'sitemap',
              sensitivity: score,
              reason,
            });
          }
        } catch {}
      }
    }
  } catch {}

  return routes;
}

/**
 * Descobre todas as rotas a partir da URL base:
 * 1. HTML links (<a>, <form>)
 * 2. JS Router definitions (React Router, Vue Router, etc.)
 * 3. sitemap.xml e robots.txt
 *
 * Retorna rotas ordenadas por sensibilidade (mais importante primeiro),
 * limitadas a MAX_ROUTES.
 */
export async function discoverRoutes(
  page: Page,
  baseUrl: string,
  scriptContents: string[],
  maxRoutes: number = 5
): Promise<DiscoveredRoute[]> {
  console.log(`  [routes] Discovering routes from ${baseUrl}...`);

  // Run all discovery methods in parallel
  const [htmlRoutes, bundleRoutes, externalRoutes] = await Promise.all([
    extractRoutesFromHTML(page, baseUrl),
    Promise.resolve(extractRoutesFromBundles(scriptContents, baseUrl)),
    extractFromSitemapAndRobots(baseUrl),
  ]);

  // Merge and dedup by path
  const seen = new Set<string>();
  const allRoutes: DiscoveredRoute[] = [];

  for (const route of [...htmlRoutes, ...bundleRoutes, ...externalRoutes]) {
    if (!seen.has(route.path)) {
      seen.add(route.path);
      allRoutes.push(route);
    } else {
      // If we've seen it, keep the one with higher sensitivity
      const existing = allRoutes.find(r => r.path === route.path);
      if (existing && route.sensitivity > existing.sensitivity) {
        existing.sensitivity = route.sensitivity;
        existing.reason = route.reason;
        existing.source = route.source;
      }
    }
  }

  // Sort by sensitivity DESC, take top N
  allRoutes.sort((a, b) => b.sensitivity - a.sensitivity);
  const topRoutes = allRoutes.slice(0, maxRoutes);

  console.log(`  [routes] Found ${allRoutes.length} total routes, selected top ${topRoutes.length}:`);
  for (const r of topRoutes) {
    console.log(`    [${r.sensitivity}] ${r.path} (${r.reason}) [${r.source}]`);
  }

  return topRoutes;
}
