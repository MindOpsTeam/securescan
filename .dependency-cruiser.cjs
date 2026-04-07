/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    // ── REGRA 1: scanners NÃO podem importar o SDK Supabase ──
    {
      name: 'no-scanner-supabase-import',
      comment:
        'Scanners de domínio (lógica de análise de segurança) não podem importar ' +
        'o SDK do Supabase. Apenas infrastructure/ pode usar @supabase/supabase-js.',
      severity: 'error',
      from: {
        path: '^src/scanners/',
      },
      to: {
        path: 'node_modules/@supabase',
      },
    },

    // ── REGRA 2: utils e security NÃO podem importar SDKs de infraestrutura ──
    {
      name: 'no-utils-infra-import',
      comment:
        'Utils e security são módulos puros de domínio e não devem depender de ' +
        'SDKs de infraestrutura (@supabase, puppeteer).',
      severity: 'error',
      from: {
        path: '^src/(utils|security)/',
      },
      to: {
        path: [
          'node_modules/@supabase',
          'node_modules/puppeteer',
        ],
      },
    },

    // ── REGRA 3: types/ é uma folha pura — não pode importar nada do projeto ──
    {
      name: 'types-are-leaf-nodes',
      comment:
        'O módulo types/ define contratos puros (Finding, ScanJob, etc.) e não ' +
        'deve depender de nenhum outro módulo interno ou SDK.',
      severity: 'error',
      from: { path: '^src/types/' },
      to: {
        path: [
          '^src/(scanners|browser|utils|security|infrastructure|worker)',
          'node_modules/@supabase',
          'node_modules/puppeteer',
        ],
      },
    },

    // ── REGRA 4: scanners individuais não podem se importar entre si ──
    {
      name: 'no-scanner-cross-import',
      comment:
        'Scanners individuais não devem importar uns aos outros diretamente. ' +
        'Toda orquestração passa pelo index.ts (orchestrator pattern).',
      severity: 'error',
      from: {
        path: '^src/scanners/(?!index\\.ts)',
      },
      to: {
        path: '^src/scanners/(?!index\\.ts)',
        pathNot: [
          '^src/types/',
          '^src/utils/',
        ],
      },
    },

    // ── REGRA 5: infrastructure/ só pode depender de types/ (+ SDKs) ──
    {
      name: 'infra-depends-only-on-types',
      comment:
        'A camada de infraestrutura implementa interfaces de types/ports.ts ' +
        'e não deve depender de scanners, browser, ou worker.',
      severity: 'error',
      from: {
        path: '^src/infrastructure/',
      },
      to: {
        path: '^src/(scanners|browser|utils|security|worker)',
      },
    },
  ],

  options: {
    doNotFollow: {
      path: 'node_modules',
    },
    tsConfig: {
      fileName: './tsconfig.json',
    },
    reporterOptions: {
      text: {
        highlightFocused: true,
      },
    },
  },
};
