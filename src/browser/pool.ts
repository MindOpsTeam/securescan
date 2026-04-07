import puppeteer, { Browser, BrowserContext, Page } from 'puppeteer';

export class BrowserPool {
  private browsers: (Browser | null)[];
  private nextIndex = 0;
  private activeSessions = 0;
  private readonly poolSize: number;

  constructor(opts: { poolSize: number }) {
    this.poolSize = opts.poolSize;
    this.browsers = new Array(this.poolSize).fill(null);
  }

  async init(): Promise<void> {
    console.log(`[BrowserPool] Initializing ${this.poolSize} browsers...`);
    for (let i = 0; i < this.poolSize; i++) {
      this.browsers[i] = await this.launchBrowser();
      console.log(`[BrowserPool] Browser ${i + 1}/${this.poolSize} ready`);
    }
  }

  private async launchBrowser(): Promise<Browser> {
    return puppeteer.launch({
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions',
        '--window-size=1920,1080',
        // NÃO usar --disable-web-security (comprometeria isolamento entre scans)
      ],
    });
  }

  /**
   * Obtém uma Page isolada (via BrowserContext).
   * Cookies, cache e Service Workers são separados por scan.
   */
  async getPage(): Promise<{ page: Page; context: BrowserContext; release: () => Promise<void> }> {
    for (let attempt = 0; attempt < this.poolSize; attempt++) {
      const idx = this.nextIndex;
      this.nextIndex = (this.nextIndex + 1) % this.poolSize;

      let browser = this.browsers[idx];

      // Health check + auto-replace
      if (!browser || !browser.isConnected()) {
        console.warn(`[BrowserPool] Browser #${idx} dead, replacing...`);
        try { await browser?.close(); } catch {}
        browser = await this.launchBrowser();
        this.browsers[idx] = browser;
      }

      try {
        const context = await browser.createBrowserContext();
        const page = await context.newPage();
        page.setDefaultTimeout(30_000);
        page.setDefaultNavigationTimeout(30_000);

        // Block heavy resources
        await page.setRequestInterception(true);
        page.on('request', (req) => {
          const type = req.resourceType();
          if (['image', 'media', 'font', 'stylesheet'].includes(type)) {
            req.abort();
          } else {
            req.continue();
          }
        });

        this.activeSessions++;

        const release = async () => {
          this.activeSessions--;
          try {
            await page.close();
            await context.close();
          } catch {}
        };

        return { page, context, release };
      } catch (err) {
        console.error(`[BrowserPool] Browser #${idx} failed:`, err);
        try { await browser?.close(); } catch {}
        this.browsers[idx] = await this.launchBrowser();
      }
    }

    throw new Error('All browser instances are unhealthy');
  }

  healthyCount(): number {
    return this.browsers.filter((b) => b?.isConnected()).length;
  }

  activeCount(): number {
    return this.activeSessions;
  }

  async shutdown(): Promise<void> {
    console.log('[BrowserPool] Shutting down...');
    await Promise.allSettled(this.browsers.map((b) => b?.close()));
  }
}
