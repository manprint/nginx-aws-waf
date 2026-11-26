import { defineConfig } from '@playwright/test';

// One project per lab site (env SITES=shop12,shop14,...). Runs inside the waf_lab network:
// shopNN.lab.test are network aliases of the WAF container (deploy/compose/node.bridge.yml),
// so both the browser and page.request (Node HTTP stack) reach the WAF on port 8080.
const sites = (process.env.SITES || 'shop12,shop14,shop16,shop18').split(',').filter(Boolean);
const runId = process.env.RUN_ID || 'local';

export default defineConfig({
  testDir: './specs',
  workers: 4,
  retries: 0,
  timeout: 120_000,
  reporter: [['list'], ['json', { outputFile: 'test-results/results.json' }]],
  use: {
    extraHTTPHeaders: { 'X-Waf-Test': `${runId}-legit` },
    launchOptions: { args: ['--host-resolver-rules=MAP *.lab.test waf:8080'] },
    trace: 'off',
  },
  projects: sites.map((s) => ({
    name: s,
    use: { baseURL: `http://${s}.lab.test:8080` },
  })),
});
