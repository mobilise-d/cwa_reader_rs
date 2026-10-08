import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  reporter: [['list'], ['json', { outputFile: 'test-results/results.json' }]],
  use: { baseURL: 'http://127.0.0.1:5287', browserName: 'chromium' },
  webServer: {
    command: 'node serve.mjs --test-fixtures',
    port: 5287,
    reuseExistingServer: false,
  },
});
