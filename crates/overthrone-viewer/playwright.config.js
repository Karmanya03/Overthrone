// @ts-check
const { defineConfig, devices } = require('@playwright/test');

/**
 * Playwright configuration for Overthrone Viewer regression tests.
 *
 * Run tests:
 *   npx playwright test
 *
 * Update baselines:
 *   npx playwright test --update-snapshots
 *
 * Run with UI:
 *   npx playwright test --ui
 */
module.exports = defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [['html', { outputFolder: 'playwright-report' }]],

  use: {
    baseURL: 'http://127.0.0.1:8080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'Mobile Chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  webServer: {
    command: 'cargo run --release --bin overthrone-viewer',
    url: 'http://127.0.0.1:8080',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
