import { defineConfig, devices } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 *
 * colorScheme is forced to 'dark' so the default scan is genuinely the dark
 * theme; clicking the toggle then deterministically reaches the light theme.
 */
// Must be unique across the crypto-lab fleet. `reuseExistingServer` adopts
// whatever already listens here, so a shared port means this suite can scan a
// different lab's page and report its findings as ours. 4221 collided with
// crypto-lab-hybrid-sign. Declared once so the three places that need it
// cannot drift apart.
const PORT = 4676;
const BASE = '/crypto-lab-bitcoin-script/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    // Build first: `vite preview` only serves whatever is already in `dist/`.
    // Without the build, a source change that fails to compile leaves the last
    // good bundle in place and the suite passes green against code that no
    // longer builds — which silently invalidates mutation checks.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    // Wait on the full base-path URL, not a bare port: a squatter on the port
    // that does not serve this lab's base path 404s and is rejected, instead
    // of being silently adopted.
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
