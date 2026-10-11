import { defineConfig } from "@playwright/test";

const baseURL = process.env.E2E_BASE_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: "list",
  use: {
    baseURL,
    browserName: "chromium",
    headless: true,
  },
  webServer: {
    command: "go run ./cmd/server",
    url: `${baseURL}/healthz`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      ...process.env,
      DATABASE_URL: process.env.E2E_DATABASE_URL ?? process.env.DATABASE_URL ?? "postgres://postgres:postgres@127.0.0.1:5432/club_membership_test?sslmode=disable",
      LISTEN_HOST: "127.0.0.1",
      PORT: "8080",
      TRUSTED_ORIGIN: baseURL,
      BOOTSTRAP_SUPERUSER_LOGIN: process.env.BOOTSTRAP_SUPERUSER_LOGIN ?? "e2e-root",
      BOOTSTRAP_SUPERUSER_PASSWORD: process.env.BOOTSTRAP_SUPERUSER_PASSWORD ?? "e2e-bootstrap-password-long-enough",
    },
  },
});
