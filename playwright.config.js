const { defineConfig } = require("@playwright/test");

const docsPort = process.env.BLASTWALL_DOCS_PORT || "8765";

module.exports = defineConfig({
  testDir: ".",
  reporter: "list",
  timeout: 30_000,
  workers: 1,
  webServer: {
    command: `python3 -m http.server ${docsPort} -d docs`,
    url: `http://127.0.0.1:${docsPort}`,
    reuseExistingServer: !process.env.CI
  },
  use: {
    baseURL: `http://127.0.0.1:${docsPort}`,
    browserName: "chromium"
  }
});
