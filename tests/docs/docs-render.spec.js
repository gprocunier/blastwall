const { expect, test } = require("@playwright/test");
const fs = require("node:fs");
const path = require("node:path");

const pages = [
  "index.html",
  "demo.html",
  "aap-demo.html",
  "ansible-lab.html",
  "comparable-approaches.html",
  "poc-flow.html",
  "quick-demo.html",
  "threat-model.html"
];

const viewports = [
  { name: "desktop-wide", width: 1440, height: 1000 },
  { name: "desktop", width: 1280, height: 800 },
  { name: "tablet", width: 1024, height: 768 },
  { name: "tablet-portrait", width: 768, height: 1024 },
  { name: "mobile", width: 390, height: 844 }
];

const pageSlug = (path) => path.replace(/\.html$/, "").replace(/^index$/, "home");
const docsRoot = path.resolve(__dirname, "../../docs");
const repoRoot = path.resolve(__dirname, "../..");

const expectedNav = {
  "index.html": ["Ansible Demo", "AAP Demo", "Comparison", "Threat Model", "Source"],
  "demo.html": ["Overview", "Ansible Lab", "Comparison", "Threat Model", "Source"],
  "aap-demo.html": ["Overview", "AAP Lab", "Comparison", "Threat Model", "Source"],
  "ansible-lab.html": ["Overview", "Ansible Demo", "Ansible Lab", "Lab Flow", "Comparison", "Source"],
  "quick-demo.html": ["Overview", "AAP Demo", "AAP Lab", "Comparison", "Source"],
  "poc-flow.html": ["Overview", "Ansible Demo", "Ansible Lab", "PoC Source"],
  "comparable-approaches.html": ["Overview", "Ansible Demo", "AAP Demo", "Comparison", "Threat Model", "Source"],
  "threat-model.html": ["Overview", "Ansible Demo", "AAP Demo", "Comparison", "Threat Model", "Source"]
};

const markdownHeadingAnchor = (heading) => heading
  .toLowerCase()
  .replace(/[`*_~]/g, "")
  .replace(/[^\w\s-]/g, "")
  .trim()
  .replace(/\s+/g, "-");

const readText = (filePath) => fs.readFileSync(filePath, "utf8");

const htmlIds = (filePath) => {
  const html = readText(filePath);
  return new Set(Array.from(html.matchAll(/\sid="([^"]+)"/g), (match) => match[1]));
};

const markdownAnchors = (filePath) => {
  const markdown = readText(filePath);
  return new Set(Array.from(markdown.matchAll(/^#{1,6}\s+(.+)$/gm), (match) => markdownHeadingAnchor(match[1])));
};

test.describe("GitHub Pages rendering", () => {
  for (const viewport of viewports) {
    test.describe(`${viewport.name} ${viewport.width}x${viewport.height}`, () => {
      test.use({ viewport });

      for (const path of pages) {
        test(`${path} has no viewport overflow`, async ({ page }, testInfo) => {
          const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";
          const failedLocalResponses = [];
          page.on("response", (response) => {
            if (response.url().startsWith(baseUrl) && response.status() >= 400) {
              failedLocalResponses.push(`${response.status()} ${response.url()}`);
            }
          });

          await page.goto(`${baseUrl}/${path}`, { waitUntil: "domcontentloaded" });
          await page.waitForTimeout(path.includes("demo") ? 2500 : 500);

          const result = await page.evaluate(() => {
            const viewportWidth = document.documentElement.clientWidth;
            const documentOverflow = document.documentElement.scrollWidth - viewportWidth;
            const offenders = [];

            const hasClippingAncestor = (element) => {
              let current = element.parentElement;

              while (current && current !== document.body && current !== document.documentElement) {
                const style = getComputedStyle(current);
                const clipsX = ["auto", "scroll", "hidden", "clip"].includes(style.overflowX);

                if (clipsX) {
                  return true;
                }

                current = current.parentElement;
              }

              return false;
            };

            for (const element of document.body.querySelectorAll("*")) {
              const rect = element.getBoundingClientRect();

              if (rect.width === 0 || rect.height === 0) {
                continue;
              }

              if (rect.left < -2 || rect.right > viewportWidth + 2) {
                if (hasClippingAncestor(element)) {
                  continue;
                }

                offenders.push({
                  tag: element.tagName.toLowerCase(),
                  id: element.id || "",
                  className: String(element.className || ""),
                  text: (element.textContent || "").trim().replace(/\s+/g, " ").slice(0, 120),
                  left: Math.round(rect.left),
                  right: Math.round(rect.right),
                  width: Math.round(rect.width)
                });
              }
            }

            return {
              documentOverflow,
              offenders: offenders.slice(0, 20)
            };
          });

          await page.screenshot({
            path: `/tmp/blastwall-docs-${pageSlug(path)}-${viewport.name}.png`,
            fullPage: true
          });

          expect(result.documentOverflow, JSON.stringify(result.offenders, null, 2)).toBeLessThanOrEqual(2);
          expect(result.offenders, JSON.stringify(result.offenders, null, 2)).toEqual([]);
          expect(failedLocalResponses).toEqual([]);
        });
      }
    });
  }

  test("asciinema players render", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    for (const path of ["demo.html", "aap-demo.html"]) {
      const failedLocalResponses = [];
      page.on("response", (response) => {
        if (response.url().startsWith(baseUrl) && response.status() >= 400) {
          failedLocalResponses.push(`${response.status()} ${response.url()}`);
        }
      });

      await page.goto(`${baseUrl}/${path}`, { waitUntil: "domcontentloaded" });
      const players = page.locator(".ap-player");
      await expect(players.first()).toBeVisible({ timeout: 10000 });
      await expect(players.first()).toHaveCount(1);
      expect(failedLocalResponses).toEqual([]);
    }
  });

  test("dense diagrams can be enlarged in place", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`${baseUrl}/index.html`, { waitUntil: "domcontentloaded" });

    const idmDiagram = page.locator("#idm-aap-flow .diagram-artifact");
    const candidateDiagram = page.locator("#candidate-flow .diagram-artifact");
    await expect(idmDiagram).toBeVisible();
    await expect(candidateDiagram).toBeVisible();

    const idmBox = await idmDiagram.boundingBox();
    const candidateBox = await candidateDiagram.boundingBox();
    expect(idmBox.width).toBeLessThanOrEqual(550);
    expect(candidateBox.width).toBeLessThanOrEqual(650);

    await candidateDiagram.click();
    const lightbox = page.locator(".diagram-lightbox");
    await expect(lightbox).toBeVisible();
    await expect(page.locator(".diagram-lightbox__image")).toHaveAttribute("src", /candidate-flow\.svg$/);

    await page.locator(".diagram-lightbox__image").click();
    await expect(lightbox).toBeHidden();
  });

  test("site nav matches the intended page map", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    for (const [path, expectedLabels] of Object.entries(expectedNav)) {
      await page.goto(`${baseUrl}/${path}`, { waitUntil: "domcontentloaded" });
      const labels = await page.locator(".site-header__actions a").evaluateAll((links) =>
        links.map((link) => link.textContent.trim())
      );
      expect(labels, path).toEqual(expectedLabels);
    }
  });

  test("local and repository hash links resolve", async () => {
    const idsByPage = new Map(pages.map((pagePath) => [
      pagePath,
      htmlIds(path.join(docsRoot, pagePath))
    ]));
    const readmeAnchors = markdownAnchors(path.join(repoRoot, "README.md"));
    const failures = [];

    for (const pagePath of pages) {
      const html = readText(path.join(docsRoot, pagePath));
      const hrefs = Array.from(html.matchAll(/href="([^"]+)"/g), (match) => match[1]);

      for (const href of hrefs) {
        if (
          href.startsWith("mailto:") ||
          href.startsWith("https://fonts.") ||
          href.startsWith("https://man7.org/") ||
          href.startsWith("https://github.com/") && !href.startsWith("https://github.com/gprocunier/blastwall")
        ) {
          continue;
        }

        if (href.startsWith("https://github.com/gprocunier/blastwall#")) {
          const anchor = href.split("#")[1];
          if (!readmeAnchors.has(anchor)) {
            failures.push(`${pagePath}: missing README anchor ${href}`);
          }
          continue;
        }

        if (href.startsWith("https://github.com/gprocunier/blastwall")) {
          continue;
        }

        const [targetPathRaw, hash] = href.split("#");
        const targetPath = targetPathRaw || pagePath;

        if (targetPath === "./") {
          if (hash && !idsByPage.get("index.html").has(hash)) {
            failures.push(`${pagePath}: missing index hash ${href}`);
          }
          continue;
        }

        if (targetPath.startsWith("assets/")) {
          if (!fs.existsSync(path.join(docsRoot, targetPath))) {
            failures.push(`${pagePath}: missing asset ${href}`);
          }
          continue;
        }

        if (!targetPath.endsWith(".html")) {
          continue;
        }

        const normalizedTarget = targetPath.replace(/^\.\//, "");
        if (!idsByPage.has(normalizedTarget)) {
          failures.push(`${pagePath}: missing local page ${href}`);
          continue;
        }

        if (hash && !idsByPage.get(normalizedTarget).has(hash)) {
          failures.push(`${pagePath}: missing hash ${href}`);
        }
      }
    }

    expect(failures).toEqual([]);
  });
});
