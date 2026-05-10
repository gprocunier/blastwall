const { expect, test } = require("@playwright/test");
const fs = require("node:fs");
const path = require("node:path");

const pages = [
  "index.html",
  "demo.html",
  "aap-demo.html",
  "architecture.html",
  "ansible-lab.html",
  "comparable-approaches.html",
  "day2-operations.html",
  "glossary.html",
  "idm-control-model.html",
  "openshift-spo.html",
  "openshift-spo-demo.html",
  "poc-flow.html",
  "quick-demo.html",
  "reference.html",
  "selinux-control-model.html",
  "threat-model.html"
];

const viewports = [
  { name: "desktop-ultrawide", width: 1920, height: 1000 },
  { name: "desktop-wide", width: 1440, height: 1000 },
  { name: "desktop", width: 1280, height: 800 },
  { name: "tablet", width: 1024, height: 768 },
  { name: "tablet-portrait", width: 768, height: 1024 },
  { name: "mobile", width: 390, height: 844 }
];

const pageSlug = (path) => path.replace(/\.html$/, "").replace(/^index$/, "home");
const docsRoot = path.resolve(__dirname, "../../docs");
const repoRoot = path.resolve(__dirname, "../..");

const expectedHighValueNav = ["GitHub Repo", "eigenstate.ipa", "Ansible Galaxy"];

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
    const expectedSources = {
      "demo.html": "blastwall-poc.cast",
      "aap-demo.html": "blastwall-aap.cast",
      "openshift-spo-demo.html": "blastwall-openshift-spo.cast"
    };

    for (const path of ["demo.html", "aap-demo.html", "openshift-spo-demo.html"]) {
      const failedLocalResponses = [];
      page.on("response", (response) => {
        if (response.url().startsWith(baseUrl) && response.status() >= 400) {
          failedLocalResponses.push(`${response.status()} ${response.url()}`);
        }
      });

      await page.goto(`${baseUrl}/${path}`, { waitUntil: "domcontentloaded" });
      await expect(page.locator("[data-asciinema-src]")).toHaveAttribute("data-asciinema-src", expectedSources[path]);
      const players = page.locator(".ap-player");
      await expect(players.first()).toBeVisible({ timeout: 10000 });
      await expect(players.first()).toHaveCount(1);
      expect(failedLocalResponses).toEqual([]);
    }
  });

  test("Ansible demo cast carries Dirty Frag evidence", () => {
    const demoHtml = readText(path.join(docsRoot, "demo.html"));
    const cast = readText(path.join(docsRoot, "blastwall-poc.cast"));

    expect(demoHtml).toContain("Dirty Frag response marker");
    expect(cast).toContain("Dirty Frag");
    expect(cast).toContain("NETLINK_XFRM");
    expect(cast).toContain("AF_RXRPC");
    expect(cast).toContain("Blastwall 0.5.2");
  });

  test("OpenShift SPO demo cast carries dual workload evidence", () => {
    const demoHtml = readText(path.join(docsRoot, "openshift-spo-demo.html"));
    const cast = readText(path.join(docsRoot, "blastwall-openshift-spo.cast"));

    expect(demoHtml).toContain("UBI workload proof");
    expect(cast).toContain("blastwallnested");
    expect(cast).toContain("blastwall-confined");
    expect(cast).toContain("blastwall-nested");
    expect(cast).toContain("Profile class: standard");
    expect(cast).toContain("Profile class: nested");
    expect(cast).toContain("standard_profile: passed");
    expect(cast).toContain("nested_profile: passed");
  });

  test("diagrams use the available card width and can be enlarged in place", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`${baseUrl}/index.html`, { waitUntil: "domcontentloaded" });

    const idmDiagram = page.locator("#idm-aap-flow .diagram-artifact");
    const candidateDiagram = page.locator("#candidate-flow .diagram-artifact");
    await expect(idmDiagram).toBeVisible();
    await expect(candidateDiagram).toBeVisible();

    const idmBox = await idmDiagram.boundingBox();
    const candidateBox = await candidateDiagram.boundingBox();
    const idmFigureBox = await page.locator("#idm-aap-flow").boundingBox();
    const candidateFigureBox = await page.locator("#candidate-flow").boundingBox();
    expect(idmBox.width / idmFigureBox.width).toBeGreaterThan(0.92);
    expect(candidateBox.width / candidateFigureBox.width).toBeGreaterThan(0.92);

    await candidateDiagram.click();
    const lightbox = page.locator(".diagram-lightbox");
    await expect(lightbox).toBeVisible();
    await expect(page.locator(".diagram-lightbox__image")).toHaveAttribute("src", /candidate-flow\.svg$/);

    await page.locator(".diagram-lightbox__image").click();
    await expect(lightbox).toBeHidden();
  });

  test("diagram cards do not silently shrink diagrams", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";
    const paths = [
      "index.html",
      "demo.html",
      "aap-demo.html",
      "architecture.html",
      "ansible-lab.html",
      "quick-demo.html",
      "day2-operations.html",
      "selinux-control-model.html",
      "idm-control-model.html",
      "openshift-spo.html",
      "openshift-spo-demo.html",
      "threat-model.html"
    ];

    await page.setViewportSize({ width: 1440, height: 1000 });

    for (const path of paths) {
      await page.goto(`${baseUrl}/${path}`, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(500);

      const undersized = await page.evaluate(() => [...document.querySelectorAll("figure.diagram-card")].flatMap((figure) => {
        const image = figure.querySelector(".diagram-artifact");

        if (!image) {
          return [];
        }

        const figureBox = figure.getBoundingClientRect();
        const imageBox = image.getBoundingClientRect();
        const ratio = imageBox.width / figureBox.width;

        return ratio < 0.92
          ? [{
              id: figure.id,
              ratio: Number(ratio.toFixed(2)),
              imageWidth: Math.round(imageBox.width),
              figureWidth: Math.round(figureBox.width)
            }]
          : [];
      }));

      expect(undersized, path).toEqual([]);
    }
  });

  test("site nav is reserved for high-value destinations", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    for (const path of pages) {
      await page.goto(`${baseUrl}/${path}`, { waitUntil: "domcontentloaded" });
      const labels = await page.locator(".site-header__actions a").evaluateAll((links) =>
        links.map((link) => link.textContent.trim())
      );
      expect(labels, path).toEqual(expectedHighValueNav);
    }
  });

  test("wide browser windows use available layout space", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    await page.setViewportSize({ width: 1920, height: 1000 });
    await page.goto(`${baseUrl}/openshift-spo.html`, { waitUntil: "domcontentloaded" });

    const shellBox = await page.locator(".page-shell").boundingBox();
    const contentBox = await page.locator(".content-column").boundingBox();
    const leadBox = await page.locator(".markdown-body .lead").boundingBox();

    expect(shellBox.width).toBeGreaterThanOrEqual(1600);
    expect(contentBox.width).toBeGreaterThanOrEqual(1200);
    expect(leadBox.width).toBeLessThanOrEqual(1050);
  });

  test("docs accordion shows the active document branch", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    await page.goto(`${baseUrl}/quick-demo.html`, { waitUntil: "domcontentloaded" });

    const groups = await page.locator(".docs-map__group summary").evaluateAll((summaries) =>
      summaries.map((summary) => summary.textContent.trim())
    );
    expect(groups).toEqual(["Start Here", "Control Models", "Demos And Labs", "Security Review", "Reference"]);

    const current = page.locator(".docs-map a[aria-current='page']");
    await expect(current).toHaveText("AAP Lab");
    await expect(current.locator("xpath=ancestor::details[contains(@class, 'docs-map__group')]")).toHaveAttribute("open", "");

    const demoLinks = await page.locator(".docs-map__group", { hasText: "Demos And Labs" }).locator("a").evaluateAll((links) =>
      links.map((link) => link.textContent.trim())
    );
    expect(demoLinks).toEqual(["AAP Demo", "AAP Lab", "Ansible Demo", "Ansible Lab", "OpenShift/SPO Demo"]);
  });

  test("glossary hash targets clear the sticky header", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";

    await page.setViewportSize({ width: 733, height: 427 });
    await page.goto(`${baseUrl}/glossary.html#selinux-context`, { waitUntil: "domcontentloaded" });
    await page.waitForFunction(() => document.fonts?.status === "loaded");
    await page.waitForTimeout(250);

    const result = await page.evaluate(() => {
      const header = document.querySelector(".site-header").getBoundingClientRect();
      const target = document.getElementById("selinux-context").getBoundingClientRect();

      return {
        headerBottom: Math.round(header.bottom),
        targetTop: Math.round(target.top)
      };
    });

    expect(result.targetTop).toBeGreaterThanOrEqual(result.headerBottom + 16);
  });

  test("malformed hashes do not break site JavaScript", async ({ page }, testInfo) => {
    const baseUrl = testInfo.project.use.baseURL || process.env.BLASTWALL_DOCS_BASE_URL || "http://127.0.0.1:8765";
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));

    await page.goto(`${baseUrl}/glossary.html#%E0%A4%A`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(250);

    expect(pageErrors).toEqual([]);
    await expect(page.locator(".site-brand__title")).toBeVisible();
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

        if (/^https?:\/\//.test(href)) {
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
