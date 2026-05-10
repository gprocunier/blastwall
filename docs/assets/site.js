const configuredSiteBaseUrl = document.body?.dataset.baseurl || "";
const inferredGitHubPagesBaseUrl = (() => {
  if (!location.hostname.endsWith("github.io")) {
    return "";
  }

  const firstPathSegment = location.pathname.split("/").filter(Boolean)[0];
  return firstPathSegment ? `/${firstPathSegment}` : "";
})();
const siteBaseUrl = configuredSiteBaseUrl || inferredGitHubPagesBaseUrl;

const withBaseUrl = (path) => {
  if (!siteBaseUrl) {
    return path;
  }
  return `${siteBaseUrl}${path}`;
};

const SHIKI_CDN_URL = "https://esm.sh/shiki@4.0.2";
const SHIKI_THEME = "github-dark-high-contrast";
const CODEBOX_DEFAULT_LANGUAGE = "bash";
const CODEBOX_FALLBACK_LANGUAGE = "text";
const CODEBOX_SUPPORTED_LANGUAGES = [
  "bash",
  "text",
  "yaml",
  "json",
  "html",
  "xml",
  "javascript",
  "typescript",
  "python",
  "powershell",
  "toml"
];
const CODEBOX_LANGUAGE_ALIASES = {
  "": "text",
  bash: "bash",
  console: "bash",
  plaintext: "text",
  powershell: "powershell",
  ps1: "powershell",
  pwsh: "powershell",
  python: "python",
  py: "python",
  javascript: "javascript",
  js: "javascript",
  json: "json",
  shell: "bash",
  sh: "bash",
  text: "text",
  toml: "toml",
  ts: "typescript",
  typescript: "typescript",
  xml: "xml",
  html: "html",
  xhtml: "html",
  svg: "xml",
  yaml: "yaml",
  yml: "yaml"
};
const CODEBOX_LANGUAGE_LABELS = {
  bash: "Shell",
  html: "HTML",
  javascript: "JavaScript",
  json: "JSON",
  powershell: "PowerShell",
  python: "Python",
  text: "Text",
  toml: "TOML",
  typescript: "TypeScript",
  xml: "XML",
  yaml: "YAML"
};
const CODEBOX_POWERSHELL_MARKERS = [
  "write-host",
  "get-ad",
  "get-childitem",
  "new-",
  "set-",
  "add-",
  "remove-",
  "restart-",
  "stop-",
  "start-",
  "out-null",
  "$env:",
  "$psscriptroot",
  "-erroraction"
];
const CODEBOX_YAML_LINE_RE = /^\s*([A-Za-z0-9_.-]+:|- [A-Za-z0-9_.-]+:)/;

let shikiHighlighterPromise;

const renderAdmonitions = () => {
  document.querySelectorAll("blockquote").forEach((blockquote) => {
    const firstParagraph = blockquote.querySelector("p");
    if (!firstParagraph) {
      return;
    }

    const marker = firstParagraph.textContent.match(/^\s*\[!(IMPORTANT|NOTE|TIP|WARNING|CAUTION)\]\s*/);
    if (!marker) {
      return;
    }

    const kind = marker[1].toLowerCase();
    firstParagraph.innerHTML = firstParagraph.innerHTML.replace(/^\s*\[![A-Z]+\]\s*/, "");

    const title = document.createElement("p");
    title.className = "admonition-title";
    title.textContent = marker[1].charAt(0) + marker[1].slice(1).toLowerCase();

    blockquote.classList.add("admonition", "admonition-" + kind);
    blockquote.insertBefore(title, firstParagraph);
  });
};

const normalizeCodeLanguage = (language) => {
  const raw = readDatasetString(language).toLowerCase();
  return CODEBOX_LANGUAGE_ALIASES[raw] || raw || CODEBOX_FALLBACK_LANGUAGE;
};

const languageLabel = (language) => {
  return CODEBOX_LANGUAGE_LABELS[language] || language.toUpperCase();
};

const looksLikeJson = (text) => {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
};

const looksLikeYaml = (text) => {
  const lines = text.split("\n").filter((line) => line.trim());
  if (!lines.length) {
    return false;
  }

  const score = lines
    .slice(0, 8)
    .filter((line) => CODEBOX_YAML_LINE_RE.test(line))
    .length;

  return score >= 2 || (text.toLowerCase().includes("apiversion:") && text.toLowerCase().includes("kind:"));
};

const looksLikeHtmlOrXml = (text) => {
  const candidate = text.trimStart();
  return candidate.startsWith("<?xml") || (candidate.startsWith("<") && candidate.includes("</") && candidate.includes(">"));
};

const looksLikePython = (text) => {
  return text.includes("def ")
    || text.includes("import ")
    || text.includes("from ")
    || text.includes("print(")
    || text.startsWith("#!/usr/bin/env python");
};

const looksLikeJavascriptOrTypescript = (text) => {
  return [
    "const ",
    "let ",
    "function ",
    "=>",
    "console.log(",
    "export ",
    "import "
  ].some((marker) => text.includes(marker));
};

const looksLikeTypescript = (text) => {
  return [
    ": string",
    ": number",
    ": boolean",
    "interface ",
    "type ",
    " as const"
  ].some((marker) => text.includes(marker));
};

const inferCodeLanguage = (rawCode) => {
  const stripped = rawCode.trim();
  if (!stripped) {
    return CODEBOX_DEFAULT_LANGUAGE;
  }

  const lowered = stripped.toLowerCase();

  if (stripped.startsWith("#!") && (lowered.includes("bash") || lowered.includes("/sh"))) {
    return "bash";
  }

  if (CODEBOX_POWERSHELL_MARKERS.some((marker) => lowered.includes(marker))) {
    return "powershell";
  }

  if ((stripped.startsWith("{") || stripped.startsWith("[")) && looksLikeJson(stripped)) {
    return "json";
  }

  if (looksLikeYaml(stripped)) {
    return "yaml";
  }

  if (looksLikeHtmlOrXml(stripped)) {
    return stripped.trimStart().toLowerCase().startsWith("<!doctype html") || lowered.includes("<html")
      ? "html"
      : "xml";
  }

  if (looksLikePython(stripped)) {
    return "python";
  }

  if (looksLikeJavascriptOrTypescript(stripped)) {
    return looksLikeTypescript(stripped) ? "typescript" : "javascript";
  }

  return CODEBOX_DEFAULT_LANGUAGE;
};

const normalizeCodeText = (rawCode) => {
  return (rawCode || "").replace(/\n+$/, "");
};

const extractExplicitCodeLanguage = (codeElement) => {
  let node = codeElement;

  while (node && node instanceof HTMLElement) {
    for (const className of Array.from(node.classList)) {
      if (className.startsWith("language-")) {
        return {
          language: normalizeCodeLanguage(className.slice("language-".length)),
          explicit: true
        };
      }
    }

    if (node.classList.contains("markdown-body")) {
      break;
    }

    node = node.parentElement;
  }

  return {
    language: CODEBOX_FALLBACK_LANGUAGE,
    explicit: false
  };
};

const normalizeShikiCodeLines = (codeTag) => {
  if (!codeTag) {
    return;
  }

  const directLines = Array.from(codeTag.children).filter((child) => {
    return child instanceof HTMLElement && child.classList.contains("line");
  });

  if (!directLines.length) {
    return;
  }

  Array.from(codeTag.childNodes).forEach((child) => {
    if (child.nodeType === Node.TEXT_NODE && !child.textContent.trim()) {
      child.remove();
    }
  });

  while (directLines.length) {
    const lastLine = directLines[directLines.length - 1];
    if (lastLine.textContent) {
      break;
    }
    lastLine.remove();
    directLines.pop();
  }
};

const getShikiHighlighter = async () => {
  if (!shikiHighlighterPromise) {
    shikiHighlighterPromise = import(SHIKI_CDN_URL)
      .then(({ createHighlighter }) => {
        return createHighlighter({
          themes: [SHIKI_THEME],
          langs: CODEBOX_SUPPORTED_LANGUAGES
        });
      })
      .catch((error) => {
        shikiHighlighterPromise = undefined;
        throw error;
      });
  }

  return shikiHighlighterPromise;
};

const createFallbackPre = (rawCode, language) => {
  const pre = document.createElement("pre");
  const code = document.createElement("code");

  pre.classList.add("codebox__plain", `language-${language}`);
  code.classList.add(`language-${language}`);
  code.textContent = rawCode;
  pre.appendChild(code);

  return pre;
};

const renderHighlightedPre = (highlighter, rawCode, language) => {
  let finalLanguage = normalizeCodeLanguage(language);
  if (!CODEBOX_SUPPORTED_LANGUAGES.includes(finalLanguage)) {
    finalLanguage = CODEBOX_FALLBACK_LANGUAGE;
  }

  let html = "";

  try {
    html = highlighter.codeToHtml(rawCode, {
      lang: finalLanguage,
      theme: SHIKI_THEME
    });
  } catch (error) {
    console.warn(`Falling back to plain text highlighting for ${finalLanguage}`, error);
    finalLanguage = CODEBOX_FALLBACK_LANGUAGE;
    html = highlighter.codeToHtml(rawCode, {
      lang: CODEBOX_FALLBACK_LANGUAGE,
      theme: SHIKI_THEME
    });
  }

  const template = document.createElement("template");
  template.innerHTML = html.trim();

  const pre = template.content.querySelector("pre") || createFallbackPre(rawCode, finalLanguage);
  const code = pre.querySelector("code");

  pre.classList.add(`language-${finalLanguage}`);
  code?.classList.add(`language-${finalLanguage}`);
  normalizeShikiCodeLines(code);

  return {
    pre,
    language: finalLanguage
  };
};

const copyTextToClipboard = async (text) => {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "readonly");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();

  try {
    if (!document.execCommand("copy")) {
      throw new Error("document.execCommand('copy') returned false");
    }
  } finally {
    textarea.remove();
  }
};

const setCopyButtonState = (button, state) => {
  const label = button.querySelector(".codebox__copy-label");

  button.dataset.copyState = state;
  if (label) {
    label.textContent = state === "copied" ? "Copied" : state === "failed" ? "Failed" : "Copy";
  }
};

const createCodeboxActionButton = (className, label, iconPath, attrs = {}) => {
  const button = document.createElement("button");
  const icon = document.createElement("span");
  const text = document.createElement("span");

  button.className = className;
  button.type = "button";

  Object.entries(attrs).forEach(([key, value]) => {
    button.setAttribute(key, value);
  });

  icon.className = `${className}-icon`;
  icon.setAttribute("aria-hidden", "true");
  icon.innerHTML = `
    <svg viewBox="0 0 16 16" focusable="false">
      <path d="${iconPath}"></path>
    </svg>
  `;

  text.className = `${className}-label`;
  text.textContent = label;

  button.append(icon, text);

  return button;
};

const createCodebox = (pre, rawCode, language) => {
  const wrapper = document.createElement("div");
  const toolbar = document.createElement("div");
  const label = document.createElement("span");
  const actions = document.createElement("div");
  const copyButton = createCodeboxActionButton(
    "codebox__copy",
    "Copy",
    "M5 1.75A1.75 1.75 0 0 1 6.75 0h5.5A1.75 1.75 0 0 1 14 1.75v7.5A1.75 1.75 0 0 1 12.25 11h-5.5A1.75 1.75 0 0 1 5 9.25zm1.75-.25a.25.25 0 0 0-.25.25v7.5c0 .138.112.25.25.25h5.5a.25.25 0 0 0 .25-.25v-7.5a.25.25 0 0 0-.25-.25z M2.75 4A1.75 1.75 0 0 0 1 5.75v7.5C1 14.217 1.784 15 2.75 15h5.5A1.75 1.75 0 0 0 10 13.25V13H8.5v.25a.25.25 0 0 1-.25.25h-5.5a.25.25 0 0 1-.25-.25v-7.5a.25.25 0 0 1 .25-.25H3V4z",
    {
      "aria-label": `Copy ${languageLabel(language)} code to clipboard`,
      "data-copy-state": "idle"
    }
  );
  const wrapButton = createCodeboxActionButton(
    "codebox__wrap",
    "Wrap",
    "M2 3.75A.75.75 0 0 1 2.75 3h8.5a2.75 2.75 0 1 1 0 5.5H7.56l1.22 1.22a.75.75 0 1 1-1.06 1.06L5.22 8.28a.75.75 0 0 1 0-1.06l2.5-2.5a.75.75 0 1 1 1.06 1.06L7.56 7h3.69a1.25 1.25 0 1 0 0-2.5h-8.5A.75.75 0 0 1 2 3.75z M2 7.75A.75.75 0 0 1 2.75 7h1.5a.75.75 0 0 1 0 1.5h-1.5A.75.75 0 0 1 2 7.75zm0 4A.75.75 0 0 1 2.75 11h6.5a.75.75 0 0 1 0 1.5h-6.5A.75.75 0 0 1 2 11.75z",
    {
      "aria-label": `Toggle word wrap for ${languageLabel(language)} code`,
      "aria-pressed": "false"
    }
  );

  wrapper.className = "codebox";
  wrapper.dataset.language = language;
  wrapper.dataset.theme = SHIKI_THEME;

  toolbar.className = "codebox__toolbar";
  label.className = "codebox__language";
  label.textContent = languageLabel(language);
  actions.className = "codebox__actions";

  copyButton.addEventListener("click", async () => {
    clearTimeout(copyButton._codeboxResetTimer);

    try {
      await copyTextToClipboard(rawCode);
      setCopyButtonState(copyButton, "copied");
    } catch (error) {
      console.error("Unable to copy code block", error);
      setCopyButtonState(copyButton, "failed");
    }

    copyButton._codeboxResetTimer = window.setTimeout(() => {
      setCopyButtonState(copyButton, "idle");
    }, 5000);
  });

  wrapButton.addEventListener("click", () => {
    const enabled = wrapButton.getAttribute("aria-pressed") !== "true";
    wrapButton.setAttribute("aria-pressed", enabled ? "true" : "false");
    wrapper.classList.toggle("codebox--wrapped", enabled);
  });

  actions.append(copyButton, wrapButton);
  toolbar.append(label, actions);
  wrapper.append(toolbar, pre);

  return wrapper;
};

const collectCodeBlocks = () => {
  const seen = new Set();

  return Array.from(document.querySelectorAll(".markdown-body pre > code")).map((code) => {
    if (code.closest(".codebox")) {
      return null;
    }

    const explicitLanguage = extractExplicitCodeLanguage(code);

    const pre = code.parentElement;
    if (!(pre instanceof HTMLElement)) {
      return null;
    }

    const highlighterWrapper = pre.closest(".highlighter-rouge");
    const root = highlighterWrapper instanceof HTMLElement ? highlighterWrapper : pre;

    if (seen.has(root)) {
      return null;
    }
    seen.add(root);

    const rawCode = normalizeCodeText(code.textContent || "");
    const language = explicitLanguage.explicit ? explicitLanguage.language : inferCodeLanguage(rawCode);

    return {
      rawCode,
      root,
      language
    };
  }).filter(Boolean);
};

const renderCodeboxes = async () => {
  const blocks = collectCodeBlocks();
  if (!blocks.length) {
    return;
  }

  let highlighter;

  try {
    highlighter = await getShikiHighlighter();
  } catch (error) {
    console.error("Shiki could not be loaded; rendering plain code boxes instead.", error);
  }

  blocks.forEach((block) => {
    const rendered = highlighter
      ? renderHighlightedPre(highlighter, block.rawCode, block.language)
      : {
          pre: createFallbackPre(block.rawCode, block.language),
          language: block.language
        };

    block.root.replaceWith(createCodebox(rendered.pre, block.rawCode, rendered.language));
  });
};

const loadScript = (src) => new Promise((resolve, reject) => {
  const existing = document.querySelector(`script[data-src="${src}"]`);
  if (existing) {
    if (existing.dataset.loaded === "true") {
      resolve();
      return;
    }
    existing.addEventListener("load", () => resolve(), { once: true });
    existing.addEventListener("error", (event) => reject(event), { once: true });
    return;
  }

  const script = document.createElement("script");
  script.src = src;
  script.defer = true;
  script.dataset.src = src;
  script.addEventListener("load", () => {
    script.dataset.loaded = "true";
    resolve();
  }, { once: true });
  script.addEventListener("error", (event) => reject(event), { once: true });
  document.head.appendChild(script);
});

const ensureStylesheet = (href) => {
  if (document.querySelector(`link[data-href="${href}"]`)) {
    return;
  }

  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = href;
  link.dataset.href = href;
  document.head.appendChild(link);
};

const readDatasetString = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim();
};

const loadTerminalFont = async (fontFamily, fontSize) => {
  const requestedFamily = readDatasetString(fontFamily);
  if (!requestedFamily || !document.fonts?.load) {
    return;
  }

  const primaryFamily = requestedFamily.split(",")[0]?.trim();
  if (!primaryFamily) {
    return;
  }

  try {
    await document.fonts.load(`${readDatasetString(fontSize) || "10pt"} ${primaryFamily}`);
  } catch (error) {
    console.warn("Unable to preload terminal font", error);
  }
};

const renderAsciinemaPlayers = async () => {
  const players = document.querySelectorAll("[data-asciinema-src]");
  if (!players.length) {
    return;
  }

  ensureStylesheet(withBaseUrl("/assets/vendor/asciinema-player.css"));
  await loadScript(withBaseUrl("/assets/vendor/asciinema-player.min.js"));

  for (const container of players) {
    if (container.dataset.rendered === "true") {
      continue;
    }

    const src = container.dataset.asciinemaSrc;
    const poster = container.dataset.asciinemaPoster || "npt:0:08";
    const speed = Number(container.dataset.asciinemaSpeed || "1.3");
    const cols = Number(container.dataset.asciinemaCols || "132");
    const rows = Number(container.dataset.asciinemaRows || "40");
    const idleTimeLimit = Number(container.dataset.asciinemaIdleTimeLimit || "");
    const terminalFontFamily = readDatasetString(container.dataset.asciinemaTerminalFontFamily);
    const terminalFontSize = readDatasetString(container.dataset.asciinemaTerminalFontSize);
    const playerOptions = {
      autoPlay: false,
      controls: true,
      fit: "width",
      speed,
      poster,
      cols,
      rows
    };

    if (Number.isFinite(idleTimeLimit) && idleTimeLimit > 0) {
      playerOptions.idleTimeLimit = idleTimeLimit;
    }

    if (terminalFontFamily) {
      playerOptions.terminalFontFamily = terminalFontFamily;
    }

    if (terminalFontSize) {
      playerOptions.terminalFontSize = terminalFontSize;
    }

    await loadTerminalFont(terminalFontFamily, terminalFontSize);
    window.AsciinemaPlayer.create(src, container, playerOptions);

    container.dataset.rendered = "true";
  }
};

const renderToc = () => {
  const tocList = document.querySelector("[data-generated-toc]");
  if (!tocList) {
    return;
  }

  const tocBlock = tocList.closest(".toc-block");
  const rootSelector = tocBlock?.dataset.tocRoot || ".markdown-body";
  const levels = (tocBlock?.dataset.tocLevels || "h2,h3").split(",");
  const root = document.querySelector(rootSelector);
  if (!root) {
    return;
  }

  const headings = Array.from(root.querySelectorAll(levels.join(","))).filter((heading) => {
    return heading.id && heading.textContent.trim() && heading.textContent.trim() !== "Related docs:";
  });

  if (!headings.length) {
    tocBlock?.remove();
    return;
  }

  tocList.innerHTML = "";

  headings.forEach((heading) => {
    const item = document.createElement("li");
    item.className = `toc-${heading.tagName.toLowerCase()}`;

    const link = document.createElement("a");
    link.href = `#${heading.id}`;
    link.textContent = heading.textContent.trim();

    item.appendChild(link);
    tocList.appendChild(item);
  });
};

const docsMap = [
  {
    label: "Start Here",
    pages: [
      { href: "./", paths: ["", "index.html"], label: "Overview" },
      { href: "architecture.html", label: "Architecture" },
      { href: "day2-operations.html", label: "Day 2 Operations" },
      { href: "openshift-spo.html", label: "OpenShift/SPO" }
    ]
  },
  {
    label: "Control Models",
    pages: [
      { href: "idm-control-model.html", label: "IdM Control Model" },
      { href: "selinux-control-model.html", label: "SELinux Control Model" }
    ]
  },
  {
    label: "Demos And Labs",
    pages: [
      { href: "aap-demo.html", label: "AAP Demo" },
      { href: "quick-demo.html", label: "AAP Lab" },
      { href: "demo.html", label: "Ansible Demo" },
      { href: "ansible-lab.html", label: "Ansible Lab" },
      { href: "poc-flow.html", label: "Ansible Lab Flow" },
      { href: "openshift-spo-demo.html", label: "OpenShift/SPO Demo" }
    ]
  },
  {
    label: "Security Review",
    pages: [
      { href: "comparable-approaches.html", label: "Comparison" },
      { href: "threat-model.html", label: "Threat Model" }
    ]
  },
  {
    label: "Reference",
    pages: [
      { href: "glossary.html", label: "Glossary" },
      { href: "reference.html", label: "Reference" },
      { href: "https://github.com/gprocunier/blastwall", label: "Source" }
    ]
  }
];

const currentDocsPath = () => {
  const path = window.location.pathname.split("/").pop() || "index.html";
  return path === "" ? "index.html" : path;
};

const isCurrentDocsPage = (page, currentPath) => {
  const paths = page.paths || [page.href];
  return paths.some((path) => {
    if (/^https?:\/\//.test(path)) {
      return false;
    }

    const normalized = path.replace(/^\.\//, "") || "index.html";
    return normalized === currentPath;
  });
};

const renderDocsMap = () => {
  const sideColumn = document.querySelector(".side-column");
  if (!sideColumn || sideColumn.querySelector(".docs-map")) {
    return;
  }

  const currentPath = currentDocsPath();
  const section = document.createElement("section");
  section.className = "docs-map";
  section.setAttribute("aria-label", "Documentation map");

  const heading = document.createElement("h2");
  heading.textContent = "Documentation";

  const nav = document.createElement("nav");
  nav.setAttribute("aria-label", "Documentation sections");

  docsMap.forEach((group) => {
    const details = document.createElement("details");
    details.className = "docs-map__group";

    const hasCurrentPage = group.pages.some((page) => isCurrentDocsPage(page, currentPath));
    if (hasCurrentPage) {
      details.open = true;
    }

    const summary = document.createElement("summary");
    summary.textContent = group.label;
    details.appendChild(summary);

    const list = document.createElement("ol");
    list.className = "docs-map__links";

    group.pages.forEach((page) => {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.href = page.href;
      link.textContent = page.label;

      if (isCurrentDocsPage(page, currentPath)) {
        link.className = "is-current";
        link.setAttribute("aria-current", "page");
      }

      item.appendChild(link);
      list.appendChild(item);
    });

    details.appendChild(list);
    nav.appendChild(details);
  });

  section.append(heading, nav);
  sideColumn.prepend(section);
};

const safeDecodeHash = (value) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const activateTocOnScroll = () => {
  const links = Array.from(document.querySelectorAll(".toc-block a[href^='#']"));
  if (!links.length || !("IntersectionObserver" in window)) {
    return;
  }

  const linkById = new Map(
    links.map((link) => [safeDecodeHash(link.getAttribute("href").slice(1)), link])
  );

  let activeId = "";

  const setActive = (id) => {
    if (!id || id === activeId) {
      return;
    }
    activeId = id;
    links.forEach((link) => {
      link.classList.toggle("is-active", link === linkById.get(id));
    });
  };

  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top);

    if (visible.length) {
      setActive(visible[0].target.id);
    }
  }, {
    rootMargin: "-20% 0px -65% 0px",
    threshold: [0, 1]
  });

  linkById.forEach((_, id) => {
    const heading = document.getElementById(id);
    if (heading) {
      observer.observe(heading);
    }
  });

  if (links[0]) {
    const initialId = safeDecodeHash(links[0].getAttribute("href").slice(1));
    setActive(initialId);
  }
};

const activateDiagramLightbox = () => {
  const diagrams = Array.from(document.querySelectorAll(".diagram-artifact"));
  if (!diagrams.length) {
    return;
  }

  const overlay = document.createElement("div");
  overlay.className = "diagram-lightbox";
  overlay.hidden = true;
  overlay.setAttribute("aria-hidden", "true");

  const frame = document.createElement("div");
  frame.className = "diagram-lightbox__frame";
  frame.setAttribute("role", "dialog");
  frame.setAttribute("aria-modal", "true");
  frame.setAttribute("aria-label", "Expanded diagram");

  const close = document.createElement("button");
  close.className = "diagram-lightbox__close";
  close.type = "button";
  close.textContent = "Close";

  const image = document.createElement("img");
  image.className = "diagram-lightbox__image";
  image.alt = "";

  frame.append(close, image);
  overlay.append(frame);
  document.body.append(overlay);

  let activeDiagram = null;

  const closeLightbox = () => {
    overlay.hidden = true;
    overlay.setAttribute("aria-hidden", "true");
    document.body.classList.remove("has-diagram-lightbox");
    image.removeAttribute("src");

    if (activeDiagram) {
      activeDiagram.focus();
      activeDiagram = null;
    }
  };

  const openLightbox = (diagram) => {
    activeDiagram = diagram;
    image.src = diagram.currentSrc || diagram.src;
    image.alt = diagram.alt || "Expanded diagram";
    overlay.hidden = false;
    overlay.setAttribute("aria-hidden", "false");
    document.body.classList.add("has-diagram-lightbox");
    close.focus();
  };

  diagrams.forEach((diagram) => {
    diagram.tabIndex = 0;
    diagram.title = "Click to enlarge";
    diagram.setAttribute("role", "button");
    diagram.setAttribute("aria-label", `${diagram.alt || "Diagram"}; click to enlarge`);

    diagram.addEventListener("click", () => openLightbox(diagram));
    diagram.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openLightbox(diagram);
      }
    });
  });

  close.addEventListener("click", closeLightbox);
  image.addEventListener("click", closeLightbox);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      closeLightbox();
    }
  });

  window.addEventListener("keydown", (event) => {
    if (!overlay.hidden && event.key === "Escape") {
      closeLightbox();
    }
  });
};

const headerAnchorOffset = () => {
  const header = document.querySelector(".site-header");
  const headerHeight = header ? Math.ceil(header.getBoundingClientRect().height) : 0;
  return headerHeight + 24;
};

const setAnchorOffset = () => {
  document.documentElement.style.setProperty("--blastwall-anchor-offset", `${headerAnchorOffset()}px`);
};

const scrollHashTargetIntoView = () => {
  if (!window.location.hash) {
    return;
  }

  const id = safeDecodeHash(window.location.hash.slice(1));
  const target = document.getElementById(id);
  if (!target) {
    return;
  }

  const top = target.getBoundingClientRect().top + window.scrollY - headerAnchorOffset();
  window.scrollTo({
    top: Math.max(0, top),
    behavior: "auto"
  });
};

const activateAnchorOffsets = () => {
  setAnchorOffset();
  window.addEventListener("resize", setAnchorOffset);
  window.addEventListener("hashchange", () => {
    setAnchorOffset();
    requestAnimationFrame(scrollHashTargetIntoView);
  });

  requestAnimationFrame(() => {
    setAnchorOffset();
    scrollHashTargetIntoView();
  });

  if (document.fonts?.ready) {
    document.fonts.ready.then(() => {
      setAnchorOffset();
      scrollHashTargetIntoView();
    });
  }
};

window.addEventListener("DOMContentLoaded", async () => {
  activateAnchorOffsets();
  renderAdmonitions();
  renderDocsMap();
  renderToc();
  activateTocOnScroll();
  activateDiagramLightbox();
  await renderCodeboxes();
  await renderAsciinemaPlayers();
});
