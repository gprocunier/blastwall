#!/usr/bin/env python3
"""Render Blastwall v3 Markdown packet pages as GitHub Pages HTML."""

from __future__ import annotations

import argparse
import html
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = REPO_ROOT / "docs"
V3_ROOT = DOCS_ROOT / "blastwall-v3"
GITHUB_BLOB = "https://github.com/gprocunier/blastwall/blob/v3"


DOC_GROUPS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    (
        "Review Entry Points",
        (
            ("External Review Packet", "external-review-packet.html"),
            ("Signed Attestation Design", "signed-attestation-design.html"),
            ("Evidence Index", "evidence-index.html"),
            ("Final Decision", "final-stable-v3-decision.html"),
        ),
    ),
    (
        "Operate The Exemplar",
        (
            ("Operator Runbook", "operator-runbook.html"),
            ("Operational Guidance", "operational-guidance.html"),
            ("KRA Topology Runbook", "kra-topology-runbook.html"),
            ("Revocation And Breakglass", "revocation-and-breakglass.html"),
            ("Readiness Checklist", "stable-v3-readiness-checklist.html"),
        ),
    ),
    (
        "Evidence And Exercises",
        (
            ("Calabi Negative Evidence", "calabi-negative-evidence.html"),
            ("Evidence Consistency Matrix", "evidence-consistency-matrix.html"),
            ("Scheduled Loop Soak", "scheduled-loop-soak.html"),
            ("Multi-Host Verification Plan", "multi-host-continuous-verification-plan.html"),
            ("Second Maintainer Exercise", "second-maintainer-diagnostic-exercise.html"),
        ),
    ),
    (
        "Reference",
        (
            ("eigenstate.ipa 1.18.1 Integration", "eigenstate-1.18.1-integration.html"),
            ("Governance Worksheet", "governance-owner-assignment.html"),
            ("Shell And Collection Exceptions", "shell-and-collection-exceptions.html"),
            ("Stable-v3 Reference Decision", "stable-v3-rc-decision.html"),
            ("Stable-v3 Release Decision", "stable-v3-release-decision.html"),
        ),
    ),
)


DIAGRAMS_BY_DOC: dict[str, tuple[tuple[str, str, str], ...]] = {
    "external-review-packet.md": (
        ("v3-marker-locator-flow.svg", "Marker Is Locator, Evidence Is Proof", "Inventory selection remains useful, while signed evidence and live checks decide trust."),
        ("v3-calabi-reference-topology.svg", "Calabi Reference Topology", "The evidence packet is grounded in the demonstration control path."),
    ),
    "signed-attestation-design.md": (
        ("v3-marker-locator-flow.svg", "Marker And Evidence Boundary", "The marker points to proof; it is not the proof."),
        ("v3-stable-preflight-decision.svg", "Stable-v3 Preflight Decision", "Each candidate passes through the same verification sequence."),
        ("v3-failure-state-map.svg", "Failure-State Map", "Verifier failures are named for audit and recovery."),
    ),
    "operator-runbook.md": (
        ("v3-operating-loop.svg", "Signed Evidence Operating Loop", "The normal run path links capture, signing, publication, launch, and audit."),
        ("v3-stable-preflight-decision.svg", "Preflight Decision Path", "Operators route outcomes by the verifier's named failure state."),
    ),
    "operational-guidance.md": (
        ("v3-custody-boundary.svg", "Custody Boundary", "Stable-v3 examples prefer service-owned signer and vault principals."),
        ("v3-adopter-readiness.svg", "Adopter Readiness Path", "Local operation needs owner assignment, custody choices, evidence replay, and decision records."),
    ),
    "kra-topology-runbook.md": (
        ("v3-custody-boundary.svg", "KRA Custody Boundary", "Vault custody and verifier access are part of the trust path."),
        ("v3-calabi-reference-topology.svg", "Reference Topology", "KRA behavior is evidenced in the demonstration topology."),
    ),
    "revocation-and-breakglass.md": (
        ("v3-breakglass-scope.svg", "Breakglass Scope", "Breakglass is scoped to infrastructure visibility and cannot bypass proof failures."),
        ("v3-failure-state-map.svg", "Failure-State Map", "Revocation, replay, drift, and binding failures remain fail-closed."),
    ),
    "evidence-index.md": (
        ("v3-failure-state-map.svg", "Failure-State Coverage", "Evidence is organized around stable verifier outcomes."),
    ),
    "stable-v3-readiness-checklist.md": (
        ("v3-adopter-readiness.svg", "Adopter Readiness Path", "The checklist turns the exemplar into a local operating decision."),
    ),
    "calabi-negative-evidence.md": (
        ("v3-failure-state-map.svg", "Failure-State Evidence Map", "Destructive checks prove named fail-closed behavior in the lab path."),
    ),
    "multi-host-continuous-verification-plan.md": (
        ("v3-operating-loop.svg", "Continuous Verification Loop", "Scheduled checks keep the evidence path visible over time."),
    ),
}


@dataclass(frozen=True)
class RenderedPage:
    source: Path
    output: Path
    title: str
    description: str
    headings: tuple[tuple[int, str, str], ...]
    body: str


def slugify(value: str) -> str:
    return (
        value.lower()
        .replace("`", "")
        .replace("*", "")
        .replace("_", "")
        .replace("~", "")
    )


def markdown_heading_anchor(heading: str) -> str:
    cleaned = re.sub(r"[^\w\s-]", "", slugify(heading)).strip()
    return re.sub(r"\s+", "-", cleaned)


def unique_id(base: str, seen: dict[str, int]) -> str:
    candidate = base or "section"
    count = seen.get(candidate, 0)
    seen[candidate] = count + 1
    return candidate if count == 0 else f"{candidate}-{count + 1}"


def split_link_target(target: str) -> tuple[str, str]:
    if "#" not in target:
        return target, ""
    path, fragment = target.split("#", 1)
    return path, f"#{fragment}"


def normalize_href(target: str, source: Path) -> str:
    if (
        target.startswith("#")
        or target.startswith("mailto:")
        or target.startswith("http://")
        or target.startswith("https://")
    ):
        return target

    path_text, fragment = split_link_target(target)
    if not path_text:
        return target

    resolved = (source.parent / path_text).resolve()
    try:
        relative_to_v3 = resolved.relative_to(V3_ROOT)
    except ValueError:
        relative_to_v3 = None

    if relative_to_v3 is not None and resolved.suffix == ".md":
        return relative_to_v3.with_suffix(".html").as_posix() + fragment

    try:
        relative_to_repo = resolved.relative_to(REPO_ROOT)
    except ValueError:
        relative_to_repo = None

    if relative_to_repo is not None and resolved.suffix in {".md", ".yml", ".yaml", ".py"} and not resolved.is_relative_to(DOCS_ROOT):
        return f"{GITHUB_BLOB}/{relative_to_repo.as_posix()}{fragment}"

    return target


def render_inline_fragment(text: str) -> str:
    escaped = html.escape(text, quote=True)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"__([^_]+)__", r"<strong>\1</strong>", escaped)
    return escaped


def render_inline(text: str, source: Path) -> str:
    code_fragments: list[str] = []
    link_fragments: list[str] = []

    def store_code(match: re.Match[str]) -> str:
        code_fragments.append(f"<code>{html.escape(match.group(1), quote=False)}</code>")
        return f"\u0000CODE{len(code_fragments) - 1}\u0000"

    text = re.sub(r"`([^`]+)`", store_code, text)

    def replace_link(match: re.Match[str]) -> str:
        label = render_inline_fragment(match.group(1))
        href = html.escape(normalize_href(match.group(2).strip(), source), quote=True)
        link_fragments.append(f'<a href="{href}">{label}</a>')
        return f"\u0000LINK{len(link_fragments) - 1}\u0000"

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", replace_link, text)
    text = render_inline_fragment(text)

    for index, fragment in enumerate(code_fragments):
        text = text.replace(html.escape(f"\u0000CODE{index}\u0000"), fragment)
    for index, fragment in enumerate(link_fragments):
        text = text.replace(html.escape(f"\u0000LINK{index}\u0000"), fragment)
    return text


def is_heading(line: str) -> bool:
    return bool(re.match(r"^#{1,6}\s+\S", line))


def is_fence(line: str) -> bool:
    return line.startswith("```")


def is_list_item(line: str) -> bool:
    return bool(re.match(r"^\s*(?:[-*+]\s+|\d+\.\s+)", line))


def is_table_start(lines: list[str], index: int) -> bool:
    if index + 1 >= len(lines):
        return False
    current = lines[index].strip()
    separator = lines[index + 1].strip()
    return (
        current.startswith("|")
        and current.endswith("|")
        and separator.startswith("|")
        and separator.endswith("|")
        and bool(re.fullmatch(r"\|[\s:.\-|]+\|", separator))
    )


class MarkdownRenderer:
    def __init__(self, source: Path) -> None:
        self.source = source
        self.lines = source.read_text(encoding="utf-8").splitlines()
        self.index = 0
        self.heading_ids: dict[str, int] = {}
        self.headings: list[tuple[int, str, str]] = []
        self.first_h1_seen = False

    def render(self) -> str:
        chunks: list[str] = []
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if not line.strip():
                self.index += 1
                continue
            if is_fence(line):
                chunks.append(self.render_code_fence())
                continue
            if is_heading(line):
                rendered = self.render_heading(line)
                if rendered:
                    chunks.append(rendered)
                self.index += 1
                continue
            if is_table_start(self.lines, self.index):
                chunks.append(self.render_table())
                continue
            if line.startswith(">"):
                chunks.append(self.render_blockquote())
                continue
            if is_list_item(line):
                chunks.append(self.render_list())
                continue
            chunks.append(self.render_paragraph())
        return "\n".join(chunks)

    def render_heading(self, line: str) -> str:
        match = re.match(r"^(#{1,6})\s+(.+)$", line)
        assert match
        level = len(match.group(1))
        text = match.group(2).strip()
        if level == 1 and not self.first_h1_seen:
            self.first_h1_seen = True
            return ""
        anchor = unique_id(markdown_heading_anchor(text), self.heading_ids)
        self.headings.append((level, text, anchor))
        html_level = min(max(level, 2), 6)
        return f'<h{html_level} id="{anchor}">{render_inline(text, self.source)}</h{html_level}>'

    def render_code_fence(self) -> str:
        opener = self.lines[self.index].strip()
        language = opener.removeprefix("```").strip().split(" ", 1)[0] or "text"
        self.index += 1
        code_lines: list[str] = []
        while self.index < len(self.lines) and not self.lines[self.index].startswith("```"):
            code_lines.append(self.lines[self.index])
            self.index += 1
        if self.index < len(self.lines):
            self.index += 1
        code = html.escape("\n".join(code_lines), quote=False)
        language_class = re.sub(r"[^A-Za-z0-9_-]", "", language) or "text"
        return f'<pre><code class="language-{language_class}">{code}</code></pre>'

    def render_table(self) -> str:
        table_lines: list[str] = []
        while self.index < len(self.lines) and self.lines[self.index].strip().startswith("|"):
            table_lines.append(self.lines[self.index].strip())
            self.index += 1

        rows = [
            [cell.strip() for cell in row.strip("|").split("|")]
            for row in table_lines
        ]
        header = rows[0]
        body = rows[2:]
        rendered = ['<table class="comparison-table">', "<thead><tr>"]
        rendered.extend(f"<th>{render_inline(cell, self.source)}</th>" for cell in header)
        rendered.append("</tr></thead>")
        rendered.append("<tbody>")
        for row in body:
            rendered.append("<tr>")
            for index, cell in enumerate(row):
                label = html.escape(header[index] if index < len(header) else "", quote=True)
                rendered.append(f'<td data-label="{label}">{render_inline(cell, self.source)}</td>')
            rendered.append("</tr>")
        rendered.append("</tbody></table>")
        return "\n".join(rendered)

    def render_blockquote(self) -> str:
        quote_lines: list[str] = []
        while self.index < len(self.lines) and self.lines[self.index].startswith(">"):
            quote_lines.append(self.lines[self.index].lstrip(">").strip())
            self.index += 1
        paragraphs = "\n".join(quote_lines).split("\n\n")
        body = "".join(
            f"<p>{render_inline(' '.join(part.splitlines()).strip(), self.source)}</p>"
            for part in paragraphs
            if part.strip()
        )
        return f"<blockquote>{body}</blockquote>"

    def render_list(self) -> str:
        ordered = bool(re.match(r"^\s*\d+\.\s+", self.lines[self.index]))
        tag = "ol" if ordered else "ul"
        items: list[str] = []
        current: list[str] = []
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if not line.strip():
                break
            match = re.match(r"^\s*(?:[-*+]\s+|\d+\.\s+)(.*)$", line)
            if match:
                if current:
                    items.append(" ".join(current).strip())
                current = [match.group(1).strip()]
                self.index += 1
                continue
            if current and (line.startswith("  ") or line.startswith("\t")):
                current.append(line.strip())
                self.index += 1
                continue
            break
        if current:
            items.append(" ".join(current).strip())
        return f"<{tag}>" + "".join(f"<li>{render_inline(item, self.source)}</li>" for item in items) + f"</{tag}>"

    def render_paragraph(self) -> str:
        parts: list[str] = []
        while self.index < len(self.lines):
            line = self.lines[self.index]
            if (
                not line.strip()
                or is_heading(line)
                or is_fence(line)
                or line.startswith(">")
                or is_list_item(line)
                or is_table_start(self.lines, self.index)
            ):
                break
            parts.append(line.strip())
            self.index += 1
        text = " ".join(parts)
        return f"<p>{render_inline(text, self.source)}</p>"


def extract_title(source: Path) -> str:
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line.removeprefix("# ").strip()
    return source.stem.replace("-", " ").title()


def extract_description(source: Path) -> str:
    lines = source.read_text(encoding="utf-8").splitlines()
    started = False
    in_fence = False
    parts: list[str] = []
    for line in lines:
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("# "):
            started = True
            continue
        if not started or not line.strip() or line.startswith("#"):
            if parts:
                break
            continue
        if line.startswith(("-", "*", "|", "```")):
            if parts:
                break
            continue
        parts.append(line.strip())
        if len(" ".join(parts)) > 220:
            break
    description = re.sub(r"`([^`]+)`", r"\1", " ".join(parts)).strip()
    return description or "Blastwall v3 signed-evidence reference documentation."


def diagram_figures(source: Path) -> str:
    figures = []
    for filename, title, caption in DIAGRAMS_BY_DOC.get(source.name, ()):
        alt = title
        figures.append(
            "\n".join(
                [
                    f'<figure class="diagram-card diagram-card--focus" id="{Path(filename).stem}">',
                    "<figcaption>",
                    f"<strong>{html.escape(title)}</strong>",
                    f"<span>{html.escape(caption)}</span>",
                    "</figcaption>",
                    f'<img class="diagram-artifact" src="../assets/diagrams/{filename}" alt="{html.escape(alt, quote=True)}">',
                    "</figure>",
                ]
            )
        )
    return "\n".join(figures)


def docs_map(current: Path) -> str:
    groups = ['<nav class="docs-map" aria-label="Blastwall v3 document map">', "<h2>v3 Packet</h2>"]
    current_name = current.with_suffix(".html").name
    for group_title, links in DOC_GROUPS:
        open_attr = " open" if any(href == current_name for _, href in links) else ""
        groups.append(f'<details class="docs-map__group"{open_attr}>')
        groups.append(f"<summary>{html.escape(group_title)}</summary>")
        groups.append('<ul class="docs-map__links">')
        for label, href in links:
            current_attrs = ' class="is-current" aria-current="page"' if href == current_name else ""
            groups.append(f'<li><a href="{href}"{current_attrs}>{html.escape(label)}</a></li>')
        groups.append("</ul>")
        groups.append("</details>")
    groups.append("</nav>")
    return "\n".join(groups)


def toc(headings: tuple[tuple[int, str, str], ...]) -> str:
    entries = [
        f'<li><a href="#{anchor}">{html.escape(text)}</a></li>'
        for level, text, anchor in headings
        if level <= 2
    ][:12]
    if not entries:
        return ""
    return '<section class="toc-block"><h2>On This Page</h2><ol class="path-list">' + "".join(entries) + "</ol></section>"


def render_page(source: Path, output: Path) -> RenderedPage:
    renderer = MarkdownRenderer(source)
    body = renderer.render()
    return RenderedPage(
        source=source,
        output=output,
        title=extract_title(source),
        description=extract_description(source),
        headings=tuple(renderer.headings),
        body=body,
    )


def page_html(page: RenderedPage) -> str:
    title = html.escape(page.title)
    description = html.escape(page.description)
    source_rel = page.source.relative_to(REPO_ROOT).as_posix()
    source_url = f"{GITHUB_BLOB}/{source_rel}"
    diagram_html = diagram_figures(page.source)
    toc_html = toc(page.headings)
    docs_map_html = docs_map(page.output)
    return f"""<!doctype html>
<!-- Generated by tools/render_v3_docs.py; edit {source_rel}. -->
<html lang="en-US">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title} | blastwall v3</title>
    <meta name="description" content="{description}">
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{description}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="https://blastwall.org/v3/blastwall-v3/{page.output.name}">
    <meta name="twitter:card" content="summary_large_image">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Red+Hat+Display:wght@500;700&family=Red+Hat+Mono:wght@400;500&family=Red+Hat+Text:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="icon" href="../favicon.ico" sizes="any">
    <link rel="stylesheet" href="../assets/site.css">
    <script type="module" src="../assets/site.js"></script>
  </head>
  <body>
    <header class="site-header">
      <div class="site-header__inner">
        <p class="eyebrow">Blastwall v3 Documentation</p>
        <div class="site-brand">
          <div>
            <h1 class="site-brand__title"><a href="../">blastwall v3</a></h1>
            <p class="site-brand__tagline">Signed evidence gates for privileged automation in the Calabi reference exemplar.</p>
          </div>
        </div>
        <nav class="site-header__actions" aria-label="Project links">
          <a href="https://github.com/gprocunier/blastwall/tree/v3"><kbd>GitHub Repo</kbd></a>
          <a href="https://gprocunier.github.io/eigenstate-ipa/"><kbd>eigenstate.ipa</kbd></a>
          <a href="https://galaxy.ansible.com/ui/repo/published/eigenstate/ipa/"><kbd>Ansible Galaxy</kbd></a>
        </nav>
      </div>
    </header>

    <main class="page-shell page-shell--wide">
      <article class="content-column markdown-body v3-doc">
        <p class="eyebrow">v3 packet</p>
        <h1 class="doc-title">{title}</h1>
        <p class="lead">{description}</p>
        {diagram_html}
        {page.body}
      </article>

      <aside class="side-column" aria-label="Page context">
        <section class="context-block context-block--meta">
          <h2>v3 Exemplar</h2>
          <p class="context-kicker">Signed evidence gate</p>
          <p class="context-copy">Use these pages with the v3 branch and the Calabi reference evidence packet.</p>
        </section>
        {toc_html}
        {docs_map_html}
        <section class="source-block">
          <h2>Source</h2>
          <p><a href="{source_url}">Edit the Markdown source</a> or return to the <a href="../">v3 home page</a>.</p>
        </section>
      </aside>
    </main>

    <footer class="site-footer">
      <p>GPL-3.0 licensed proof of concept. Source lives at <a href="https://github.com/gprocunier/blastwall/tree/v3">github.com/gprocunier/blastwall/tree/v3</a>.</p>
    </footer>
  </body>
</html>
"""


def render_all(output_root: Path = V3_ROOT) -> dict[Path, str]:
    rendered: dict[Path, str] = {}
    for source in sorted(V3_ROOT.glob("*.md")):
        output = output_root / source.with_suffix(".html").name
        page = render_page(source, output)
        rendered[output] = "\n".join(line.rstrip() for line in page_html(page).splitlines()) + "\n"
    return rendered


def write_all(output_root: Path = V3_ROOT) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    for output, content in render_all(output_root).items():
        output.write_text(content, encoding="utf-8")


def check_all() -> int:
    stale: list[str] = []
    expected = render_all(V3_ROOT)
    for output, content in expected.items():
        if not output.exists() or output.read_text(encoding="utf-8") != content:
            stale.append(str(output.relative_to(REPO_ROOT)))
    if stale:
        print("Stale generated v3 docs:")
        for path in stale:
            print(f"  {path}")
        return 1

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        temp_rendered = render_all(temp_root)
        if len(temp_rendered) != len(expected):
            print("Unexpected v3 docs render count mismatch")
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify generated HTML is current without writing")
    args = parser.parse_args()
    if args.check:
        return check_all()
    write_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
