#!/usr/bin/env python3
"""Render Blastwall v3 diagram source and publication SVGs."""

from __future__ import annotations

import argparse
import html
from dataclasses import dataclass, field
from pathlib import Path


CANVAS = "#ffffff"
INK = "#151515"
MUTED = "#4d4d4d"
RED = "#ee0000"
RED_DARK = "#a30000"
GRAY_10 = "#f5f5f5"
GRAY_20 = "#e0e0e0"
GRAY_30 = "#c7c7c7"
BLUE = "#0066cc"
GREEN = "#3d7317"
AMBER = "#f0ab00"


@dataclass(frozen=True)
class Card:
    x: int
    y: int
    w: int
    h: int
    title: tuple[str, ...]
    body: tuple[str, ...] = ()
    tone: str = "default"


@dataclass(frozen=True)
class Label:
    x: int
    y: int
    lines: tuple[str, ...]
    tone: str = "muted"
    anchor: str = "middle"


@dataclass(frozen=True)
class Lane:
    x: int
    y: int
    w: int
    h: int
    title: str
    tone: str = "default"


@dataclass(frozen=True)
class Connector:
    points: tuple[tuple[int, int], ...]
    tone: str = "default"
    dashed: bool = False
    label: str | None = None
    label_pos: tuple[int, int] | None = None


@dataclass(frozen=True)
class Diagram:
    name: str
    title: str
    desc: str
    width: int
    height: int
    lanes: tuple[Lane, ...] = ()
    cards: tuple[Card, ...] = ()
    connectors: tuple[Connector, ...] = ()
    labels: tuple[Label, ...] = ()
    mermaid: str = ""


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def text_lines(lines: tuple[str, ...] | str, x: int, y: int, class_name: str, anchor: str = "start", gap: int = 16) -> str:
    if isinstance(lines, str):
        lines = (lines,)

    rendered = [
        f'<text class="{class_name}" x="{x}" y="{y}" text-anchor="{anchor}">'
    ]
    for index, line in enumerate(lines):
        dy = 0 if index == 0 else gap
        rendered.append(f'<tspan x="{x}" dy="{dy}">{esc(line)}</tspan>')
    rendered.append("</text>")
    return "\n".join(rendered)


def card_classes(card: Card) -> str:
    return f"card card--{card.tone}"


def render_card(card: Card) -> str:
    title_y = card.y + 30
    body_y = title_y + (len(card.title) * 15) + 4
    body = [
        f'<g class="{card_classes(card)}">',
        f'<rect x="{card.x}" y="{card.y}" width="{card.w}" height="{card.h}" rx="6" />',
        text_lines(card.title, card.x + 18, title_y, "card-title"),
    ]
    if card.body:
        body.append(text_lines(card.body, card.x + 18, body_y, "card-body", gap=13))
    body.append("</g>")
    return "\n".join(body)


def render_lane(lane: Lane) -> str:
    title_y = lane.y + 28
    return "\n".join(
        [
            f'<g class="lane lane--{lane.tone}">',
            f'<rect x="{lane.x}" y="{lane.y}" width="{lane.w}" height="{lane.h}" rx="8" />',
            text_lines((lane.title,), lane.x + 18, title_y, "lane-title"),
            "</g>",
        ]
    )


def render_connector(connector: Connector) -> str:
    points = " ".join(f"{x},{y}" for x, y in connector.points)
    classes = ["connector", f"connector--{connector.tone}"]
    if connector.dashed:
        classes.append("connector--dashed")
    rendered = [f'<polyline class="{" ".join(classes)}" points="{points}" marker-end="url(#arrow-{connector.tone})" />']
    if connector.label and connector.label_pos:
        x, y = connector.label_pos
        rendered.append(f'<text class="connector-label" x="{x}" y="{y}" text-anchor="middle">{esc(connector.label)}</text>')
    return "\n".join(rendered)


def render_label(label: Label) -> str:
    class_name = f"standalone-label standalone-label--{label.tone}"
    return text_lines(label.lines, label.x, label.y, class_name, anchor=label.anchor, gap=16)


def render_svg(diagram: Diagram) -> str:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{diagram.width}" height="{diagram.height}" viewBox="0 0 {diagram.width} {diagram.height}" role="img" aria-labelledby="{diagram.name}-title {diagram.name}-desc">',
        f'<title id="{diagram.name}-title">{esc(diagram.title)}</title>',
        f'<desc id="{diagram.name}-desc">{esc(diagram.desc)}</desc>',
        "<defs>",
        f'<marker id="arrow-default" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{RED}" /></marker>',
        f'<marker id="arrow-muted" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}" /></marker>',
        f'<marker id="arrow-success" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{GREEN}" /></marker>',
        f'<marker id="arrow-warning" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{AMBER}" /></marker>',
        "</defs>",
        "<style>",
        f"svg {{ background: {CANVAS}; font-family: 'Red Hat Text', 'Helvetica Neue', Arial, sans-serif; }}",
        f".diagram-title {{ fill: {INK}; font: 700 26px 'Red Hat Display', 'Red Hat Text', Arial, sans-serif; }}",
        f".diagram-subtitle {{ fill: {MUTED}; font: 400 15px 'Red Hat Text', Arial, sans-serif; }}",
        f".lane rect {{ fill: {GRAY_10}; stroke: {GRAY_20}; stroke-width: 1.5; }}",
        f".lane--red rect {{ fill: #fff5f5; stroke: #f4b7b7; }}",
        f".lane--blue rect {{ fill: #f1f7ff; stroke: #b8d8ff; }}",
        f".lane-title {{ fill: {RED_DARK}; font: 700 16px 'Red Hat Display', 'Red Hat Text', Arial, sans-serif; }}",
        f".card rect {{ fill: #ffffff; stroke: {GRAY_20}; stroke-width: 1.5; }}",
        f".card--gate rect {{ stroke: {RED}; stroke-width: 2.2; }}",
        f".card--proof rect {{ stroke: {BLUE}; stroke-width: 2; }}",
        f".card--success rect {{ stroke: {GREEN}; stroke-width: 2; }}",
        f".card--warning rect {{ stroke: {AMBER}; stroke-width: 2; }}",
        f".card--muted rect {{ fill: {GRAY_10}; stroke: {GRAY_30}; }}",
        f".card-title {{ fill: {INK}; font: 700 17px 'Red Hat Display', 'Red Hat Text', Arial, sans-serif; }}",
        f".card-body {{ fill: {MUTED}; font: 400 13.5px 'Red Hat Text', Arial, sans-serif; }}",
        f".connector {{ fill: none; stroke: {RED}; stroke-width: 2.4; stroke-linecap: round; stroke-linejoin: round; }}",
        f".connector--muted {{ stroke: {MUTED}; }}",
        f".connector--success {{ stroke: {GREEN}; }}",
        f".connector--warning {{ stroke: {AMBER}; }}",
        ".connector--dashed { stroke-dasharray: 7 7; }",
        f".connector-label {{ fill: {MUTED}; font: 700 12px 'Red Hat Text', Arial, sans-serif; }}",
        f".standalone-label {{ fill: {INK}; font: 700 15px 'Red Hat Text', Arial, sans-serif; }}",
        f".standalone-label--muted {{ fill: {MUTED}; font-weight: 500; }}",
        f".standalone-label--red {{ fill: {RED_DARK}; }}",
        "</style>",
        f'<text class="diagram-title" x="32" y="42">{esc(diagram.title)}</text>',
        f'<text class="diagram-subtitle" x="32" y="68">{esc(diagram.desc)}</text>',
    ]
    parts.extend(render_lane(lane) for lane in diagram.lanes)
    parts.extend(render_connector(connector) for connector in diagram.connectors)
    parts.extend(render_card(card) for card in diagram.cards)
    parts.extend(render_label(label) for label in diagram.labels)
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def diagrams() -> tuple[Diagram, ...]:
    return (
        Diagram(
            name="v3-attestation-architecture",
            title="Signed Attestation Architecture",
            desc="Build evidence, sign it, store it in the IdM trust fabric, and verify it before launch.",
            width=1280,
            height=670,
            lanes=(
                Lane(32, 98, 280, 445, "Build and verification", "blue"),
                Lane(344, 98, 280, 445, "Attestation creation", "default"),
                Lane(656, 98, 280, 445, "IdM trust fabric", "red"),
                Lane(968, 98, 280, 445, "Selection and gate", "default"),
            ),
            cards=(
                Card(68, 150, 208, 96, ("Git source",), ("policy, profiles,", "probes"), "muted"),
                Card(68, 270, 208, 96, ("AAP build", "validation"), ("registry, drift,", "tests"), "proof"),
                Card(68, 390, 208, 96, ("Managed host", "evidence"), ("install, probes,", "policy hash"), "proof"),
                Card(380, 150, 208, 96, ("Canonical", "payload"), ("host, profile,", "hash, evidence"), "proof"),
                Card(380, 270, 208, 96, ("Blastwall", "signer"), ("IdM CA-issued", "certificate"), "gate"),
                Card(380, 390, 208, 96, ("Signed", "envelope"), ("payload plus", "detached signature"), "proof"),
                Card(692, 135, 208, 96, ("IdM / Dogtag", "CA"), ("signer chain", "trust root"), "proof"),
                Card(692, 255, 208, 96, ("KRA vault",), ("attestation", "latest index"), "proof"),
                Card(692, 375, 208, 96, ("Host marker",), ("locator plus", "digest binding"), "muted"),
                Card(1004, 150, 208, 96, ("Inventory", "groups"), ("current, stale,", "profile match"), "muted"),
                Card(1004, 270, 208, 96, ("AAP preflight",), ("signature, replay,", "binding, drift"), "gate"),
                Card(1004, 390, 208, 96, ("Launch", "decision"), ("allow or", "fail closed"), "success"),
            ),
            connectors=(
                Connector(((172, 246), (172, 270)), "muted"),
                Connector(((172, 366), (172, 390)), "default"),
                Connector(((276, 318), (380, 198)), "default"),
                Connector(((276, 438), (380, 198)), "default"),
                Connector(((484, 246), (484, 270)), "default"),
                Connector(((484, 366), (484, 390)), "default"),
                Connector(((692, 183), (588, 318)), "muted", True, "trusts signer", (620, 235)),
                Connector(((588, 438), (692, 303)), "default"),
                Connector(((900, 303), (1004, 318)), "default"),
                Connector(((796, 351), (796, 375)), "muted"),
                Connector(((900, 423), (1004, 198)), "muted", True, "locator", (950, 302)),
                Connector(((1108, 246), (1108, 270)), "default"),
                Connector(((1108, 366), (1108, 390)), "success"),
            ),
            labels=(
                Label(172, 520, ("Build output must match", "the signed payload"), "muted"),
                Label(796, 520, ("Vault artifact is proof;", "marker is only a locator"), "red"),
            ),
            mermaid="""flowchart TB
  subgraph Build["Build and Verification"]
    Git["Git source<br/>policy, profiles.yml, probes"]
    BuildJob["AAP build and drift validation"]
    Install["Install / activate policy on host"]
    Verify["Run safe probes"]
    Hash["Compute installed policy hash"]
  end

  subgraph Attest["Attestation Creation"]
    Payload["Canonical attestation JSON"]
    Signer["Blastwall attestation signer<br/>IdM CA-issued certificate"]
    Sig["Detached signature"]
    Envelope["Signed attestation envelope"]
    Index["Signed latest-generation index"]
  end

  subgraph IdM["IdM Trust Fabric"]
    CA["IdM / Dogtag CA"]
    Vault["IdM vault<br/>via eigenstate.ipa"]
    Marker["Host userClass marker v3<br/>attest_ref + digest"]
  end

  subgraph Runtime["Selection and Gate"]
    Inventory["eigenstate.ipa inventory"]
    Groups["current / stale / profile groups"]
    Preflight["AAP preflight"]
    Gate["Allow or fail closed"]
  end

  Git --> BuildJob --> Install --> Verify
  Install --> Hash
  Verify --> Payload
  Hash --> Payload
  BuildJob --> Payload
  CA --> Signer
  Payload --> Signer --> Sig
  Payload --> Envelope
  Sig --> Envelope
  Envelope --> Vault
  Envelope --> Index
  Index --> Vault
  Vault --> Marker
  Marker --> Inventory --> Groups --> Preflight
  Vault --> Preflight
  CA --> Preflight
  Preflight --> Gate
""",
        ),
        Diagram(
            name="v3-attestation-sequence",
            title="Signed Attestation Sequence",
            desc="The reference workflow turns source validation and host evidence into a signed launch gate.",
            width=1280,
            height=600,
            cards=(
                Card(64, 130, 170, 96, ("1. Sync", "source"), ("pinned branch", "profiles.yml"), "muted"),
                Card(286, 130, 170, 96, ("2. Validate", "and install"), ("registry, drift,", "policy RPM"), "proof"),
                Card(508, 130, 170, 96, ("3. Probe", "host"), ("required probes", "policy hash"), "proof"),
                Card(730, 130, 170, 96, ("4. Build", "payload"), ("canonical JSON", "profile binding"), "proof"),
                Card(952, 130, 170, 96, ("5. Sign", "payload"), ("signer cert", "IdM CA chain"), "gate"),
                Card(952, 345, 170, 96, ("6. Store", "evidence"), ("vault envelope", "latest index"), "proof"),
                Card(730, 345, 170, 96, ("7. Publish", "marker"), ("attest_ref", "digest"), "muted"),
                Card(508, 345, 170, 96, ("8. Inventory", "selects"), ("current/stale", "profile groups"), "muted"),
                Card(286, 345, 170, 96, ("9. Preflight", "verifies"), ("signature, replay,", "binding, drift"), "gate"),
                Card(64, 345, 170, 96, ("10. Launch", "or stop"), ("allow only", "after proof"), "success"),
            ),
            connectors=(
                Connector(((234, 178), (286, 178)), "default"),
                Connector(((456, 178), (508, 178)), "default"),
                Connector(((678, 178), (730, 178)), "default"),
                Connector(((900, 178), (952, 178)), "default"),
                Connector(((1037, 226), (1037, 345)), "default"),
                Connector(((952, 393), (900, 393)), "default"),
                Connector(((730, 393), (678, 393)), "muted"),
                Connector(((508, 393), (456, 393)), "default"),
                Connector(((286, 393), (234, 393)), "success"),
            ),
            labels=(
                Label(640, 278, ("Forward path creates signed evidence",), "muted"),
                Label(640, 505, ("Return path consumes proof before runtime launch",), "red"),
            ),
            mermaid="""sequenceDiagram
  autonumber

  participant Git as Git / profiles.yml
  participant AAP as AAP Workflow
  participant Host as Managed RHEL Host
  participant Probe as Blastwall Probes
  participant Signer as Marker Signer
  participant CA as IdM CA
  participant Vault as IdM Vault / eigenstate.ipa
  participant IdM as IdM host userClass
  participant Inv as eigenstate.ipa Inventory
  participant PF as AAP Preflight

  AAP->>Git: Sync pinned branch / source revision
  AAP->>Git: Validate registry, drift, tests
  AAP->>Host: Install or refresh Blastwall policy RPM
  Host->>Host: Activate SELinux modules and login context
  Host->>Probe: Run probes required by profile
  Probe-->>AAP: Return BLOCKED / SKIP_ABSENT / failure evidence
  Host-->>AAP: Return installed policy payload hash

  AAP->>AAP: Build canonical attestation payload
  AAP->>Signer: Request signature over canonical payload bytes
  Signer->>CA: Use IdM CA-issued signer certificate
  Signer-->>AAP: Detached signature and signer certificate metadata

  AAP->>Vault: Store signed attestation envelope
  AAP->>Vault: Store signed latest-generation index
  Vault-->>AAP: Return attestation reference
  AAP->>AAP: Compute envelope digest
  AAP->>IdM: Publish v3 marker with attestation reference and digest

  Inv->>IdM: Read host marker
  Inv-->>AAP: Place host in marker-derived groups

  PF->>IdM: Read marker
  PF->>Vault: Retrieve signed attestation envelope
  PF->>Vault: Retrieve signed latest-generation index
  PF->>CA: Verify signer certificate chain and allowlist
  PF->>Host: Recompute current installed policy hash in stable-v3
  PF->>PF: Verify digest, expiry, host/profile/policy binding, generation
  PF-->>AAP: Allow launch only if attestation verifies
""",
        ),
        Diagram(
            name="v3-verification-flow-detail",
            title="Stable-v3 Verification Flow",
            desc="Preflight resolves marker compatibility, verifies signed proof, checks live host state, then allows or fails closed.",
            width=1280,
            height=780,
            lanes=(
                Lane(34, 100, 1212, 145, "Marker compatibility", "blue"),
                Lane(34, 292, 1212, 205, "Stable-v3 proof path", "red"),
                Lane(34, 548, 1212, 135, "Terminal outcomes", "default"),
            ),
            cards=(
                Card(70, 145, 150, 70, ("Selected", "host"), ("from inventory",), "muted"),
                Card(258, 145, 160, 70, ("Marker", "present?"), ("missing fails",), "gate"),
                Card(456, 145, 160, 70, ("Marker", "version"), ("v3 or legacy",), "gate"),
                Card(655, 145, 180, 70, ("Legacy", "mode check"), ("v1/v2 parser", "only if allowed"), "warning"),
                Card(1000, 145, 170, 70, ("Reject", "unsigned mode"), ("when legacy is", "not configured"), "warning"),
                Card(70, 338, 142, 82, ("Parse", "v3 marker"), ("reserved fields", "state"), "gate"),
                Card(250, 338, 142, 82, ("Fetch", "artifact"), ("KRA vault", "envelope"), "proof"),
                Card(430, 338, 142, 82, ("Digest", "binding"), ("sha256 matches", "marker"), "gate"),
                Card(610, 338, 142, 82, ("Envelope", "support"), ("version and", "schema"), "gate"),
                Card(790, 338, 142, 82, ("Signature", "chain"), ("IdM CA", "and allowlist"), "gate"),
                Card(970, 338, 142, 82, ("Replay", "guard"), ("latest index", "not revoked"), "gate"),
                Card(430, 455, 142, 82, ("Live", "hash"), ("current policy", "matches payload"), "proof"),
                Card(610, 455, 142, 82, ("Request", "binding"), ("host, profile,", "registry"), "gate"),
                Card(790, 455, 142, 82, ("Validity", "window"), ("fresh enough", "for launch"), "gate"),
                Card(105, 585, 320, 70, ("Fail closed",), ("missing, malformed, unauthorized,", "stale, drifted, or revoked"), "warning"),
                Card(490, 585, 300, 70, ("Preflight PASS",), ("stable-v3 proof and", "live checks agree"), "success"),
                Card(890, 585, 300, 70, ("RC / transition only",), ("legacy marker path", "remains explicit"), "muted"),
            ),
            connectors=(
                Connector(((220, 180), (258, 180)), "default"),
                Connector(((418, 180), (456, 180)), "default"),
                Connector(((616, 180), (655, 180)), "warning", False, "v1/v2", (636, 160)),
                Connector(((835, 180), (1000, 180)), "warning", True, "not allowed", (918, 160)),
                Connector(((746, 215), (1035, 585)), "muted", True, "allowed", (895, 260)),
                Connector(((536, 215), (141, 338)), "default", False, "v3", (365, 258)),
                Connector(((212, 379), (250, 379)), "default"),
                Connector(((392, 379), (430, 379)), "default"),
                Connector(((572, 379), (610, 379)), "default"),
                Connector(((752, 379), (790, 379)), "default"),
                Connector(((932, 379), (970, 379)), "default"),
                Connector(((1041, 420), (1041, 505), (572, 505)), "default"),
                Connector(((572, 496), (610, 496)), "default"),
                Connector(((752, 496), (790, 496)), "default"),
                Connector(((861, 537), (640, 585)), "success"),
                Connector(((330, 420), (330, 548), (225, 548), (225, 585)), "warning", True, "any failure", (390, 520)),
                Connector(((681, 537), (681, 548), (345, 548), (345, 585)), "warning", True),
                Connector(((861, 420), (861, 548), (345, 548), (345, 585)), "warning", True),
            ),
            labels=(
                Label(720, 725, ("Every proof-path disagreement produces a named failure state.",), "red"),
            ),
            mermaid="""flowchart TD
  Start["Preflight receives selected host"] --> MarkerCheck{"Marker present?"}

  MarkerCheck -- "No" --> Stale["Fail: missing marker"]
  MarkerCheck -- "Yes" --> Version{"Marker version"}

  Version -- "v1/v2" --> LegacyPolicy{"Unsigned marker mode allowed?"}
  LegacyPolicy -- "No" --> RejectUnsigned["Reject unsigned marker"]
  LegacyPolicy -- "Yes" --> ParserV2["Run v2 parser checks"]

  Version -- "v3" --> ParseV3["Parse v3 marker"]
  ParseV3 --> Reserved{"Duplicate reserved fields?"}
  Reserved -- "Yes" --> RejectDup["Reject duplicate semantic field"]
  Reserved -- "No" --> State{"state suitable?"}

  State -- "revoked/failed/expired" --> RejectState["Reject marker state"]
  State -- "active/lab-active" --> Fetch["Retrieve attestation from IdM vault"]

  Fetch --> FetchOK{"Artifact retrieved?"}
  FetchOK -- "No" --> RejectMissing["Reject missing attestation"]
  FetchOK -- "Yes" --> Digest{"Artifact sha256 matches marker?"}

  Digest -- "No" --> RejectDigest["Reject digest mismatch"]
  Digest -- "Yes" --> Env{"Envelope version supported?"}

  Env -- "No" --> RejectEnv["Reject unsupported envelope"]
  Env -- "Yes" --> Sig{"Signature valid to IdM CA?"}

  Sig -- "No" --> RejectSig["Reject bad signature"]
  Sig -- "Yes" --> Signer{"Signer allowed?"}

  Signer -- "No" --> RejectSigner["Reject unauthorized signer"]
  Signer -- "Yes" --> Index["Retrieve signed latest-generation index"]

  Index --> IndexOK{"Index valid and latest?"}
  IndexOK -- "No" --> RejectReplay["Reject replay / missing index"]
  IndexOK -- "Yes" --> LiveHash["Compute current host policy hash"]

  LiveHash --> HashOK{"Host hash matches payload?"}
  HashOK -- "No" --> RejectDrift["Reject drifted host"]
  HashOK -- "Yes" --> Binding{"Payload matches marker, host, profile, registry?"}

  Binding -- "No" --> RejectBinding["Reject binding mismatch"]
  Binding -- "Yes" --> Fresh{"Within validity window?"}

  Fresh -- "No" --> RejectFresh["Reject stale attestation"]
  Fresh -- "Yes" --> Allow["Preflight PASS"]

  ParserV2 --> AllowV2{"Parser suitable?"}
  AllowV2 -- "No" --> RejectV2["Reject invalid v2 marker"]
  AllowV2 -- "Yes" --> AllowRC["Allow only under configured unsigned-marker mode"]
""",
        ),
        Diagram(
            name="v3-marker-locator-flow",
            title="Marker Is Locator, Evidence Is Proof",
            desc="Inventory may select a candidate from IdM, but stable-v3 trusts only verified signed evidence.",
            width=1280,
            height=470,
            lanes=(
                Lane(32, 95, 350, 305, "Selection plane", "blue"),
                Lane(430, 95, 818, 305, "Proof and launch plane", "red"),
            ),
            cards=(
                Card(62, 155, 138, 105, ("IdM host", "marker"), ("blastwall=v3", "attest_ref", "attest_sha256")),
                Card(224, 155, 128, 105, ("AAP", "inventory"), ("candidate", "group only"), "muted"),
                Card(462, 155, 142, 105, ("KRA vault", "artifact"), ("signed envelope", "latest index"), "proof"),
                Card(640, 155, 152, 105, ("Verifier", "preflight"), ("parse", "signature", "binding"), "gate"),
                Card(830, 155, 154, 105, ("Live host", "checks"), ("policy hash", "profile set", "state"), "proof"),
                Card(1022, 155, 164, 105, ("Launch", "decision"), ("allow only after", "all checks pass"), "success"),
            ),
            connectors=(
                Connector(((200, 208), (224, 208)), "muted"),
                Connector(((352, 208), (462, 208)), "default", True, "locator", (407, 192)),
                Connector(((604, 208), (640, 208))),
                Connector(((792, 208), (830, 208))),
                Connector(((984, 208), (1022, 208)), "success"),
            ),
            labels=(
                Label(406, 318, ("Trust boundary:", "marker text is never enough"), "red"),
                Label(1106, 318, ("Security failures", "fail closed"), "red"),
            ),
            mermaid="""flowchart LR
  marker[IdM host marker<br/>locator only] --> inventory[AAP inventory<br/>candidate group]
  inventory -. attest_ref .-> artifact[KRA vault artifact<br/>signed envelope + latest index]
  artifact --> verifier[stable-v3 verifier<br/>signature, signer, binding, replay]
  verifier --> live[Live host checks<br/>policy hash + profile state]
  live --> decision[Launch decision<br/>allow or fail closed]
""",
        ),
        Diagram(
            name="v3-custody-boundary",
            title="Stable-v3 Custody Boundary",
            desc="Production-shaped examples use service-owned signer and vault principals; shared custody stays explicit lab/RC evidence.",
            width=1280,
            height=540,
            lanes=(
                Lane(34, 95, 1208, 170, "Stable-v3 operating custody", "red"),
                Lane(34, 305, 1208, 155, "Lab / RC transition custody", "blue"),
            ),
            cards=(
                Card(72, 145, 170, 100, ("Signer owner",), ("named service", "rotation path"), "proof"),
                Card(300, 145, 180, 100, ("Service vault", "principal"), ("artifact write", "latest index"), "proof"),
                Card(538, 145, 190, 100, ("Verifier", "principal"), ("read-only fetch", "allowlist checks"), "gate"),
                Card(786, 145, 185, 100, ("KRA health", "owner"), ("replica choice", "canary checks"), "proof"),
                Card(1028, 145, 165, 100, ("Decision", "record"), ("owners", "timeouts", "evidence"), "success"),
                Card(105, 350, 220, 76, ("Shared vault scope",), ("permitted only when mode says lab/RC"), "warning"),
                Card(390, 350, 230, 76, ("Transition workflow",), ("labels custody as RC evidence"), "warning"),
                Card(685, 350, 230, 76, ("Stable-v3 verifier",), ("rejects shared vault scope"), "gate"),
            ),
            connectors=(
                Connector(((242, 190), (300, 190)), "default"),
                Connector(((480, 190), (538, 190)), "default"),
                Connector(((728, 190), (786, 190)), "default"),
                Connector(((971, 190), (1028, 190)), "success"),
                Connector(((325, 388), (390, 388)), "warning"),
                Connector(((620, 388), (685, 388)), "warning"),
            ),
            mermaid="""flowchart LR
  signer[Signer owner<br/>named service principal] --> vault[Service-owned KRA vault<br/>artifact + latest index]
  vault --> verifier[Verifier principal<br/>read-only retrieval]
  verifier --> health[KRA health owner<br/>replica + canary checks]
  health --> record[Decision record<br/>owners and evidence]

  shared[Shared vault scope<br/>lab or RC only] --> transition[Transition workflow<br/>labels custody as RC]
  transition --> stable[stable-v3 verifier<br/>rejects shared scope]
""",
        ),
        Diagram(
            name="v3-stable-preflight-decision",
            title="Stable-v3 Preflight Decision",
            desc="Every candidate takes the same verification path; named failures stop launch before runtime work.",
            width=1280,
            height=610,
            cards=(
                Card(60, 130, 150, 100, ("Candidate", "host"), ("selected by", "inventory"), "muted"),
                Card(250, 130, 150, 100, ("Parse v3", "marker"), ("version", "locator", "digest"), "gate"),
                Card(440, 130, 160, 100, ("Fetch", "artifact"), ("KRA vault", "latest index"), "proof"),
                Card(640, 130, 160, 100, ("Verify", "signature"), ("chain", "allowlist", "expiry"), "gate"),
                Card(840, 130, 160, 100, ("Replay", "guard"), ("latest", "generation", "revoked state"), "gate"),
                Card(1040, 130, 160, 100, ("Bind to", "request"), ("host", "profile set", "policy"), "gate"),
                Card(1040, 340, 160, 100, ("Probe live", "state"), ("policy hash", "host facts"), "proof"),
                Card(840, 340, 160, 86, ("Allow", "launch"), ("all checks", "passed"), "success"),
                Card(250, 340, 350, 92, ("Fail closed with a named state",), ("parse, artifact, signature, replay, binding,", "drift, revocation, or infrastructure failure"), "warning"),
            ),
            connectors=(
                Connector(((210, 173), (250, 173))),
                Connector(((400, 173), (440, 173))),
                Connector(((600, 173), (640, 173))),
                Connector(((800, 173), (840, 173))),
                Connector(((1000, 173), (1040, 173))),
                Connector(((1120, 216), (1120, 340))),
                Connector(((1040, 383), (1000, 383), (1000, 383), (840, 383)), "success"),
                Connector(((325, 216), (325, 340)), "warning", True, "on failure", (370, 278)),
                Connector(((520, 216), (520, 340)), "warning", True),
                Connector(((720, 216), (720, 475), (425, 475), (425, 432)), "warning", True),
                Connector(((920, 216), (920, 475), (500, 475), (500, 432)), "warning", True),
                Connector(((1120, 426), (1120, 500), (560, 500), (560, 432)), "warning", True),
            ),
            mermaid="""flowchart LR
  candidate[Candidate selected by inventory] --> marker[Parse v3 marker]
  marker --> artifact[Fetch KRA artifact and latest index]
  artifact --> signature[Verify signature and signer]
  signature --> replay[Check latest generation and revocation]
  replay --> binding[Check host/profile/policy binding]
  binding --> live[Probe live host state]
  live --> allow[Allow launch]
  marker -. any failure .-> fail[Fail closed with named state]
  artifact -. any failure .-> fail
  signature -. any failure .-> fail
  replay -. any failure .-> fail
  binding -. any failure .-> fail
  live -. any failure .-> fail
""",
        ),
        Diagram(
            name="v3-failure-state-map",
            title="Failure-State Map",
            desc="Stable-v3 turns verifier problems into durable, auditable outcomes instead of ambiguous launch errors.",
            width=1280,
            height=620,
            cards=(
                Card(520, 132, 240, 90, ("Stable-v3", "verifier"), ("classifies every", "stop condition"), "gate"),
                Card(80, 300, 180, 105, ("Marker", "parse"), ("unsupported", "malformed", "unsuitable"), "warning"),
                Card(300, 300, 180, 105, ("Artifact", "visibility"), ("missing", "digest mismatch", "KRA outage"), "warning"),
                Card(520, 300, 180, 105, ("Signature", "and signer"), ("invalid", "untrusted", "expired"), "warning"),
                Card(740, 300, 180, 105, ("Replay", "and revocation"), ("not latest", "revoked marker", "revoked index"), "warning"),
                Card(960, 300, 180, 105, ("Binding", "and drift"), ("wrong host", "wrong profile", "policy mismatch"), "warning"),
                Card(520, 470, 240, 78, ("Outcome",), ("fail closed, route by failure class"), "success"),
            ),
            connectors=(
                Connector(((520, 177), (170, 177), (170, 300)), "warning"),
                Connector(((560, 222), (390, 222), (390, 300)), "warning"),
                Connector(((640, 222), (610, 222), (610, 300)), "warning"),
                Connector(((720, 222), (830, 222), (830, 300)), "warning"),
                Connector(((760, 177), (1050, 177), (1050, 300)), "warning"),
                Connector(((170, 386), (170, 510), (520, 510)), "muted"),
                Connector(((390, 386), (390, 510), (520, 510)), "muted"),
                Connector(((610, 386), (610, 470)), "muted"),
                Connector(((830, 386), (830, 510), (760, 510)), "muted"),
                Connector(((1050, 386), (1050, 510), (760, 510)), "muted"),
            ),
            mermaid="""flowchart TB
  verifier[stable-v3 verifier] --> parse[Marker parse states]
  verifier --> artifact[Artifact visibility states]
  verifier --> signature[Signature and signer states]
  verifier --> replay[Replay and revocation states]
  verifier --> binding[Binding and live drift states]
  parse --> outcome[Fail closed and route by class]
  artifact --> outcome
  signature --> outcome
  replay --> outcome
  binding --> outcome
""",
        ),
        Diagram(
            name="v3-calabi-reference-topology",
            title="Calabi Reference Topology",
            desc="The exemplar evidence path runs through the lab control chain before touching managed hosts.",
            width=1280,
            height=570,
            lanes=(
                Lane(34, 98, 258, 342, "Operator workstation", "blue"),
                Lane(330, 98, 260, 342, "Jump and bastion", "default"),
                Lane(628, 98, 288, 342, "Control services", "red"),
                Lane(954, 98, 292, 342, "Managed hosts", "default"),
            ),
            cards=(
                Card(72, 165, 180, 105, ("Codex", "workspace"), ("source branch", "validation", "publish docs"), "muted"),
                Card(366, 145, 180, 80, ("virt-01",), ("lab jump host", "boundary hop"), "muted"),
                Card(366, 285, 180, 80, ("Bastion",), ("AAP and IdM", "access path"), "muted"),
                Card(662, 130, 220, 78, ("AAP Controller",), ("inventory, preflight,", "workflow execution"), "proof"),
                Card(662, 240, 220, 78, ("IdM + KRA",), ("markers, CA, vault,", "latest index"), "proof"),
                Card(662, 350, 220, 78, ("Evidence ledger",), ("job IDs and", "artifact bindings"), "success"),
                Card(994, 175, 210, 84, ("mirror-registry",), ("reference host", "policy probes"), "gate"),
                Card(994, 310, 210, 84, ("additional hosts",), ("mixed-state", "scheduled checks"), "proof"),
            ),
            connectors=(
                Connector(((252, 207), (366, 185)), "muted"),
                Connector(((456, 225), (456, 285)), "muted"),
                Connector(((546, 325), (662, 169)), "default"),
                Connector(((546, 325), (662, 279)), "default"),
                Connector(((882, 169), (994, 217)), "default"),
                Connector(((882, 279), (994, 217)), "default"),
                Connector(((882, 389), (994, 352)), "success"),
            ),
            mermaid="""flowchart LR
  workspace[Codex workspace<br/>v3 branch and docs] --> virt[virt-01 jump host]
  virt --> bastion[Bastion access path]
  bastion --> aap[AAP Controller<br/>inventory + preflight]
  bastion --> idm[IdM + KRA<br/>markers + vault artifacts]
  aap --> host[mirror-registry reference host]
  idm --> host
  aap --> ledger[Evidence ledger<br/>job IDs + bindings]
  ledger --> mixed[Additional hosts<br/>mixed-state and schedules]
""",
        ),
        Diagram(
            name="v3-operating-loop",
            title="Signed Evidence Operating Loop",
            desc="The demonstration path treats capture, signing, publication, launch, and audit as one repeatable loop.",
            width=1280,
            height=560,
            cards=(
                Card(80, 145, 150, 84, ("Capture", "host state"), ("policy hash", "profile facts"), "muted"),
                Card(275, 145, 150, 84, ("Sign", "evidence"), ("service key", "allowed signer"), "proof"),
                Card(470, 145, 150, 84, ("Store", "artifact"), ("KRA vault", "latest index"), "proof"),
                Card(665, 145, 150, 84, ("Publish", "marker"), ("locator", "digest binding"), "muted"),
                Card(860, 145, 150, 84, ("Select", "candidate"), ("inventory", "profile match"), "muted"),
                Card(1055, 145, 150, 84, ("Verify", "preflight"), ("signed proof", "live state"), "gate"),
                Card(1055, 345, 150, 84, ("Launch", "runtime"), ("confined", "auditable"), "success"),
                Card(660, 345, 170, 84, ("Scheduled", "audit"), ("KRA health", "inventory drift"), "proof"),
                Card(250, 345, 190, 84, ("Recapture", "when needed"), ("contract or", "evidence change"), "warning"),
            ),
            connectors=(
                Connector(((230, 187), (275, 187))),
                Connector(((425, 187), (470, 187))),
                Connector(((620, 187), (665, 187))),
                Connector(((815, 187), (860, 187))),
                Connector(((1010, 187), (1055, 187))),
                Connector(((1130, 229), (1130, 345)), "success"),
                Connector(((1055, 387), (830, 387)), "muted"),
                Connector(((660, 387), (440, 387)), "warning"),
                Connector(((250, 387), (155, 387), (155, 229)), "warning"),
            ),
            mermaid="""flowchart LR
  capture[Capture host state] --> sign[Sign evidence]
  sign --> store[Store artifact and latest index]
  store --> marker[Publish marker locator]
  marker --> select[Inventory selects candidate]
  select --> verify[Stable-v3 preflight verifies]
  verify --> launch[Confined runtime launch]
  launch --> audit[Scheduled audit]
  audit --> recapture[Recapture when contract or evidence changes]
  recapture --> capture
""",
        ),
        Diagram(
            name="v3-breakglass-scope",
            title="Breakglass Scope",
            desc="Breakglass is explicit, scoped, and limited to infrastructure visibility; it cannot bypass security proof failures.",
            width=1280,
            height=560,
            lanes=(
                Lane(44, 105, 562, 330, "Eligible infrastructure visibility failures", "blue"),
                Lane(674, 105, 562, 330, "Security failures remain fail-closed", "red"),
            ),
            cards=(
                Card(88, 165, 190, 88, ("KRA artifact", "not visible"), ("replica, canary,", "or access issue"), "warning"),
                Card(352, 165, 190, 88, ("Explicit", "profile scope"), ("requested profiles", "must match"), "gate"),
                Card(220, 315, 210, 82, ("Audit package",), ("ticket, approver,", "reason, timeout, review"), "success"),
                Card(718, 150, 190, 82, ("Signature", "failure"), ("invalid or", "untrusted signer"), "gate"),
                Card(986, 150, 190, 82, ("Revoked or", "replayed"), ("latest index", "rejects trust"), "gate"),
                Card(718, 305, 190, 82, ("Binding", "mismatch"), ("wrong host", "or profile set"), "gate"),
                Card(986, 305, 190, 82, ("Live drift",), ("policy hash or", "host state mismatch"), "gate"),
            ),
            connectors=(
                Connector(((278, 209), (352, 209)), "warning"),
                Connector(((447, 253), (365, 315)), "success"),
                Connector(((908, 191), (986, 191)), "default"),
                Connector(((908, 346), (986, 346)), "default"),
            ),
            labels=(
                Label(314, 465, ("Allowed only when mode and scope are explicit",), "muted"),
                Label(955, 465, ("No bypass path for proof or host-state failures",), "red"),
            ),
            mermaid="""flowchart LR
  artifact[KRA artifact not visible] --> scope[Explicit breakglass profile scope]
  scope --> audit[Audit package<br/>ticket, approver, reason, timeout, review]

  sig[Signature failure] --> revoked[Revoked or replayed]
  bind[Binding mismatch] --> drift[Live drift]
  revoked --> fail[Fail closed]
  drift --> fail
""",
        ),
        Diagram(
            name="v3-adopter-readiness",
            title="Adopter Readiness Path",
            desc="The exemplar is useful when local owners turn the demonstrated path into their own operating control.",
            width=1280,
            height=560,
            cards=(
                Card(70, 145, 160, 115, ("Assign", "owners"), ("boundary", "signer/KRA", "response"), "muted"),
                Card(275, 145, 170, 115, ("Choose", "custody"), ("service principals", "rotation", "revocation"), "proof"),
                Card(490, 145, 170, 115, ("Validate", "topology"), ("IdM/KRA", "AAP", "host access"), "proof"),
                Card(705, 145, 170, 115, ("Run", "evidence gate"), ("healthy path", "failure states"), "gate"),
                Card(920, 145, 170, 115, ("Replay", "corpus"), ("ordinary", "automation jobs"), "muted"),
                Card(705, 350, 170, 100, ("Record", "decision"), ("evidence, dates,", "owners"), "success"),
                Card(490, 350, 170, 100, ("Plan", "recapture"), ("contract changes", "signing changes"), "warning"),
                Card(275, 350, 170, 100, ("Schedule", "audit"), ("KRA health", "inventory drift"), "proof"),
            ),
            connectors=(
                Connector(((230, 191), (275, 191))),
                Connector(((445, 191), (490, 191))),
                Connector(((660, 191), (705, 191))),
                Connector(((875, 191), (920, 191))),
                Connector(((1005, 237), (1005, 392), (875, 392)), "success"),
                Connector(((705, 392), (660, 392)), "warning"),
                Connector(((490, 392), (445, 392)), "muted"),
            ),
            mermaid="""flowchart LR
  owners[Assign local owners] --> custody[Choose signer and vault custody]
  custody --> topology[Validate local topology]
  topology --> evidence[Run healthy and failure evidence]
  evidence --> corpus[Replay ordinary automation corpus]
  corpus --> decision[Record adopter decision]
  decision --> recapture[Plan recapture triggers]
  recapture --> audit[Schedule audit loop]
""",
        ),
    )


def write_index(output_dir: Path, rendered: tuple[Diagram, ...]) -> None:
    cards = "\n".join(
        f'<article><h2>{esc(diagram.title)}</h2><p>{esc(diagram.desc)}</p><img src="{diagram.name}.svg" alt="{esc(diagram.title)}"></article>'
        for diagram in rendered
    )
    index = f"""<!doctype html>
<html lang="en-US">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Blastwall v3 diagram candidates</title>
    <style>
      body {{ margin: 0; padding: 2rem; font-family: "Red Hat Text", Arial, sans-serif; color: #151515; background: #f5f5f5; }}
      main {{ display: grid; gap: 1.5rem; max-width: 1280px; margin: 0 auto; }}
      article {{ background: #fff; border: 1px solid #e0e0e0; padding: 1rem; }}
      h1, h2 {{ font-family: "Red Hat Display", "Red Hat Text", Arial, sans-serif; }}
      img {{ width: 100%; height: auto; border: 1px solid #e0e0e0; background: #fff; }}
    </style>
  </head>
  <body>
    <main>
      <h1>Blastwall v3 diagram candidates</h1>
      {cards}
    </main>
  </body>
</html>
"""
    (output_dir / "index.html").write_text(index, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/assets/diagrams"),
        help="directory for generated .svg and .mmd files",
    )
    parser.add_argument(
        "--index",
        action="store_true",
        help="also write a candidate-review index.html",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify generated .svg and .mmd files are current without writing",
    )
    args = parser.parse_args()

    rendered = diagrams()
    if args.check:
        stale = []
        for diagram in rendered:
            expected = {
                args.output / f"{diagram.name}.svg": render_svg(diagram),
                args.output / f"{diagram.name}.mmd": diagram.mermaid.strip() + "\n",
            }
            for path, content in expected.items():
                if not path.exists() or path.read_text(encoding="utf-8") != content:
                    stale.append(str(path))
        if stale:
            print("Stale generated v3 diagrams:")
            for path in stale:
                print(f"  {path}")
            return 1
        return 0

    args.output.mkdir(parents=True, exist_ok=True)
    for diagram in rendered:
        (args.output / f"{diagram.name}.svg").write_text(render_svg(diagram), encoding="utf-8")
        (args.output / f"{diagram.name}.mmd").write_text(diagram.mermaid.strip() + "\n", encoding="utf-8")

    if args.index:
        write_index(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
