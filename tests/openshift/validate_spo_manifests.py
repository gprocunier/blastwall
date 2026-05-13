#!/usr/bin/env python3
"""Static checks for the Blastwall OpenShift/SPO implementation."""

from __future__ import annotations

from pathlib import Path
import sys
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPO = ROOT / "openshift" / "spo"
DOCS = ROOT / "docs"
WORKFLOW = ROOT / ".github" / "workflows" / "policy-pipeline-smoke.yml"
AAP_CONFIG = ROOT / "aap" / "configure-controller.yml"
AAP_VARS = ROOT / "aap" / "vars" / "blastwall-controller.yml"
RENDER_PLAYBOOK = ROOT / "playbooks" / "render-spo-policy-crs.yml"
APPLY_VALIDATE_PLAYBOOK = ROOT / "playbooks" / "apply-validate-spo-policy-crs.yml"
RENDERED_BUNDLE = Path("/var/tmp/blastwall-policy-pipeline/artifacts/openshift-spo/blastwall-spo-crs.yaml")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_yaml_documents(path: Path) -> list[dict]:
    try:
        docs = [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]
    except yaml.YAMLError as exc:
        fail(f"{path.relative_to(ROOT)} does not parse as YAML: {exc}")
    for doc in docs:
        if not isinstance(doc, dict):
            fail(f"{path.relative_to(ROOT)} contains a non-object YAML document")
    return docs


all_yaml = sorted(SPO.rglob("*.yaml")) + sorted(SPO.rglob("*.yml"))
if not all_yaml:
    fail("openshift/spo contains no YAML manifests")

documents: list[tuple[Path, dict]] = []
for yaml_path in all_yaml:
    for document in read_yaml_documents(yaml_path):
        documents.append((yaml_path, document))

def find_one(kind: str, name: str) -> dict:
    match = next((doc for _, doc in documents if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name), None)
    if not match:
        fail(f"{kind}/{name} is missing")
    return match


standard_profile = find_one("RawSelinuxProfile", "blastwall")
nested_profile = find_one("RawSelinuxProfile", "blastwallnested")

standard_policy = standard_profile.get("spec", {}).get("policy", "")
nested_policy = nested_profile.get("spec", {}).get("policy", "")
required_surfaces = [
    "netlink_xfrm_socket",
    "rxrpc_socket",
    "packet_socket",
    "alg_socket",
    "bpf",
    "capability2 (bpf)",
    "io_uring",
]
for name, policy in [("blastwall", standard_policy), ("blastwallnested", nested_policy)]:
    if "(blockinherit container)" not in policy:
        fail(f"RawSelinuxProfile/{name} does not inherit the container policy block")
    if "neverallow" not in policy:
        fail(f"RawSelinuxProfile/{name} does not include neverallow guards")
    for surface in required_surfaces:
        if surface not in policy:
            fail(f"RawSelinuxProfile/{name} is missing deny surface {surface}")

if "user_namespace" not in standard_policy or "(create)" not in standard_policy:
    fail("RawSelinuxProfile/blastwall does not deny user_namespace create")
if "user_namespace" in nested_policy:
    fail("RawSelinuxProfile/blastwallnested must not deny or neverallow user_namespace create")

standard_scc = find_one("SecurityContextConstraints", "blastwall-confined")
nested_scc = find_one("SecurityContextConstraints", "blastwall-nested")


def check_scc_posture(scc: dict, expected_type: str) -> None:
    name = scc.get("metadata", {}).get("name", "unknown")
    checks = {
        "allowPrivilegedContainer": False,
        "allowPrivilegeEscalation": False,
        "allowHostDirVolumePlugin": False,
        "allowHostIPC": False,
        "allowHostNetwork": False,
        "allowHostPID": False,
        "allowHostPorts": False,
    }
    for key, expected in checks.items():
        if scc.get(key) is not expected:
            fail(f"SCC {name} has {key}={scc.get(key)!r}, expected {expected!r}")
    if scc.get("allowedCapabilities") not in ([], None):
        fail(f"SCC {name} allows added capabilities")
    if scc.get("defaultAddCapabilities") not in ([], None):
        fail(f"SCC {name} sets default added capabilities")
    if "ALL" not in (scc.get("requiredDropCapabilities") or []):
        fail(f"SCC {name} does not drop all capabilities")
    if "runtime/default" not in (scc.get("seccompProfiles") or []):
        fail(f"SCC {name} does not require runtime/default seccomp")
    if "hostPath" in (scc.get("volumes") or []) or "*" in (scc.get("volumes") or []):
        fail(f"SCC {name} allows hostPath or wildcard volumes")
    selinux_type = (
        scc.get("seLinuxContext", {})
        .get("seLinuxOptions", {})
        .get("type")
    )
    if selinux_type != expected_type:
        fail(f"SCC {name} requires SELinux type {selinux_type!r}, expected {expected_type!r}")
    if "level" in scc.get("seLinuxContext", {}).get("seLinuxOptions", {}):
        fail(f"SCC {name} must not force a fixed SELinux MCS level")


check_scc_posture(standard_scc, "blastwall_.process")
check_scc_posture(nested_scc, "blastwallnested_.process")
if nested_scc.get("userNamespaceLevel") != "RequirePodLevel":
    fail("SCC blastwall-nested must require pod-level user namespaces")
for strategy in ["fsGroup", "runAsUser", "supplementalGroups"]:
    if nested_scc.get(strategy, {}).get("type") != "RunAsAny":
        fail(f"SCC blastwall-nested must set {strategy}.type=RunAsAny for pod user namespaces")

nested_example = find_one("Deployment", "blastwall-nested-demo")
if nested_example.get("spec", {}).get("template", {}).get("spec", {}).get("hostUsers") is not False:
    fail("nested example workload must set spec.template.spec.hostUsers: false")

nested_rolebindings = [
    doc for _, doc in documents
    if doc.get("kind") == "RoleBinding"
    and doc.get("roleRef", {}).get("name") == "use-blastwall-nested-scc"
]
if any(
    subject.get("kind") == "ServiceAccount" and subject.get("name") == "blastwall-runner"
    for binding in nested_rolebindings
    for subject in binding.get("subjects", [])
):
    fail("standard service account must not be bound to the nested SCC role")

for page in ["index.html", "day2-operations.html"]:
    text = (DOCS / page).read_text(encoding="utf-8")
    for target in ["openshift-spo.html", "openshift-spo-demo.html"]:
        if target not in text:
            fail(f"docs/{page} does not link to {target}")

readme = (ROOT / "README.md").read_text(encoding="utf-8")
for target in ["openshift-spo.html", "openshift-spo-demo.html"]:
    if target not in readme:
        fail(f"README.md does not link to {target}")

for page in ["openshift-spo.html", "openshift-spo-demo.html", "day2-operations.html"]:
    if "blastwall-nested" not in (DOCS / page).read_text(encoding="utf-8"):
        fail(f"docs/{page} does not mention blastwall-nested")

workflow = WORKFLOW.read_text(encoding="utf-8")
for expected in [
    "render_spo_policy_crs",
    "spo_policy_crs_render",
    "apply_validate_spo_policy_crs",
    "blastwall-spo-crs.yaml",
    "policy_nevra",
    "blastwall_spo_bundle_yaml",
    "blastwall_spo_bundle_path",
    "blastwall_spo_bundle_sha256",
    "RawSelinuxProfile",
    "spo_profiles",
    "spo_profile_resources",
    "blastwall-nested",
    "blastwallnested",
    "spo_sccs",
    "blastwall-confined",
]:
    if expected not in workflow:
        fail(f"policy-pipeline-smoke.yml is missing {expected}")

if "SPO_APPLY_VALIDATE" not in workflow:
    fail("policy-pipeline-smoke.yml is missing the SPO apply validation toggle")

if "evidence contract" not in (DOCS / "day2-operations.html").read_text(encoding="utf-8").lower():
    fail("day2-operations.html does not mention the AAP evidence contract")

aap_config = AAP_CONFIG.read_text(encoding="utf-8")
for expected in [
    "blastwall_aap_openshift_credential_type",
    "blastwall_aap_openshift_credential",
    "K8S_AUTH_KUBECONFIG",
    "Blastwall apply and validate SPO policy CRs",
    "apply_validate_spo_policy_crs",
]:
    if expected not in aap_config:
        fail(f"aap/configure-controller.yml is missing {expected}")

aap_vars = AAP_VARS.read_text(encoding="utf-8")
for expected in [
    "BLASTWALL_OPENSHIFT_KUBECONFIG",
    "Blastwall apply and validate SPO policy CRs",
    "playbooks/apply-validate-spo-policy-crs.yml",
]:
    if expected not in aap_vars:
        fail(f"aap/vars/blastwall-controller.yml is missing {expected}")

render_playbook = RENDER_PLAYBOOK.read_text(encoding="utf-8")
for expected in [
    "ansible.builtin.set_stats",
    "blastwall_spo_bundle_yaml",
    "blastwall_spo_bundle_path",
    "blastwall_spo_bundle_sha256",
    "policy_nevra",
]:
    if expected not in render_playbook:
        fail(f"playbooks/render-spo-policy-crs.yml is missing {expected}")

if not APPLY_VALIDATE_PLAYBOOK.exists():
    fail("playbooks/apply-validate-spo-policy-crs.yml is missing")
apply_validate_playbook = APPLY_VALIDATE_PLAYBOOK.read_text(encoding="utf-8")
for expected in [
    "kubernetes.core.k8s",
    "kubernetes.core.k8s_info",
    "kubernetes.core.k8s_log",
    "standard_profile: passed",
    "nested_profile: passed",
    "spo_policy_apply_validate",
]:
    if expected not in apply_validate_playbook:
        fail(f"playbooks/apply-validate-spo-policy-crs.yml is missing {expected}")

probe_harness = (ROOT / "tests" / "openshift" / "blastwall_spo_probe.py").read_text(encoding="utf-8")
probe_configmap = (SPO / "40-test-harness-configmap.yaml").read_text(encoding="utf-8")
for path_name, text in [
    ("tests/openshift/blastwall_spo_probe.py", probe_harness),
    ("openshift/spo/40-test-harness-configmap.yaml", probe_configmap),
]:
    if "_profile: {'passed' if overall == 'PASS' else 'failed'}" not in text:
        fail(f"{path_name} does not emit AAP validation summary markers")

if RENDERED_BUNDLE.exists():
    bundle_docs = read_yaml_documents(RENDERED_BUNDLE)
    for kind, name in [
        ("RawSelinuxProfile", "blastwall"),
        ("RawSelinuxProfile", "blastwallnested"),
        ("SecurityContextConstraints", "blastwall-confined"),
        ("SecurityContextConstraints", "blastwall-nested"),
    ]:
        if not any(doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name for doc in bundle_docs):
            fail(f"rendered bundle exists but does not contain {kind}/{name}")
    forbidden = {"Policy", "ConfigurationPolicy", "Placement", "PlacementBinding"}
    if any(doc.get("kind") in forbidden for doc in bundle_docs):
        fail("rendered bundle contains fleet-governance objects")

print(f"PASS: parsed {len(all_yaml)} OpenShift/SPO YAML files")
print("PASS: OpenShift/SPO standard and nested deny surfaces are correct")
print("PASS: standard and nested SCC posture is constrained")
print("PASS: docs and AAP smoke workflow reference dual OpenShift/SPO classes")
