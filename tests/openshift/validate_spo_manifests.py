#!/usr/bin/env python3
"""Static checks for the Blastwall OpenShift/SPO implementation."""

from __future__ import annotations

import difflib
from pathlib import Path
import sys
import yaml


ROOT = Path(__file__).resolve().parents[2]
SPO = ROOT / "openshift" / "spo"
SPO_STRANGE = SPO / "strange-socket-v1"
SPO_README = SPO / "README.md"
DOCS = ROOT / "docs"
WORKFLOW = ROOT / ".github" / "workflows" / "policy-pipeline-smoke.yml"
AAP_CONFIG = ROOT / "aap" / "configure-controller.yml"
AAP_VARS = ROOT / "aap" / "vars" / "blastwall-controller.yml"
RENDER_PLAYBOOK = ROOT / "playbooks" / "render-spo-policy-crs.yml"
APPLY_VALIDATE_PLAYBOOK = ROOT / "playbooks" / "apply-validate-spo-policy-crs.yml"
BASE_KUSTOMIZATION = SPO / "kustomization.yaml"
STRANGE_KUSTOMIZATION = SPO_STRANGE / "kustomization.yaml"
OVERLAY_KUSTOMIZATION = ROOT / "openshift" / "spo-overlays" / "strange-socket-v1" / "kustomization.yaml"
RENDERED_BUNDLE = Path("/var/tmp/blastwall-policy-pipeline/artifacts/openshift-spo/blastwall-spo-crs.yaml")
STANDARD_TYPE_PLACEHOLDER = "__BLASTWALL_SPO_STANDARD_SELINUX_TYPE__"
NESTED_TYPE_PLACEHOLDER = "__BLASTWALL_SPO_NESTED_SELINUX_TYPE__"
STRANGE_TYPE_PLACEHOLDER = "__BLASTWALL_SPO_STRANGE_SELINUX_TYPE__"
NESTED_STRANGE_TYPE_PLACEHOLDER = "__BLASTWALL_SPO_NESTED_STRANGE_SELINUX_TYPE__"
LEGACY_STANDARD_USAGE = "blastwall_" + ".process"
LEGACY_NESTED_USAGE = "blastwallnested_" + ".process"
DEFAULT_SELINUX_MODE = "calabi-ocp420-rawprofile-underscore"
EXECUTABLE_USAGE_PATHS = [
    SPO / "20-scc-blastwall-confined.yaml",
    SPO / "40-test-harness-configmap.yaml",
    SPO / "tests" / "50-validation-job.yaml",
    SPO / "scripts" / "validate-blastwall-spo-nodes.sh",
    ROOT / "tests" / "openshift" / "blastwall_spo_probe.py",
    APPLY_VALIDATE_PLAYBOOK,
]
BASE_APPLY_SECTION_HEADING = "## What The Base Applies"
STRANGE_OVERLAY_SECTION_HEADING = "## Strange Overlay"
BASE_SECTION_STRANGE_STRINGS = [
    "blastwallstrange",
    "blastwallnestedstrange",
    "blastwall-strange",
    "blastwall-nested-strange",
]
STRANGE_SPO_MANIFESTS = [
    SPO_STRANGE / "12-rawselinuxprofile-blastwall-strange.yaml",
    SPO_STRANGE / "13-rawselinuxprofile-blastwall-nested-strange.yaml",
    SPO_STRANGE / "21-scc-blastwall-strange.yaml",
    SPO_STRANGE / "31-workload-rbac-strange.yaml",
    SPO_STRANGE / "tests" / "50-validation-job-strange.yaml",
]
OVERLAY_BASE_RESOURCES = {"../../spo", "../../spo/strange-socket-v1"}
OVERLAY_STRANGE_RESOURCES = {
    (SPO_STRANGE / p).resolve().name for p in [
        "12-rawselinuxprofile-blastwall-strange.yaml",
        "13-rawselinuxprofile-blastwall-nested-strange.yaml",
        "21-scc-blastwall-strange.yaml",
        "31-workload-rbac-strange.yaml",
        "tests/50-validation-job-strange.yaml",
    ]
}
BASE_STANDARD_RESOURCES = {
    "00-namespace.yaml",
    "05-workload-namespace.yaml",
    "10-rawselinuxprofile-blastwall.yaml",
    "11-rawselinuxprofile-blastwall-nested.yaml",
    "20-scc-blastwall-confined.yaml",
    "30-workload-rbac.yaml",
    "40-test-harness-configmap.yaml",
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_kustomization_resources(path: Path) -> list[str]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        fail(f"{path.relative_to(ROOT)} is not valid YAML: {exc}")
    if not isinstance(data, dict):
        fail(f"{path.relative_to(ROOT)} does not contain a kustomization dict")
    resources = data.get("resources")
    if not isinstance(resources, list) or not all(isinstance(item, str) for item in resources):
        fail(f"{path.relative_to(ROOT)} resources must be a string list")
    return resources


def extract_markdown_section(text: str, heading: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == heading), None)
    if start is None:
        fail(f"{SPO_README.relative_to(ROOT)} missing expected section: {heading}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start:end])


def find_embedded_probe_script() -> str:
    configmap = find_one("ConfigMap", "blastwall-spo-probe")
    data = configmap.get("data")
    if not isinstance(data, dict):
        fail("ConfigMap blastwall-spo-probe has no data section")
    script = data.get("blastwall_spo_probe.py")
    if not isinstance(script, str):
        fail("ConfigMap blastwall-spo-probe does not define blastwall_spo_probe.py")
    return script


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


base_kustomization_resources = read_kustomization_resources(BASE_KUSTOMIZATION)
base_resource_names = {Path(resource).name for resource in base_kustomization_resources}
if not BASE_STANDARD_RESOURCES.issubset(base_resource_names):
    missing_base_resources = sorted(BASE_STANDARD_RESOURCES - base_resource_names)
    fail(f"Root openshift/spo/kustomization.yaml missing base resources: {', '.join(missing_base_resources)}")
if any("strange" in resource for resource in base_resource_names):
    fail("Root openshift/spo/kustomization.yaml must not include strange-socket-v1 resources")

if not all(path.exists() for path in STRANGE_SPO_MANIFESTS):
    missing = ", ".join(str(path.relative_to(ROOT)) for path in STRANGE_SPO_MANIFESTS if not path.exists())
    fail(f"Missing strange-socket-v1 manifest files: {missing}")

overlay_kustomization_resources = read_kustomization_resources(OVERLAY_KUSTOMIZATION)
overlay_resources = set(overlay_kustomization_resources)
if not OVERLAY_BASE_RESOURCES.issubset(overlay_resources):
    missing_overlay_base_resources = sorted(OVERLAY_BASE_RESOURCES - overlay_resources)
    fail(f"strange-socket-v1 overlay missing base resources: {', '.join(missing_overlay_base_resources)}")
if SPO in OVERLAY_KUSTOMIZATION.parents:
    fail("strange-socket-v1 overlay must live outside openshift/spo to avoid kustomize base cycles")

strange_kustomization_resources = read_kustomization_resources(STRANGE_KUSTOMIZATION)
overlay_resource_names = {Path(resource).name for resource in strange_kustomization_resources}
if not OVERLAY_STRANGE_RESOURCES.issubset(overlay_resource_names):
    missing_overlay_resources = sorted(OVERLAY_STRANGE_RESOURCES - overlay_resource_names)
    fail(f"strange-socket-v1 resource kustomization missing resources: {', '.join(missing_overlay_resources)}")


def find_one(kind: str, name: str) -> dict:
    match = next((doc for _, doc in documents if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name), None)
    if not match:
        fail(f"{kind}/{name} is missing")
    return match


standard_profile = find_one("RawSelinuxProfile", "blastwall")
nested_profile = find_one("RawSelinuxProfile", "blastwallnested")
strange_profile = find_one("RawSelinuxProfile", "blastwallstrange")
nested_strange_profile = find_one("RawSelinuxProfile", "blastwallnestedstrange")

standard_policy = standard_profile.get("spec", {}).get("policy", "")
nested_policy = nested_profile.get("spec", {}).get("policy", "")
strange_policy = strange_profile.get("spec", {}).get("policy", "")
nested_strange_policy = nested_strange_profile.get("spec", {}).get("policy", "")
required_surfaces = [
    "netlink_xfrm_socket",
    "rxrpc_socket",
    "packet_socket",
    "alg_socket",
    "bpf",
    "capability2 (bpf)",
    "io_uring",
]
strange_surfaces = [
    "xdp_socket",
    "tipc_socket",
    "can_socket",
    "bluetooth_socket",
    "nfc_socket",
    "kcm_socket",
    "rds_socket",
]
for name, policy in [
    ("blastwall", standard_policy),
    ("blastwallnested", nested_policy),
    ("blastwallstrange", strange_policy),
    ("blastwallnestedstrange", nested_strange_policy),
]:
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
if "user_namespace" not in strange_policy or "(create)" not in strange_policy:
    fail("RawSelinuxProfile/blastwallstrange does not deny user_namespace create")
if "user_namespace" in nested_strange_policy:
    fail("RawSelinuxProfile/blastwallnestedstrange must not deny or neverallow user_namespace create")
for surface in strange_surfaces:
    if surface in standard_policy or surface in nested_policy:
        fail(f"base OpenShift/SPO profiles must not include strange-socket-v1 surface {surface}")
    if surface not in strange_policy:
        fail(f"RawSelinuxProfile/blastwallstrange is missing strange-socket-v1 surface {surface}")
    if surface not in nested_strange_policy:
        fail(f"RawSelinuxProfile/blastwallnestedstrange is missing strange-socket-v1 surface {surface}")

standard_scc = find_one("SecurityContextConstraints", "blastwall-confined")
nested_scc = find_one("SecurityContextConstraints", "blastwall-nested")
strange_scc = find_one("SecurityContextConstraints", "blastwall-strange")
nested_strange_scc = find_one("SecurityContextConstraints", "blastwall-nested-strange")


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


check_scc_posture(standard_scc, STANDARD_TYPE_PLACEHOLDER)
check_scc_posture(nested_scc, NESTED_TYPE_PLACEHOLDER)
check_scc_posture(strange_scc, STRANGE_TYPE_PLACEHOLDER)
check_scc_posture(nested_strange_scc, NESTED_STRANGE_TYPE_PLACEHOLDER)
if nested_scc.get("userNamespaceLevel") != "RequirePodLevel":
    fail("SCC blastwall-nested must require pod-level user namespaces")
if nested_strange_scc.get("userNamespaceLevel") != "RequirePodLevel":
    fail("SCC blastwall-nested-strange must require pod-level user namespaces")
for strategy in ["fsGroup", "runAsUser", "supplementalGroups"]:
    if nested_scc.get(strategy, {}).get("type") != "RunAsAny":
        fail(f"SCC blastwall-nested must set {strategy}.type=RunAsAny for pod user namespaces")
    if nested_strange_scc.get(strategy, {}).get("type") != "RunAsAny":
        fail(f"SCC blastwall-nested-strange must set {strategy}.type=RunAsAny for pod user namespaces")

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


def job_env_value(job: dict, name: str) -> str | None:
    containers = job.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    for container in containers:
        for env in container.get("env", []) or []:
            if env.get("name") == name:
                return env.get("value")
    return None


standard_job = find_one("Job", "blastwall-spo-validation")
nested_job = find_one("Job", "blastwall-nested-spo-validation")
strange_job = find_one("Job", "blastwall-strange-spo-validation")
nested_strange_job = find_one("Job", "blastwall-nested-strange-spo-validation")
if job_env_value(standard_job, "BLASTWALL_EXPECTED_SELINUX_TYPE") != STANDARD_TYPE_PLACEHOLDER:
    fail("standard validation job must use the status-derived SELinux type placeholder")
if job_env_value(nested_job, "BLASTWALL_EXPECTED_SELINUX_TYPE") != NESTED_TYPE_PLACEHOLDER:
    fail("nested validation job must use the status-derived SELinux type placeholder")
if job_env_value(strange_job, "BLASTWALL_EXPECTED_SELINUX_TYPE") != STRANGE_TYPE_PLACEHOLDER:
    fail("strange validation job must use the status-derived SELinux type placeholder")
if job_env_value(nested_strange_job, "BLASTWALL_EXPECTED_SELINUX_TYPE") != NESTED_STRANGE_TYPE_PLACEHOLDER:
    fail("nested strange validation job must use the status-derived SELinux type placeholder")
for job, name in [(strange_job, "strange"), (nested_strange_job, "nested strange")]:
    if job_env_value(job, "BLASTWALL_STRANGE_SOCKET_V1") != "true":
        fail(f"{name} validation job must enable BLASTWALL_STRANGE_SOCKET_V1")

for executable_path in EXECUTABLE_USAGE_PATHS:
    text = executable_path.read_text(encoding="utf-8")
    if LEGACY_STANDARD_USAGE in text or LEGACY_NESTED_USAGE in text:
        fail(f"{executable_path.relative_to(ROOT)} hardcodes legacy SPO process type strings")

probe_text = (ROOT / "tests" / "openshift" / "blastwall_spo_probe.py").read_text(encoding="utf-8")
if "required_env(\"BLASTWALL_EXPECTED_SELINUX_TYPE\")" not in probe_text:
    fail("tests/openshift/blastwall_spo_probe.py must require status-derived expected type")
if "Fragnesia AF_ALG" not in probe_text:
    fail("tests/openshift/blastwall_spo_probe.py must label AF_ALG evidence as Fragnesia AF_ALG")
configmap_script = find_embedded_probe_script()
if probe_text != configmap_script:
    diff = difflib.unified_diff(
        probe_text.splitlines(keepends=True),
        configmap_script.splitlines(keepends=True),
        fromfile="tests/openshift/blastwall_spo_probe.py",
        tofile="openshift/spo/40-test-harness-configmap.yaml:data.blastwall_spo_probe.py",
        lineterm="",
    )
    diff_preview = "".join(line for _, line in zip(range(20), diff))
    fail(
        "ConfigMap embedded probe script does not match tests/openshift/blastwall_spo_probe.py\n"
        f"First diff:\n{diff_preview}"
    )

configmap_text = (SPO / "40-test-harness-configmap.yaml").read_text(encoding="utf-8")
if "required_env(\"BLASTWALL_EXPECTED_SELINUX_TYPE\")" not in configmap_text:
    fail("openshift/spo/40-test-harness-configmap.yaml must require status-derived expected type")

node_script = (SPO / "scripts" / "validate-blastwall-spo-nodes.sh").read_text(encoding="utf-8")
for expected in [
    "usage_mode",
    "BLASTWALL_SPO_SELINUX_TYPE_RESOLUTION_MODE",
    "calabi-ocp420-rawprofile-underscore",
    "status-usage-direct",
    "get_spo_selinux_usage",
    ".status.usage",
    "derive_selinux_type",
    "Unknown OpenShift/SPO status.usage format",
    "patch_scc_usage",
    "openshift/spo-overlays/strange-socket-v1",
    "delete job",
    "blastwall-strange-spo-validation",
    "blastwall-nested-strange-spo-validation",
    "skipped_nodes",
    "node is not Ready and schedulable",
]:
    if expected not in node_script:
        fail(f"validate-blastwall-spo-nodes.sh is missing {expected}")

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

spo_readme_text = SPO_README.read_text(encoding="utf-8")
base_section = extract_markdown_section(spo_readme_text, BASE_APPLY_SECTION_HEADING)
if any(marker in base_section.lower() for marker in BASE_SECTION_STRANGE_STRINGS):
    fail("openshift/spo/README.md base section should not list strange-socket-v1 resources")
strange_section = extract_markdown_section(spo_readme_text, STRANGE_OVERLAY_SECTION_HEADING)
for expected in [
    "oc apply -k openshift/spo-overlays/strange-socket-v1",
    "rawselinuxprofile/blastwallstrange",
    "rawselinuxprofile/blastwallnestedstrange",
]:
    if expected not in strange_section:
        fail("openshift/spo/README.md strange overlay section does not document required commands")

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
    "blastwall-strange",
    "blastwall-nested-strange",
    "blastwallnested",
    "blastwallstrange",
    "blastwallnestedstrange",
    "spo_sccs",
    "blastwall-confined",
    "! grep -F 'blastwall-strange'",
    "! grep -F 'standard-strange_profile: passed'",
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
    "BLASTWALL_SPO_INCLUDE_STRANGE_SOCKET_V1",
    "BLASTWALL_SPO_INCLUDE_STRANGE_SOCKET_V1 |",
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
    "blastwall_spo_selinux_type_resolution_mode",
    DEFAULT_SELINUX_MODE,
    "standard_profile: passed",
    "nested_profile: passed",
    "BLASTWALL_SPO_VALIDATE_STRANGE_SOCKET_V1",
    "BLASTWALL_SPO_VALIDATE_STRANGE_SOCKET_V1 |",
    "blastwall_spo_all_validation_jobs",
    "blastwall.io/policy-profile",
    "spo_policy_apply_validate",
    "status.usage",
    "blastwall_spo_usage_by_profile",
    "Assert OpenShift/SPO status.usage format is recognized",
    "Unknown OpenShift/SPO status.usage format",
    "spo_validation_classes",
]:
    if expected not in apply_validate_playbook:
        fail(f"playbooks/apply-validate-spo-policy-crs.yml is missing {expected}")

if RENDERED_BUNDLE.exists():
    bundle_docs = read_yaml_documents(RENDERED_BUNDLE)
    for kind, name in [
        ("RawSelinuxProfile", "blastwall"),
        ("RawSelinuxProfile", "blastwallnested"),
        ("RawSelinuxProfile", "blastwallstrange"),
        ("RawSelinuxProfile", "blastwallnestedstrange"),
        ("SecurityContextConstraints", "blastwall-confined"),
        ("SecurityContextConstraints", "blastwall-nested"),
        ("SecurityContextConstraints", "blastwall-strange"),
        ("SecurityContextConstraints", "blastwall-nested-strange"),
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
