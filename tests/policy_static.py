#!/usr/bin/env python3
"""Static checks for Blastwall policy scope wiring."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy"
PLAYBOOKS = ROOT / "playbooks"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


makefile = (POLICY / "Makefile").read_text(encoding="utf-8")
match = re.search(r"^DENY_POLICIES\s*:=\s*(.+)$", makefile, re.MULTILINE)
if not match:
    fail("policy/Makefile does not define DENY_POLICIES")

deny_policies = match.group(1).split()
if not deny_policies:
    fail("DENY_POLICIES is empty")

support_match = re.search(r"^SUPPORT_POLICIES\s*:=\s*(.+)$", makefile, re.MULTILINE)
if not support_match:
    fail("policy/Makefile does not define SUPPORT_POLICIES")

support_policies = support_match.group(1).split()
if "blastwall-sshd-login" not in support_policies:
    fail("blastwall-sshd-login support policy is required for GSSAPI SSH login")

sshd_login = (POLICY / "blastwall-sshd-login.cil").read_text(encoding="utf-8")
if "dyntransition" not in sshd_login:
    fail("blastwall-sshd-login.cil does not allow sshd dyntransition")

for policy in deny_policies:
    cil_path = POLICY / f"{policy}.cil"
    if not cil_path.exists():
        fail(f"{cil_path.relative_to(ROOT)} is listed but missing")

    cil = cil_path.read_text(encoding="utf-8")
    if "(deny " not in cil:
        fail(f"{cil_path.relative_to(ROOT)} does not contain a deny rule")
    if "(neverallow " not in cil:
        fail(f"{cil_path.relative_to(ROOT)} does not contain a neverallow rule")

print(f"PASS: validated {len(deny_policies)} deny policy scopes")

dirtyfrag_scopes = {
    "blastwall-xfrm-deny": "xfrm=deny",
    "blastwall-rxrpc-deny": "rxrpc=deny",
}

active_policy_marker = (
    "blastwall:state=active;"
    "rpm=blastwall-selinux-0.5.2-1;"
    "rpm_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;"
    "alg=deny;"
    "bpf=deny;"
    "self=deny;"
    "pkt=deny;"
    "userns=deny;"
    "iou=deny;"
    "xfrm=deny;"
    "rxrpc=deny"
)

if len(active_policy_marker) > 240:
    fail(
        "active IdM policy marker is too long for the host userClass field "
        f"({len(active_policy_marker)} characters)"
    )

for policy, marker in dirtyfrag_scopes.items():
    if policy not in deny_policies:
        fail(f"{policy} is required for Dirty Frag coverage")
    for path in [
        ROOT / "playbooks" / "promote-policy-rpm.yml",
        ROOT / "inventory" / "blastwall-idm.yml",
        ROOT / "poc-calabi" / "aap" / "inventory" / "blastwall-idm.yml",
        ROOT / "tests" / "fixtures" / "inventory-policy-markers.json",
    ]:
        if marker not in path.read_text(encoding="utf-8"):
            fail(f"{path.relative_to(ROOT)} does not require {marker}")

if not (ROOT / "tests" / "trigger-dirtyfrag-deny.py").exists():
    fail("tests/trigger-dirtyfrag-deny.py is missing")

xfrm_policy = (POLICY / "blastwall-xfrm-deny.cil").read_text(encoding="utf-8")
if " nlmsg " in xfrm_policy or "\nnlmsg " in xfrm_policy:
    fail("blastwall-xfrm-deny.cil uses invalid generic nlmsg permission")

print("PASS: Dirty Frag policy scopes are wired into markers and tests")

aap_config = (ROOT / "aap" / "configure-controller.yml").read_text(encoding="utf-8")
controller_vars = (ROOT / "aap" / "vars" / "blastwall-controller.yml").read_text(encoding="utf-8")
for required in [
    "ask_limit_on_launch: true",
    "blastwall_aap_policy_pipeline_candidate_group",
    "blastwall_policy_pipeline_build_hosts:",
    "blastwall_policy_pipeline_target_hosts:",
    "blastwall_verify_target_hosts:",
    "blastwall_verify_target_hosts: blastwall_policy_current",
]:
    if required not in aap_config:
        fail(f"aap/configure-controller.yml does not set {required}")

if "BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose a policy pipeline candidate group")

calabi_config = (ROOT / "poc-calabi" / "aap" / "20-configure-controller.yml").read_text(encoding="utf-8")
calabi_inventory = (ROOT / "poc-calabi" / "aap" / "inventory" / "blastwall-idm.yml").read_text(encoding="utf-8")
calabi_eigenstate = (ROOT / "poc-calabi" / "inventory-eigenstate.yml").read_text(encoding="utf-8")
if "idm_description" in calabi_eigenstate:
    fail("poc-calabi/inventory-eigenstate.yml still references idm_description in hostvars")
generic_inventory = (ROOT / "inventory" / "blastwall-idm.yml").read_text(encoding="utf-8")
for path_name, inventory_text in [
    ("inventory/blastwall-idm.yml", generic_inventory),
    ("poc-calabi/aap/inventory/blastwall-idm.yml", calabi_inventory),
]:
    if "idm_userclass" not in inventory_text:
        fail(f"{path_name} does not include idm_userclass")
    groups_text = inventory_text.split("\ngroups:", 1)[1]
    if "idm_description" in groups_text:
        fail(f"{path_name} still uses idm_description in policy grouping")
if "idm_userclass" not in calabi_eigenstate:
    fail("poc-calabi/inventory-eigenstate.yml does not include idm_userclass")
if "BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP: blastwall_policy_candidate" not in calabi_config:
    fail("Calabi AAP configuration does not use the candidate group for policy upgrades")
if "BLASTWALL_IDM_ADMIN_PRINCIPAL" not in calabi_config or "BLASTWALL_IDM_ADMIN_PASSWORD" not in calabi_config:
    fail("Calabi AAP configuration does not pass the IdM admin credential for marker promotion")
if "default(calabi_aap_runtime_password.stdout, true)" not in calabi_config:
    fail("Calabi IdM admin credential does not default to the AAP runtime secret")
if "blastwall_policy_candidate:" not in calabi_inventory:
    fail("Calabi AAP inventory does not define blastwall_policy_candidate")

for template, limit in [
    ("Blastwall build policy RPM", "limit: \"{{ blastwall_aap_policy_pipeline_candidate_group }}\""),
    (
        "Blastwall install candidate policy RPM",
        "limit: \"{{ blastwall_aap_policy_pipeline_candidate_group }}\"",
    ),
    ("Blastwall promote policy marker", "limit: \"{{ blastwall_aap_policy_pipeline_candidate_group }}\""),
]:
    template_index = controller_vars.find(f"name: {template}")
    if template_index == -1:
        fail(f"aap/vars/blastwall-controller.yml is missing {template}")
    next_template_index = controller_vars.find("\n  - name:", template_index + 1)
    template_block = controller_vars[
        template_index: next_template_index if next_template_index != -1 else len(controller_vars)
    ]
    if limit not in template_block:
        fail(f"{template} is not limited to blastwall_policy_stale for the policy pipeline")

for playbook in [
    ROOT / "playbooks" / "build-policy-rpm.yml",
    ROOT / "playbooks" / "install-policy-rpm.yml",
    ROOT / "playbooks" / "promote-policy-rpm.yml",
]:
    if "default('blastwall_policy_stale')" not in playbook.read_text(encoding="utf-8"):
        fail(f"{playbook.relative_to(ROOT)} does not default policy pipeline hosts to stale")

if "blastwall_verify_target_hosts | default('blastwall_policy_current')" not in (
    ROOT / "playbooks" / "verify-managed-host.yml"
).read_text(encoding="utf-8"):
    fail("playbooks/verify-managed-host.yml does not expose a runtime/pipeline host boundary")

print("PASS: AAP policy pipeline targets stale candidates before promotion")

collection_backed_marker_paths = [
    ROOT / "playbooks" / "deploy-policy.yml",
    ROOT / "poc-calabi" / "aap" / "25-seed-selection-fixture.yml",
]

for path in collection_backed_marker_paths:
    text = path.read_text(encoding="utf-8")
    for raw_cli in ["ipa host-mod", "ipa host-add", "hostgroup-add-member"]:
        if raw_cli in text:
            fail(f"{path.relative_to(ROOT)} uses raw {raw_cli} instead of collection modules")

promotion = (PLAYBOOKS / "promote-policy-rpm.yml").read_text(encoding="utf-8")
if "freeipa.ansible_freeipa.ipahost" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not use freeipa.ansible_freeipa.ipahost for marker writes")
if "--desc" in promotion:
    fail("playbooks/promote-policy-rpm.yml still writes host description markers")
if "userclass:" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not write host userClass markers")
if "ipa host-mod" in promotion and "FreeIPA CLI fallback" not in promotion:
    fail("playbooks/promote-policy-rpm.yml uses ipa host-mod without a named fallback boundary")

deploy_policy = (PLAYBOOKS / "deploy-policy.yml").read_text(encoding="utf-8")
if "description: \"{{ blastwall_policy_marker }}\"" in deploy_policy:
    fail("playbooks/deploy-policy.yml still writes policy markers to host description")
if "userclass:" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not write host userClass markers")
if "blastwall_clear_legacy_description_marker" not in promotion or "blastwall_clear_legacy_description_marker" not in deploy_policy:
    fail("policy marker playbooks do not clear legacy Blastwall description markers")

print("PASS: IdM marker writes use FreeIPA collection modules")

workflow = (ROOT / ".github" / "workflows" / "policy-pipeline-smoke.yml").read_text(encoding="utf-8")
if "SPO_APPLY_VALIDATE" not in workflow:
    fail("policy-pipeline-smoke.yml does not expose a SPO apply validation toggle")

day2_operations = (ROOT / "docs" / "day2-operations.html").read_text(encoding="utf-8").lower()
if "evidence contract" not in day2_operations:
    fail("docs/day2-operations.html no longer states the AAP evidence contract")
