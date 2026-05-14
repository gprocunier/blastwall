#!/usr/bin/env python3
"""Static checks for Blastwall policy scope wiring."""

from pathlib import Path
import hashlib
import importlib.util
import re
import sys
import yaml
from jinja2 import Environment


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy"
PLAYBOOKS = ROOT / "playbooks"
PROFILE_REGISTRY_SHA256 = hashlib.sha256((ROOT / "policy" / "profiles.yml").read_bytes()).hexdigest()
RENDER_INVENTORY_GROUPS = ROOT / "tools" / "render_inventory_profile_groups.py"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def jinja_bool_filter(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def inventory_expression_environment() -> Environment:
    env = Environment()
    env.filters["bool"] = jinja_bool_filter
    env.filters["regex_escape"] = re.escape
    return env


def select_match_string_arguments(text: str):
    """Yield raw-prefix flag and first quoted argument literal for select('match')."""
    for match in re.finditer(r"select\('match',\s*(r?)(['\"])", text):
        raw_prefix = match.group(1)
        quote = match.group(2)
        index = match.end()
        literal = []
        escaped = False
        while index < len(text):
            char = text[index]
            if escaped:
                literal.append(char)
                escaped = False
            elif char == "\\":
                literal.append(char)
                escaped = True
            elif char == quote:
                break
            else:
                literal.append(char)
            index += 1
        yield raw_prefix, "".join(literal)


makefile = (POLICY / "Makefile").read_text(encoding="utf-8")
version_match = re.search(r"^VERSION\s*:=\s*(.+)$", makefile, re.MULTILINE)
if not version_match:
    fail("policy/Makefile does not define VERSION")
policy_version = version_match.group(1).strip()

te_source = (POLICY / "blastwall.te").read_text(encoding="utf-8")
module_match = re.search(r"^policy_module\(blastwall,\s*([^)]+)\)", te_source, re.MULTILINE)
if not module_match:
    fail("policy/blastwall.te does not define policy_module(blastwall, ...)")
module_version = module_match.group(1).strip()
if module_version != policy_version:
    fail(f"policy/blastwall.te version {module_version} does not match policy/Makefile VERSION {policy_version}")

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

dry_run_match = re.search(r"^DRY_RUN_POLICIES\s*:=\s*(.+)$", makefile, re.MULTILINE)
if not dry_run_match:
    fail("policy/Makefile does not define DRY_RUN_POLICIES")

dry_run_policies = dry_run_match.group(1).split()
if dry_run_policies != ["blastwall-strange-socket-v1-deny"]:
    fail("DRY_RUN_POLICIES must contain only blastwall-strange-socket-v1-deny")
if "blastwall-strange-socket-v1-deny" in deny_policies:
    fail("strange-socket-v1 dry-run policy must not be in default DENY_POLICIES")
if not re.search(r"^install-dry-run:\n\tsemodule -i \$\(DRY_RUN_CIL\)$", makefile, re.MULTILINE):
    fail("policy/Makefile install-dry-run must install only DRY_RUN_CIL")

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

for policy in dry_run_policies:
    cil_path = POLICY / f"{policy}.cil"
    if not cil_path.exists():
        fail(f"{cil_path.relative_to(ROOT)} is listed but missing")
    cil = cil_path.read_text(encoding="utf-8")
    for required in ["xdp_socket", "tipc_socket", "can_socket", "bluetooth_socket", "nfc_socket", "kcm_socket", "rds_socket"]:
        if required not in cil:
            fail(f"{cil_path.relative_to(ROOT)} does not cover {required}")
    if "(optional " not in cil or "(deny " not in cil or "(neverallow " not in cil:
        fail(f"{cil_path.relative_to(ROOT)} must use optional deny plus neverallow blocks")

print("PASS: validated dry-run strange-socket-v1 policy is not default-active")

dirtyfrag_scopes = {
    "blastwall-xfrm-deny": "xfrm",
    "blastwall-rxrpc-deny": "rxrpc",
}

for policy, marker in dirtyfrag_scopes.items():
    if policy not in deny_policies:
        fail(f"{policy} is required for Dirty Frag coverage")
    for path in [
        ROOT / "inventory" / "blastwall-idm.yml",
        ROOT / "poc-calabi" / "aap" / "inventory" / "blastwall-idm.yml",
        ROOT / "tests" / "fixtures" / "inventory-policy-markers.json",
    ]:
        if marker not in path.read_text(encoding="utf-8"):
            fail(f"{path.relative_to(ROOT)} does not require {marker}")

dirtyfrag_probe_path = ROOT / "tests" / "trigger-dirtyfrag-deny.py"
if not dirtyfrag_probe_path.exists():
    fail("tests/trigger-dirtyfrag-deny.py is missing")
dirtyfrag_probe = dirtyfrag_probe_path.read_text(encoding="utf-8")
for required in ["Fragnesia AF_ALG", "FAIL_MISSING_CLASS_REQUIRED", "FAIL_UNKNOWN", "FAIL_ALLOWED"]:
    if required not in dirtyfrag_probe:
        fail(f"tests/trigger-dirtyfrag-deny.py does not enforce {required} evidence")

xfrm_policy = (POLICY / "blastwall-xfrm-deny.cil").read_text(encoding="utf-8")
if "Fragnesia" not in xfrm_policy:
    fail("blastwall-xfrm-deny.cil does not document Fragnesia coverage")
if " nlmsg " in xfrm_policy or "\nnlmsg " in xfrm_policy:
    fail("blastwall-xfrm-deny.cil uses invalid generic nlmsg permission")

for workflow in [
    ROOT / ".github" / "workflows" / "lab-smoke.yml",
    ROOT / ".github" / "workflows" / "policy-pipeline-smoke.yml",
]:
    workflow_text = workflow.read_text(encoding="utf-8")
    if "Fragnesia AF_ALG" not in workflow_text:
        fail(f"{workflow.relative_to(ROOT)} does not assert Fragnesia AF_ALG evidence")

print("PASS: Dirty Frag / Fragnesia policy scopes are wired into markers and tests")

aap_config = (ROOT / "aap" / "configure-controller.yml").read_text(encoding="utf-8")
controller_vars = (ROOT / "aap" / "vars" / "blastwall-controller.yml").read_text(encoding="utf-8")
for required in [
    "ask_limit_on_launch: true",
    "blastwall_aap_policy_pipeline_candidate_group",
    "blastwall_policy_pipeline_build_hosts:",
    "blastwall_policy_pipeline_target_hosts:",
    "blastwall_verify_target_hosts:",
    "blastwall_aap_verify_target_group",
    'limit: "{{ blastwall_aap_verify_target_group }}"',
    'blastwall_verify_target_hosts: "{{ blastwall_aap_verify_target_group }}"',
]:
    if required not in aap_config:
        fail(f"aap/configure-controller.yml does not set {required}")

if "BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose a policy pipeline candidate group")
if "BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose a post-promotion preflight target group")
if "BLASTWALL_AAP_VERIFY_TARGET_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose the AAP verify target group")
if "default('blastwall_profile_base', true)" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not default AAP verify targeting to blastwall_profile_base")
controller_post_promotion_group_pattern = re.compile(
    r"blastwall_aap_post_promotion_preflight_target_group:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP['\"]\s*\)\s*"
    r"\|\s*default\(\s*['\"]['\"]\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not controller_post_promotion_group_pattern.search(controller_vars):
    fail("aap/vars/blastwall-controller.yml must default post-promotion preflight targeting to the profile-derived group")

calabi_config = (ROOT / "poc-calabi" / "aap" / "20-configure-controller.yml").read_text(encoding="utf-8")
calabi_inventory = (ROOT / "poc-calabi" / "aap" / "inventory" / "blastwall-idm.yml").read_text(encoding="utf-8")
calabi_eigenstate = (ROOT / "poc-calabi" / "inventory-eigenstate.yml").read_text(encoding="utf-8")
calabi_seed_fixture = (ROOT / "poc-calabi" / "aap" / "25-seed-selection-fixture.yml").read_text(encoding="utf-8")
if "idm_description" in calabi_eigenstate:
    fail("poc-calabi/inventory-eigenstate.yml still references idm_description in hostvars")
generic_inventory = (ROOT / "inventory" / "blastwall-idm.yml").read_text(encoding="utf-8")
inventory_renderer_spec = importlib.util.spec_from_file_location(
    "render_inventory_profile_groups",
    RENDER_INVENTORY_GROUPS,
)
if inventory_renderer_spec is None or inventory_renderer_spec.loader is None:
    fail("could not load tools/render_inventory_profile_groups.py")
inventory_renderer = importlib.util.module_from_spec(inventory_renderer_spec)
sys.modules["render_inventory_profile_groups"] = inventory_renderer
inventory_renderer_spec.loader.exec_module(inventory_renderer)
rendered_inventory_groups = inventory_renderer.render_profile_group_expressions()
jinja_env = inventory_expression_environment()
for key, expression in rendered_inventory_groups.items():
    try:
        jinja_env.compile_expression(expression)
    except Exception as exc:
        fail(f"tools/render_inventory_profile_groups.py renders invalid Jinja for {key}: {exc}")

profile_stale_expr = rendered_inventory_groups.get("blastwall_policy_stale")
profile_candidate_expr = rendered_inventory_groups.get("blastwall_policy_candidate")
if profile_candidate_expr is None:
    fail("tools/render_inventory_profile_groups.py is missing blastwall_policy_candidate")
if re.sub(r"\s+", "", profile_candidate_expr) != re.sub(r"\s+", "", profile_stale_expr or ""):
    fail("generic blastwall_policy_candidate must be generated from the stale policy cohort")

profile_base_expr = rendered_inventory_groups.get("blastwall_profile_base")
if profile_base_expr is None:
    fail("tools/render_inventory_profile_groups.py is missing blastwall_profile_base")
if "BLASTWALL_ALLOW_DRY_RUN_PROFILES" not in profile_base_expr:
    fail("rendered blastwall_profile_base does not guard dry-run profiles behind BLASTWALL_ALLOW_DRY_RUN_PROFILES")
normalized_profile_base = re.sub(r"\s+", "", profile_base_expr)

strange_marker = inventory_renderer.blastwall_marker.emit_marker_v2(
    registry=inventory_renderer.blastwall_marker.load_registry(),
    registry_hash=PROFILE_REGISTRY_SHA256,
    policy_hash="a" * 64,
    rpm=inventory_renderer.blastwall_marker.DEFAULT_RPM,
    profiles=["base", "strange-socket-v1"],
    allow_dry_run_profiles=True,
)
strange_fields: dict[str, str] = {}
for token in strange_marker.removeprefix("blastwall:").split(";"):
    if "=" not in token:
        continue
    key, value = token.split("=", 1)
    strange_fields[key] = value
strange_profiles = strange_fields.get("profiles", "")
strange_scopes = strange_fields.get("scopes", "")
if not strange_profiles or not strange_scopes:
    fail("could not derive canonical strange-socket-v1 emission profile fields")
if f"profiles={strange_profiles}" not in normalized_profile_base:
    fail("rendered blastwall_profile_base misses canonical profiles=base,strange-socket-v1 branch")
if f"scopes={strange_scopes}" not in normalized_profile_base:
    fail("rendered blastwall_profile_base does not include canonical strange-socket-v1 scope sequence")

for path_name, inventory_text in [
    ("inventory/blastwall-idm.yml", generic_inventory),
    ("poc-calabi/aap/inventory/blastwall-idm.yml", calabi_inventory),
]:
    if "idm_userclass" not in inventory_text:
        fail(f"{path_name} does not include idm_userclass")
    if PROFILE_REGISTRY_SHA256 not in inventory_text:
        fail(f"{path_name} does not default to the current profile registry hash")
    for required_inventory_knob in [
        "BLASTWALL_REQUIRED_POLICY_MARKER",
        "BLASTWALL_PROFILE_REGISTRY_SHA256",
    ]:
        if required_inventory_knob not in inventory_text:
            fail(f"{path_name} does not expose {required_inventory_knob} for release-candidate grouping")
    groups_text = inventory_text.split("\ngroups:", 1)[1]
    if "idm_description" in groups_text:
        fail(f"{path_name} still uses idm_description in policy grouping")
    for raw_prefix, literal in select_match_string_arguments(groups_text):
        if raw_prefix:
            fail(f"{path_name} uses Python raw-string syntax inside a Jinja select('match') expression")
        if "lookup('env'" in literal:
            fail(f"{path_name} embeds lookup('env', ...) inside a quoted regex literal")
    inventory_data = yaml.safe_load(inventory_text)
    inventory_groups = inventory_data.get("groups", {})
    for key, actual_expr in inventory_groups.items():
        if not isinstance(actual_expr, str):
            fail(f"{path_name} group {key} is not a string expression")
        try:
            jinja_env.compile_expression(actual_expr)
        except Exception as exc:
            fail(f"{path_name} group {key} is invalid Jinja: {exc}")
    for key, expected_expr in rendered_inventory_groups.items():
        actual_expr = inventory_groups.get(key)
        if not isinstance(actual_expr, str):
            fail(f"{path_name} is missing rendered group expression {key}")
        actual_normalized = re.sub(r"\s+", "", actual_expr)
        if path_name == "poc-calabi/aap/inventory/blastwall-idm.yml" and key == "blastwall_policy_candidate":
            expected_expr = f"idm_fqdn == 'mirror-registry.workshop.lan' and\n(\n{expected_expr}\n)"
        expected_normalized = re.sub(r"\s+", "", expected_expr)
        if actual_normalized != expected_normalized:
            fail(f"{path_name} has stale expression for {key}")

print("PASS: inventory profile grouping expressions are generated from policy/profiles")
if "idm_userclass" not in calabi_eigenstate:
    fail("poc-calabi/inventory-eigenstate.yml does not include idm_userclass")
if "BLASTWALL_AAP_VERIFY_TARGET_GROUP" not in calabi_config:
    fail("Calabi AAP configuration does not pass the managed-host verify target group")
if "BLASTWALL_IDM_ADMIN_PRINCIPAL" not in calabi_config or "BLASTWALL_IDM_ADMIN_PASSWORD" not in calabi_config:
    fail("Calabi AAP configuration does not pass the IdM admin credential for marker promotion")
if "default(calabi_aap_runtime_password.stdout, true)" not in calabi_config:
    fail("Calabi IdM admin credential does not default to the AAP runtime secret")
if "blastwall_policy_candidate:" not in calabi_inventory:
    fail("Calabi AAP inventory does not define blastwall_policy_candidate")
if "BLASTWALL_PROJECT_BRANCH" not in calabi_config:
    fail("Calabi AAP configuration does not pass BLASTWALL_PROJECT_BRANCH")
if "BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP" not in calabi_config:
    fail("Calabi AAP configuration does not pass the post-promotion preflight target group")
project_url_env_pattern = re.compile(
    r"BLASTWALL_PROJECT_URL:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_PROJECT_URL['\"]\s*\)\s*\|\s*default\("
    r"\s*['\"]https://github\.com/gprocunier/blastwall\.git['\"]\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not project_url_env_pattern.search(calabi_config):
    fail(
        "Calabi AAP configuration does not default BLASTWALL_PROJECT_URL to "
        "the upstream Blastwall project via env override"
    )
project_branch_env_pattern = re.compile(
    r"BLASTWALL_PROJECT_BRANCH:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_PROJECT_BRANCH['\"]\s*\)\s*\|\s*default\("
    r"\s*['\"]blastwall-v2-phase-08-rc1k['\"]\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not project_branch_env_pattern.search(calabi_config):
    fail(
        "Calabi AAP configuration does not default BLASTWALL_PROJECT_BRANCH to "
        "blastwall-v2-phase-08-rc1k via env override"
    )
candidate_group_pattern = re.compile(
    r"BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP['\"]\s*\)\s*"
    r"\|\s*default\(\s*['\"]blastwall_policy_candidate['\"]\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not candidate_group_pattern.search(calabi_config):
    fail(
        "Calabi AAP configuration does not env-override BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP "
        "to blastwall_policy_candidate"
    )
post_promotion_group_pattern = re.compile(
    r"BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP['\"]\s*\)\s*"
    r"\|\s*default\(\s*['\"]['\"]\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not post_promotion_group_pattern.search(calabi_config):
    fail(
        "Calabi AAP configuration must default BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP "
        "to the profile-derived group"
    )

stale_host_match = re.search(
    r"calabi_blastwall_stale_host:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_STALE_HOST['\"]\s*\)\s*"
    r"\|\s*default\(\s*['\"]([^'\"]+)['\"]\s*,\s*true\s*\)\s*\}\}",
    calabi_seed_fixture,
    re.MULTILINE,
)
if not stale_host_match:
    fail("Calabi AAP seed-selection fixture does not define BLASTWALL_STALE_HOST default")

candidate_host_match = re.search(
    r"blastwall_policy_candidate:\s*>\-[^\n]*\n\s*idm_fqdn\s*==\s*['\"]([^'\"]+)['\"]",
    calabi_inventory,
    re.MULTILINE,
)
if not candidate_host_match:
    fail("Calabi AAP inventory does not define blastwall_policy_candidate FQDN guard")

if stale_host_match.group(1) != candidate_host_match.group(1):
    fail("Calabi AAP seed stale host default diverges from inventory blastwall_policy_candidate host filter")

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

verify_policy = (ROOT / "playbooks" / "verify-managed-host.yml").read_text(encoding="utf-8")
if "blastwall_verify_target_hosts | default('blastwall_policy_current')" in verify_policy:
    fail("playbooks/verify-managed-host.yml must not default managed-host verification to blastwall_policy_current")
if "blastwall_verify_target_hosts | default('blastwall_profile_base')" not in verify_policy:
    fail("playbooks/verify-managed-host.yml does not default managed-host verification to blastwall_profile_base")
if "required_blastwall_profiles:" not in verify_policy:
    fail("playbooks/verify-managed-host.yml does not derive required profile set for verify path")
if (
    "blastwall_required_profiles_env" not in verify_policy
    or "else ['base']" not in verify_policy
):
    fail("playbooks/verify-managed-host.yml does not default BLASTWALL_REQUIRED_PROFILE intent to base")
if "BLASTWALL_REQUIRED_POLICY_PROFILES |" not in verify_policy:
    fail("playbooks/verify-managed-host.yml does not read BLASTWALL_REQUIRED_POLICY_PROFILES")
if (
    "BLASTWALL_ALLOW_DRY_RUN_PROFILES |" not in verify_policy
    or "default('false', true)" not in verify_policy
):
    fail("playbooks/verify-managed-host.yml does not gate strange-socket-v1 verification on canonical dry-run allow")
for required_verify_contract in [
    "blastwall_strange_socket_v1_legacy_dry_run_raw",
    "Assert strange-socket-v1 dry-run intent is consistent",
    "derived profile intent",
]:
    if required_verify_contract not in verify_policy:
        fail(f"playbooks/verify-managed-host.yml is missing profile-aware verify contract: {required_verify_contract}")

preflight = (PLAYBOOKS / "preflight.yml").read_text(encoding="utf-8")
install_policy = (PLAYBOOKS / "install-policy-rpm.yml").read_text(encoding="utf-8")
promotion = (PLAYBOOKS / "promote-policy-rpm.yml").read_text(encoding="utf-8")
deploy_policy = (PLAYBOOKS / "deploy-policy.yml").read_text(encoding="utf-8")
for path_name, text in [
    ("playbooks/deploy-policy.yml", deploy_policy),
    ("playbooks/install-policy-rpm.yml", install_policy),
    ("playbooks/preflight.yml", preflight),
    ("playbooks/promote-policy-rpm.yml", promotion),
]:
    for required_dry_run_contract in [
        "BLASTWALL_REQUIRED_POLICY_PROFILES",
        "BLASTWALL_ALLOW_DRY_RUN_PROFILES",
        "blastwall_strange_socket_v1_requested",
        "blastwall_strange_socket_v1_legacy_dry_run_raw",
        "blastwall_enable_strange_socket_v1_dry_run",
        "Assert strange-socket-v1 dry-run intent is consistent",
    ]:
        if required_dry_run_contract not in text:
            fail(f"{path_name} is missing canonical dry-run intent contract: {required_dry_run_contract}")
    if (
        "BLASTWALL_STRANGE_SOCKET_V1_DRY_RUN" in text
        and "derived profile intent" not in text
        and "derived dry-run profile intent" not in text
    ):
        fail(f"{path_name} uses legacy dry-run intent without canonical mismatch protection")
if re.search(r"\{%[^\n]*if\s+blastwall_enable_strange_socket_v1_dry_run\s*%\}", install_policy):
    fail("playbooks/install-policy-rpm.yml uses blastwall_enable_strange_socket_v1_dry_run in an if without | bool")
if re.search(
    r"blastwall_policy_dry_run_modules\s+if\s+blastwall_enable_strange_socket_v1_dry_run\s*else",
    install_policy,
) and not re.search(
    r"blastwall_policy_dry_run_modules\s+if\s+blastwall_enable_strange_socket_v1_dry_run\s*\|\s*bool\s*else",
    install_policy,
):
    fail("playbooks/install-policy-rpm.yml uses blastwall_enable_strange_socket_v1_dry_run in module inclusion without | bool")

for required in [
    "BLASTWALL_REQUIRED_POLICY_PROFILES",
    "blastwall_required_profiles_env",
    "blastwall_strange_socket_v1_requested",
    "BLASTWALL_STRANGE_SOCKET_V1_DRY_RUN",
    "blastwall_enable_strange_socket_v1_dry_run",
]:
    if required not in verify_policy:
        fail(f"playbooks/verify-managed-host.yml is missing profile-aware verify contract: {required}")

if "target: install-dry-run" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not install dry-run modules through policy/Makefile install-dry-run")
for required_source_install in [
    "blastwall_policy_dry_run_modules",
    "blastwall_policy_modules_effective",
    "loop: \"{{ blastwall_policy_modules_effective }}\"",
    "loop: \"{{ blastwall_policy_modules_effective | reverse | list }}\"",
]:
    if required_source_install not in deploy_policy:
        fail(f"playbooks/deploy-policy.yml is missing dry-run source deploy validation: {required_source_install}")
active_marker_index = deploy_policy.find("Render active Blastwall marker for collection writes")
install_complete_index = deploy_policy.find("Assert Blastwall policy install is complete")
if active_marker_index == -1 or install_complete_index == -1 or active_marker_index < install_complete_index:
    fail("playbooks/deploy-policy.yml must render the active marker only after policy validation")
if "blastwall_policy_dry_run_modules" not in install_policy or "dry-run/{{ module }}.cil" not in install_policy:
    fail("playbooks/install-policy-rpm.yml does not install the dry-run RPM module when enabled")
if "--oldpackage" not in install_policy:
    fail("playbooks/install-policy-rpm.yml does not allow replaying an RC candidate RPM with the same NEVRA")

for required in [
    "required_blastwall_profiles:",
    "BLASTWALL_REQUIRED_POLICY_PROFILES",
    "BLASTWALL_ALLOW_DRY_RUN_PROFILES",
    "blastwall_profile_registry_sha256",
    "lookup('file', blastwall_profile_registry_path, rstrip=False)",
    "registry_sha256=",
    "--allow-dry-run-profiles",
    "blastwall_base_scope_csv: alg_socket,bpf,capability2_bpf,packet_socket,userns,io_uring,xfrm,rxrpc,selfprotect",
    "strange-socket-v1",
    "blastwall_profile_preflight_group:",
    "blastwall_preflight_target_group_override",
    "blastwall_preflight_effective_group:",
    "blastwall_profile_base",
    "blastwall_profile_strange_socket_v1",
]:
    if required not in preflight:
        fail(f"playbooks/preflight.yml is missing profile preflight check: {required}")
if "groups['blastwall_policy_current']" in preflight:
    fail("playbooks/preflight.yml must select profile-specific groups, not blastwall_policy_current")
if "blastwall_preflight_target_group_override: \"{{ blastwall_aap_post_promotion_preflight_target_group }}\"" not in aap_config:
    fail("AAP policy pipeline post-promotion preflight cannot override the target group")

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

if "freeipa.ansible_freeipa.ipahost" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not use freeipa.ansible_freeipa.ipahost for marker writes")
if "lookup('file', blastwall_profile_registry_path, rstrip=False)" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not hash raw registry file bytes")
if "--desc" in promotion:
    fail("playbooks/promote-policy-rpm.yml still writes host description markers")
if "userclass:" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not write host userClass markers")
if "ipa host-mod" in promotion and "FreeIPA CLI fallback" not in promotion:
    fail("playbooks/promote-policy-rpm.yml uses ipa host-mod without a named fallback boundary")
if "blastwall_marker_emit_command" not in promotion:
    fail("playbooks/promote-policy-rpm.yml should define blastwall_marker_emit_command for helper-based marker generation")
if (
    "--emit" not in promotion
    or "--target=rhel-login" not in promotion
    or "--rpm" not in promotion
    or "--state=active" not in promotion
    or "--state=failed" not in promotion
    or "--profile" not in promotion
    or "--allow-dry-run-profiles" not in promotion
    or "BLASTWALL_REQUIRED_POLICY_PROFILES" not in promotion
    or "BLASTWALL_ALLOW_DRY_RUN_PROFILES" not in promotion
    or "--policy-sha256" not in promotion
):
    fail(
        "playbooks/promote-policy-rpm.yml should call blastwall_marker.py with "
        "--emit, --rpm, --state, --profile, --allow-dry-run-profiles, and --policy-sha256 for marker generation"
    )
if "blastwall:v=2;state=active" in promotion or "blastwall:v=2;state=failed" in promotion:
    fail("playbooks/promote-policy-rpm.yml appears to build marker payloads by hand instead of helper output")

if "description: \"{{ blastwall_policy_marker }}\"" in deploy_policy:
    fail("playbooks/deploy-policy.yml still writes policy markers to host description")
if "lookup('file', blastwall_profile_registry_path, rstrip=False)" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not hash raw registry file bytes")
if "userclass:" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not write host userClass markers")
if "blastwall_marker_emit_command" not in deploy_policy:
    fail("playbooks/deploy-policy.yml should define blastwall_marker_emit_command for helper-based marker generation")
if "blastwall_clear_legacy_description_marker" not in promotion or "blastwall_clear_legacy_description_marker" not in deploy_policy:
    fail("policy marker playbooks do not clear legacy Blastwall description markers")
if (
    "--emit" not in deploy_policy
    or "--target=rhel-login" not in deploy_policy
    or "--rpm" not in deploy_policy
    or "--state=active" not in deploy_policy
    or "--state=failed" not in deploy_policy
    or "--profile" not in deploy_policy
    or "--allow-dry-run-profiles" not in deploy_policy
    or "BLASTWALL_REQUIRED_POLICY_PROFILES" not in deploy_policy
    or "BLASTWALL_ALLOW_DRY_RUN_PROFILES" not in deploy_policy
    or "--policy-sha256" not in deploy_policy
):
    fail(
        "playbooks/deploy-policy.yml should call blastwall_marker.py with "
        "--emit, --rpm, --state, --profile, --allow-dry-run-profiles, and --policy-sha256 for marker generation"
    )
if "blastwall:v=2;state=active" in deploy_policy or "blastwall:v=2;state=failed" in deploy_policy:
    fail("playbooks/deploy-policy.yml appears to build marker payloads by hand instead of helper output")
if "blastwall_policy_marker.stdout" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not use blastwall_policy_marker.stdout")
if "blastwall_policy_failed_marker.stdout" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not use blastwall_policy_failed_marker.stdout")
if "blastwall_base_scopes" in deploy_policy:
    fail("playbooks/deploy-policy.yml still tracks blastwall_base_scopes for marker generation")
if "blastwall_base_scopes" in promotion:
    fail("playbooks/promote-policy-rpm.yml still tracks blastwall_base_scopes for marker generation")
if (
    "blastwall_policy_marker: >-" in promotion
    or "blastwall_policy_marker: >-" in deploy_policy
    or ("blastwall_policy_marker:" in promotion and "blastwall_policy_marker.stdout" not in promotion)
    or ("blastwall_policy_marker:" in deploy_policy and "blastwall_policy_marker.stdout" not in deploy_policy)
):
    fail("marker playbooks keep old raw marker payload variable instead of using helper stdout consistently")
if (
    "blastwall_policy_failed_marker: >-" in promotion
    or "blastwall_policy_failed_marker: >-" in deploy_policy
    or ("blastwall_policy_failed_marker:" in promotion and "blastwall_policy_failed_marker.stdout" not in promotion)
    or ("blastwall_policy_failed_marker:" in deploy_policy and "blastwall_policy_failed_marker.stdout" not in deploy_policy)
):
    fail("marker playbooks keep old raw failed marker payload variable instead of using helper stdout consistently")

print("PASS: IdM marker writes use FreeIPA collection modules")

workflow = (ROOT / ".github" / "workflows" / "policy-pipeline-smoke.yml").read_text(encoding="utf-8")
if "SPO_APPLY_VALIDATE" not in workflow:
    fail("policy-pipeline-smoke.yml does not expose a SPO apply validation toggle")

day2_operations = (ROOT / "docs" / "day2-operations.html").read_text(encoding="utf-8").lower()
if "evidence contract" not in day2_operations:
    fail("docs/day2-operations.html no longer states the AAP evidence contract")

for docs_path in (ROOT / "docs" / "blastwall-v2").glob("*.md"):
    docs_text = docs_path.read_text(encoding="utf-8").lower()
    if "profiles=base-nested" in docs_text:
        fail(f"{docs_path.relative_to(ROOT)} describes base-nested as a marker profile")
    if "killswitch" in docs_text:
        fail(f"{docs_path.relative_to(ROOT)} keeps killswitch in RC-facing roadmap docs")

rc_frontmatter_docs = {
    "release-notes.md",
    "backlog.md",
    "developer-guide.md",
    "spo-compatibility.md",
}
for rc_doc in rc_frontmatter_docs:
    docs_path = ROOT / "docs" / "blastwall-v2" / rc_doc
    docs_text = docs_path.read_text(encoding="utf-8").lower()
    if "rc1e" in docs_text:
        fail(f"{docs_path.relative_to(ROOT)} still contains stale RC1e wording; use RC1k/current-RC language")
    if "rc1j" in docs_text:
        fail(f"{docs_path.relative_to(ROOT)} still contains stale RC1j wording; use RC1k/current-RC language")
