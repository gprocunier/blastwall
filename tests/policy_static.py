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
DEPLOY_POLICY_PLAYBOOK = PLAYBOOKS / "deploy-policy.yml"
EIGENSTATE_IPA_MINIMUM = (1, 18, 1)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_version_tuple(version: str) -> tuple[int, ...]:
    version = str(version).strip().strip("\"'")
    match = re.match(r"^(?:>=|==|=|~>)?\s*([0-9]+(?:\.[0-9]+)*)", version)
    if not match:
        fail(f"unsupported collection version constraint: {version}")
    return tuple(int(part) for part in match.group(1).split("."))


def assert_eigenstate_ipa_minimum(requirements_path: Path, minimum: tuple[int, ...]) -> None:
    data = yaml.safe_load(requirements_path.read_text(encoding="utf-8")) or {}
    collections = data.get("collections", [])
    for collection in collections:
        if collection.get("name") != "eigenstate.ipa":
            continue
        version = collection.get("version")
        if version is None:
            fail(f"{requirements_path} must pin eigenstate.ipa >= 1.18.1")
        if parse_version_tuple(str(version)) < minimum:
            fail(f"{requirements_path} pins eigenstate.ipa below 1.18.1: {version}")
        return
    fail(f"{requirements_path} does not declare eigenstate.ipa")


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
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value or "")) is not None
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


def walk_playbook_tasks(tasks, inside_rescue: bool = False):
    if not tasks:
        return

    for task in tasks:
        if not isinstance(task, dict):
            continue
        yield task, inside_rescue

        for key in ("block", "always", "rescue"):
            nested_tasks = task.get(key)
            if isinstance(nested_tasks, list):
                yield from walk_playbook_tasks(
                    nested_tasks,
                    inside_rescue or key == "rescue",
                )


for requirements_file in [
    ROOT / "requirements.yml",
    ROOT / "execution-environment" / "requirements.yml",
    ROOT / "poc-calabi" / "requirements.yml",
]:
    assert_eigenstate_ipa_minimum(requirements_file, EIGENSTATE_IPA_MINIMUM)


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
for usermanage_interface in ["usermanage_run_groupadd", "usermanage_run_useradd"]:
    if f"{usermanage_interface}(blastwall_t, blastwall_r)" not in te_source:
        fail(f"policy/blastwall.te must allow {usermanage_interface} for ordinary automation corpus user management")
for systemd_interface in ["init_reload_services", "systemd_exec_systemctl"]:
    if f"{systemd_interface}(blastwall_t)" not in te_source:
        fail(f"policy/blastwall.te must allow {systemd_interface} for ordinary automation corpus service management")

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
    "blastwall_aap_verify_target_group",
    'limit: "{{ blastwall_aap_verify_target_group }}"',
    'source_vars: "{{ blastwall_aap_inventory_source_vars }}"',
    'extra_vars: "{{ item.extra_vars | default(omit) }}"',
    "blastwall_aap_profile_extra_vars | combine",
    "'blastwall_policy_pipeline_target_hosts': blastwall_aap_policy_pipeline_candidate_group",
    "'blastwall_verify_target_hosts': blastwall_aap_verify_target_group",
    "'blastwall_verify_target_hosts': blastwall_aap_policy_pipeline_candidate_group",
    "'blastwall_preflight_target_group_override': blastwall_aap_post_promotion_preflight_target_group",
    'extra_data: "{{ blastwall_aap_spo_render_extra_vars }}"',
    'extra_data: "{{ blastwall_aap_spo_apply_extra_vars }}"',
]:
    if required not in aap_config:
        fail(f"aap/configure-controller.yml does not set {required}")

if "BLASTWALL_POLICY_PIPELINE_CANDIDATE_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose a policy pipeline candidate group")
if "BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose a post-promotion preflight target group")
if "BLASTWALL_AAP_VERIFY_TARGET_GROUP" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not expose the AAP verify target group")
for required_env in [
    "BLASTWALL_REQUIRED_POLICY_PROFILES",
    "BLASTWALL_ALLOW_DRY_RUN_PROFILES",
    "BLASTWALL_STRANGE_SOCKET_V1_DRY_RUN",
    "BLASTWALL_SPO_INCLUDE_STRANGE_SOCKET_V1",
    "BLASTWALL_SPO_VALIDATE_STRANGE_SOCKET_V1",
]:
    if required_env not in controller_vars:
        fail(f"aap/vars/blastwall-controller.yml does not expose {required_env}")
for required_var in [
    "blastwall_aap_profile_extra_vars:",
    "blastwall_aap_spo_render_extra_vars:",
    "blastwall_aap_spo_apply_extra_vars:",
    "blastwall_aap_inventory_source_vars:",
]:
    if required_var not in controller_vars:
        fail(f"aap/vars/blastwall-controller.yml does not define {required_var}")
if "default('blastwall_profile_base', true)" not in controller_vars:
    fail("aap/vars/blastwall-controller.yml does not default AAP verify targeting to blastwall_profile_base")
controller_post_promotion_group_pattern = re.compile(
    r"blastwall_aap_post_promotion_preflight_target_group:\s*>\-[^\n]*\n\s*\{\{\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP['\"]\s*\)\s*"
    r"\|\s*default\(\s*blastwall_aap_profile_post_promotion_preflight_group\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not controller_post_promotion_group_pattern.search(controller_vars):
    fail("aap/vars/blastwall-controller.yml must default post-promotion preflight targeting to a profile-derived group")
post_promotion_block = controller_vars.partition("blastwall_aap_post_promotion_preflight_target_group:")[2]
post_promotion_block = post_promotion_block.split("\n\n", 1)[0]
if "blastwall_aap_policy_pipeline_candidate_group" in post_promotion_block:
    fail("post-promotion preflight default must not be derived from the stale/candidate group")

calabi_config = (ROOT / "poc-calabi" / "aap" / "20-configure-controller.yml").read_text(encoding="utf-8")
calabi_inventory = (ROOT / "poc-calabi" / "aap" / "inventory" / "blastwall-idm.yml").read_text(encoding="utf-8")
calabi_eigenstate = (ROOT / "poc-calabi" / "inventory-eigenstate.yml").read_text(encoding="utf-8")
calabi_seed_fixture = (ROOT / "poc-calabi" / "aap" / "25-seed-selection-fixture.yml").read_text(encoding="utf-8")
calabi_idm_config = (ROOT / "poc-calabi" / "10-configure-idm.yml").read_text(encoding="utf-8")
calabi_idm_validate = (ROOT / "poc-calabi" / "15-validate-idm-with-eigenstate.yml").read_text(encoding="utf-8")
if "idm_description" in calabi_eigenstate:
    fail("poc-calabi/inventory-eigenstate.yml still references idm_description in hostvars")
if re.search(r"^\s*cmdcategory:\s*all\s*$", calabi_idm_config, re.MULTILINE):
    fail("poc-calabi/10-configure-idm.yml must not create broad cmdcategory=all sudo rules")
if "cmdcategory: \"\"" not in calabi_idm_config:
    fail("poc-calabi/10-configure-idm.yml must clear sudo cmdcategory before using command groups")
if "allow_sudocmdgroup:" not in calabi_idm_config:
    fail("poc-calabi/10-configure-idm.yml must attach the Blastwall sudo command group")
if "blastwall_eigen_sudo_rule.cmdcategory != 'all'" not in calabi_idm_validate:
    fail("poc-calabi/15-validate-idm-with-eigenstate.yml must reject cmdcategory=all")
if 'chdir: "{{ playbook_dir }}"' not in calabi_idm_validate:
    fail("poc-calabi/15-validate-idm-with-eigenstate.yml must render inventory relative to playbook_dir")
inventory_render_task = calabi_idm_validate.split("name: Render eigenstate.ipa IdM inventory candidate view", 1)[1]
inventory_render_task = inventory_render_task.split("name: Assert automation endpoint is visible", 1)[0]
if "ANSIBLE_COLLECTIONS_PATH" not in inventory_render_task:
    fail("poc-calabi/15-validate-idm-with-eigenstate.yml must set collection path for nested ansible-inventory")
if "no_log: true" in inventory_render_task:
    fail("poc-calabi/15-validate-idm-with-eigenstate.yml must not sanitize registered inventory stdout")
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
for strange_scope in strange_scopes.split(","):
    if strange_scope not in normalized_profile_base:
        fail(f"rendered blastwall_profile_base does not include strange-socket-v1 scope {strange_scope}")

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
            expected_expr = "idm_fqdn == 'mirror-registry.workshop.lan'"
        expected_normalized = re.sub(r"\s+", "", expected_expr)
        if actual_normalized != expected_normalized:
            fail(f"{path_name} has stale expression for {key}")

print("PASS: inventory profile grouping expressions are generated from policy/profiles")
if "idm_userclass" not in calabi_eigenstate:
    fail("poc-calabi/inventory-eigenstate.yml does not include idm_userclass")
if "BLASTWALL_AAP_VERIFY_TARGET_GROUP" not in calabi_config:
    fail("Calabi AAP configuration does not pass the managed-host verify target group")
calabi_aap_registry = (ROOT / "poc-calabi" / "aap" / "05-configure-ee-registry.yml").read_text(encoding="utf-8")
if "{{ ansible_env.HOME }}/.ssh/id_ed25519" in calabi_aap_registry:
    fail("Calabi AAP registry prep must not derive the bastion key path from ansible_env.HOME")
if "{{ calabi_operator_home }}/.ssh/id_ed25519" not in calabi_aap_registry:
    fail("Calabi AAP registry prep must use calabi_operator_home for the bastion key path")
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
for required_seed_fallback in [
    "Seed stale Blastwall fixture host with FreeIPA CLI fallback",
    "hostgroup-add-member",
    "KRB5CCNAME",
]:
    if required_seed_fallback not in calabi_seed_fixture:
        fail(f"Calabi AAP seed fixture is missing FreeIPA CLI fallback: {required_seed_fallback}")
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
    r"\s*['\"]blastwall-v3-signed-attestation['\"]\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not project_branch_env_pattern.search(calabi_config):
    fail(
        "Calabi AAP configuration does not default BLASTWALL_PROJECT_BRANCH to "
        "blastwall-v3-signed-attestation via env override"
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
    r"\|\s*default\(\s*lookup\(\s*['\"]env['\"]\s*,\s*['\"]BLASTWALL_POST_PROMOTION_PROFILE_GROUP['\"]\s*\)\s*"
    r"\|\s*default\(\s*['\"]blastwall_profile_base['\"]\s*,\s*true\s*\)\s*,\s*true\s*\)\s*\}\}",
    re.MULTILINE,
)
if not post_promotion_group_pattern.search(calabi_config):
    fail(
        "Calabi AAP configuration must default BLASTWALL_POST_PROMOTION_PREFLIGHT_TARGET_GROUP "
        "to a profile-derived group"
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
        fail(f"{template} is not limited to the configured policy pipeline candidate group")

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
if "sudo sh -c" in verify_policy:
    fail("playbooks/verify-managed-host.yml must not require a sudo shell wrapper")
for allowed_sudo_probe in ["sudo /usr/bin/id -u", "sudo /usr/bin/id -Z"]:
    if allowed_sudo_probe not in verify_policy:
        fail(f"playbooks/verify-managed-host.yml must use allowed sudo probe: {allowed_sudo_probe}")
if "blastwall_sudo_id" in verify_policy:
    fail("playbooks/verify-managed-host.yml must not reference stale combined sudo probe output")
for sudo_report_field in [
    'sudo_uid: "{{ blastwall_sudo_uid.stdout }}"',
    'sudo_context: "{{ blastwall_sudo_context.stdout }}"',
]:
    if sudo_report_field not in verify_policy:
        fail(f"playbooks/verify-managed-host.yml report must include {sudo_report_field}")
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
policy_hash_tool = ROOT / "tools" / "blastwall_policy_hash.py"
inventory_audit_tool = ROOT / "tools" / "audit_blastwall_inventory.py"
inventory_audit_playbook = PLAYBOOKS / "audit-inventory-membership.yml"
if not policy_hash_tool.exists():
    fail("tools/blastwall_policy_hash.py is missing")
if not inventory_audit_tool.exists():
    fail("tools/audit_blastwall_inventory.py is missing")
if not inventory_audit_playbook.exists():
    fail("playbooks/audit-inventory-membership.yml is missing")
inventory_audit = inventory_audit_tool.read_text(encoding="utf-8")
inventory_audit_playbook_text = inventory_audit_playbook.read_text(encoding="utf-8")
if "--fail-on-current-marker-parse-error" not in inventory_audit:
    fail("tools/audit_blastwall_inventory.py is missing --fail-on-current-marker-parse-error")
if "--fail-on-current-marker-parse-error" not in inventory_audit_playbook_text:
    fail("playbooks/audit-inventory-membership.yml does not default current marker parse errors to fatal")
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
if "target: uninstall-dry-run" not in deploy_policy or "not blastwall_enable_strange_socket_v1_dry_run | bool" not in deploy_policy:
    fail("playbooks/deploy-policy.yml does not remove dry-run modules when dry-run intent is absent")
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
for path_name, text in [
    ("playbooks/deploy-policy.yml", deploy_policy),
    ("playbooks/promote-policy-rpm.yml", promotion),
]:
    validation_indices = [
        text.find("Pre-validate active Blastwall marker before IdM publication"),
        text.find("Pre-validate promoted Blastwall marker before IdM publication"),
    ]
    validation_indices = [index for index in validation_indices if index != -1]
    validation_index = min(validation_indices) if validation_indices else -1
    publish_indices = [
        text.find("Publish active Blastwall host marker to IdM"),
        text.find("Publish Blastwall host marker to IdM"),
        text.find("Publish verified Blastwall host marker to IdM"),
    ]
    publish_indices = [index for index in publish_indices if index != -1]
    publish_index = min(publish_indices) if publish_indices else -1
    if validation_index == -1:
        fail(f"{path_name} is missing pre-publication marker validation")
    if publish_index == -1:
        fail(f"{path_name} is missing IdM marker publication")
    if validation_index > publish_index:
        fail(f"{path_name} validates the marker after IdM publication")
    for required_marker_gate in [
        "blastwall_marker.py",
        "--expected-registry-sha256",
        "--expected-policy-sha256",
        "--accepted-rpm",
        "--expected-target",
        "--required-profiles-csv",
        "--markers-stdin",
    ]:
        if required_marker_gate not in text:
            fail(f"{path_name} marker pre-validation is missing {required_marker_gate}")
    if "blastwall_policy_module_sha256" not in text:
        fail(f"{path_name} does not use the installed policy payload hash for markers")
if "artifact_sha256" not in install_policy or "policy_rpm_sha256" not in install_policy:
    fail("playbooks/install-policy-rpm.yml does not expose both artifact_sha256 and policy_rpm_sha256 evidence")
if "blastwall_policy_dry_run_modules" not in install_policy or "dry-run/{{ module }}.cil" not in install_policy:
    fail("playbooks/install-policy-rpm.yml does not install the dry-run RPM module when enabled")
if "Remove dry-run SELinux policy modules when not requested" not in install_policy:
    fail("playbooks/install-policy-rpm.yml does not remove dry-run modules when dry-run intent is absent")
if "Dry-run SELinux module {{ item }} is installed without dry-run intent" not in install_policy:
    fail("playbooks/install-policy-rpm.yml does not assert dry-run modules are absent in base mode")
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
for required_preflight_safety in [
    "blastwall_fail_on_no_eligible_hosts",
    "blastwall_validate_selected_markers",
    "BLASTWALL_DANGER_SKIP_MARKER_VALIDATION",
    "BLASTWALL_DANGER_SKIP_MARKER_VALIDATION_REASON",
    "marker_validation_enabled",
]:
    if required_preflight_safety not in preflight:
        fail(f"playbooks/preflight.yml is missing marker-validation safety control {required_preflight_safety}")
marker_check_index = preflight.find("Fail closed when selected hosts lack required Blastwall profile evidence")
if marker_check_index == -1:
    fail("playbooks/preflight.yml is missing selected-host marker validation")
marker_check_block_end = preflight.find("\n    - name:", marker_check_index + 1)
marker_check_block = preflight[
    marker_check_index: marker_check_block_end if marker_check_block_end != -1 else len(preflight)
]
if "blastwall_fail_on_stale_policy" in marker_check_block:
    fail("preflight marker validation is still gated by blastwall_fail_on_stale_policy")
if "blastwall_validate_selected_markers | bool" not in marker_check_block:
    fail("preflight marker validation is not gated by the explicit validation control")
if "'blastwall_preflight_target_group_override': blastwall_aap_post_promotion_preflight_target_group" not in aap_config:
    fail("AAP policy pipeline post-promotion preflight cannot override the target group")
policy_pipeline_preflight_block = aap_config.partition("identifier: post_promotion_preflight")[2].partition("when: item.identifier")[0]
if (
    "'BLASTWALL_TARGET_IDENTITY': blastwall_aap_identity" not in policy_pipeline_preflight_block
    or "'blastwall_target_identity': blastwall_aap_identity" not in policy_pipeline_preflight_block
    or "'blastwall_preflight_target_group_override': blastwall_aap_post_promotion_preflight_target_group" not in policy_pipeline_preflight_block
):
    fail("AAP policy pipeline post-promotion preflight must validate the runtime identity on the promoted candidate group")

print("PASS: AAP policy pipeline targets configured candidates before promotion")

if "freeipa.ansible_freeipa.ipahost" not in calabi_seed_fixture:
    fail("poc-calabi/aap/25-seed-selection-fixture.yml does not use the FreeIPA host collection module")
if "freeipa.ansible_freeipa.ipahostgroup" not in calabi_seed_fixture:
    fail("poc-calabi/aap/25-seed-selection-fixture.yml does not use the FreeIPA hostgroup collection module")

if "freeipa.ansible_freeipa.ipahost" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not use freeipa.ansible_freeipa.ipahost for marker writes")
for marker_write_text, path_name in [
    (promotion, "playbooks/promote-policy-rpm.yml"),
    (deploy_policy, "playbooks/deploy-policy.yml"),
]:
    if 'ipaadmin_principal: "{{ ipa_principal }}"' in marker_write_text:
        fail(f"{path_name} must not call FreeIPA marker writes with an unqualified Kerberos principal")
    if 'ipaadmin_principal: "{{ ipa_login_principal }}"' not in marker_write_text:
        fail(f"{path_name} must use the realm-qualified FreeIPA marker write principal")
if "Authenticate IdM principal for FreeIPA collection marker update" not in promotion:
    fail("playbooks/promote-policy-rpm.yml must create the AAP credential cache before FreeIPA marker writes")
if 'kinit "${IPA_LOGIN_PRINCIPAL}"' not in promotion or "/usr/bin/printf" not in promotion or "KRB5CCNAME" not in promotion:
    fail("playbooks/promote-policy-rpm.yml must authenticate into the injected Kerberos cache for collection writes")
if "lookup('file', blastwall_profile_registry_path, rstrip=False)" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not hash raw registry file bytes")
if "--desc" in promotion:
    fail("playbooks/promote-policy-rpm.yml still writes host description markers")
if "userclass:" not in promotion:
    fail("playbooks/promote-policy-rpm.yml does not write host userClass markers")
for fallback_text, path_name in [(promotion, "playbooks/promote-policy-rpm.yml"), (deploy_policy, "playbooks/deploy-policy.yml")]:
    if "ipa host-mod" in fallback_text and "FreeIPA CLI fallback" not in fallback_text:
        fail(f"{path_name} uses ipa host-mod without a named fallback boundary")
    if "ipa host-mod" in fallback_text:
        for required_fallback_guard in [
            "BLASTWALL_ALLOW_IPA_CLI_FALLBACK",
            "BLASTWALL_ALLOW_IPA_CLI_FALLBACK_REASON",
            "blastwall_allow_ipa_cli_fallback | bool",
            "blastwall_allow_ipa_cli_fallback_reason | length > 0",
            "Stop when FreeIPA CLI fallback is not approved",
        ]:
            if required_fallback_guard not in fallback_text:
                fail(f"{path_name} raw IPA CLI fallback is missing explicit guard {required_fallback_guard}")
if "blastwall_marker_emit_argv_base" not in promotion:
    fail("playbooks/promote-policy-rpm.yml should define blastwall_marker_emit_argv_base for command-argv marker generation")
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
if "blastwall_marker_emit_argv_base" not in deploy_policy:
    fail("playbooks/deploy-policy.yml should define blastwall_marker_emit_argv_base for command-argv marker generation")
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
for required_rollback_signal in [
    "--state=rollback-active",
    "--state=rollback-failed",
    "Verify Blastwall rollback result",
    "Publish rollback-active Blastwall host marker to IdM",
    "Publish rollback-failed Blastwall host marker to IdM",
    "Publish failed Blastwall host marker to IdM when rollback is disabled",
]:
    if required_rollback_signal not in deploy_policy:
        fail(f"playbooks/deploy-policy.yml is missing rollback evidence signal: {required_rollback_signal}")
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

print("PASS: IdM marker writes use FreeIPA collection modules with bounded fallbacks")

workflow = (ROOT / ".github" / "workflows" / "policy-pipeline-smoke.yml").read_text(encoding="utf-8")
if "SPO_APPLY_VALIDATE" not in workflow:
    fail("policy-pipeline-smoke.yml does not expose a SPO apply validation toggle")
for required_workflow_evidence in [
    "policy_rpm_sha256",
    "artifact_sha256",
    "policy_sha256=[0-9a-f]{64}",
    "registry_sha256=[0-9a-f]{64}",
    "profiles=base",
]:
    if required_workflow_evidence not in workflow:
        fail(f"policy-pipeline-smoke.yml does not assert {required_workflow_evidence}")

spo_apply = (ROOT / "playbooks" / "apply-validate-spo-policy-crs.yml").read_text(encoding="utf-8")
spo_node_validator = (ROOT / "openshift" / "spo" / "scripts" / "validate-blastwall-spo-nodes.sh").read_text(
    encoding="utf-8"
)
for required_spo_guard in [
    "Assert OpenShift/SPO status.usage format is recognized",
    "spo_validation_classes",
]:
    if required_spo_guard not in spo_apply:
        fail(f"playbooks/apply-validate-spo-policy-crs.yml is missing SPO guard {required_spo_guard}")
if "FAIL: Unknown OpenShift/SPO status.usage format" not in spo_node_validator:
    fail("OpenShift/SPO node validator does not fail closed for unknown status.usage")

day2_operations = (ROOT / "docs" / "day2-operations.html").read_text(encoding="utf-8").lower()
if "evidence contract" not in day2_operations:
    fail("docs/day2-operations.html no longer states the AAP evidence contract")

required_phase08_docs = [
    "operator-one-page-summary.md",
    "troubleshooting-runbook.md",
    "inventory-diagnostic-decision-tree.md",
    "stable-or-reference-decision.md",
    "ownership-and-escalation.md",
    "scope-triage-policy.md",
    "future-scope-triage.md",
    "tabletop-fail-stale-marker.md",
    "positioning-against-detection-tools.md",
    "base-corpus-replay-report.md",
    "spo-compatibility-matrix.md",
    "phase-08-remediation-checkpoint.md",
    "phase-08-calabi-final-checkpoint.md",
]
for doc_name in required_phase08_docs:
    docs_path = ROOT / "docs" / "blastwall-v2" / doc_name
    if not docs_path.exists():
        fail(f"required Phase 08 evidence doc is missing: {docs_path.relative_to(ROOT)}")

markers_doc = (ROOT / "docs" / "blastwall-v2" / "markers.md").read_text(encoding="utf-8").lower()
if "policy_sha256=<policy-rpm-sha256>" in markers_doc:
    fail("docs/blastwall-v2/markers.md still documents policy_sha256 as the RPM hash")
if "policy_sha256=` is the verified policy rpm artifact hash" in markers_doc:
    fail("docs/blastwall-v2/markers.md still uses old RPM-as-policy-hash wording")
if "installed blastwall policy" not in markers_doc or "artifact_sha256" not in markers_doc:
    fail("docs/blastwall-v2/markers.md does not document the policy/artifact hash split")

corpus_playbook = ROOT / "tests" / "corpus" / "base_automation_corpus.yml"
if not corpus_playbook.exists():
    fail("tests/corpus/base_automation_corpus.yml is missing")
corpus_text = corpus_playbook.read_text(encoding="utf-8")
for required_corpus_task in [
    "Require corpus to run under Blastwall login context",
    "package_facts",
    "lineinfile",
    "blastwall-corpus.service",
    "ansible.builtin.uri",
]:
    if required_corpus_task not in corpus_text:
        fail(f"base automation corpus is missing {required_corpus_task}")

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

deploy_policy = yaml.safe_load(DEPLOY_POLICY_PLAYBOOK.read_text(encoding="utf-8"))
if not isinstance(deploy_policy, list) or not deploy_policy:
    fail(f"{DEPLOY_POLICY_PLAYBOOK.relative_to(ROOT)} must be a non-empty playbook document list")
deploy_tasks = deploy_policy[0].get("tasks", [])
if not isinstance(deploy_tasks, list):
    fail(f"{DEPLOY_POLICY_PLAYBOOK.relative_to(ROOT)} is missing a task list")

deploy_marker_fallbacks = {
    "Publish active Blastwall host marker with FreeIPA CLI fallback": "Publish active Blastwall host marker to IdM with collection",
    "Publish failed Blastwall host marker with FreeIPA CLI fallback": "Publish failed Blastwall host marker with collection",
}

for fallback_name, collection_name in deploy_marker_fallbacks.items():
    seen_fallback = False
    seen_fallback_in_rescue = False
    seen_fallback_outside_rescue = False
    seen_collection = False

    for task, in_rescue in walk_playbook_tasks(deploy_tasks):
        task_name = task.get("name")
        if not isinstance(task_name, str):
            continue
        if task_name == fallback_name:
            seen_fallback = True
            if in_rescue:
                seen_fallback_in_rescue = True
            else:
                seen_fallback_outside_rescue = True
        if task_name == collection_name:
            seen_collection = True

    if not seen_fallback:
        fail(f"deploy-policy.yml missing required fallback marker publication task: {fallback_name}")
    if not seen_fallback_in_rescue:
        fail(f"deploy-policy.yml fallback marker task must be in a rescue block: {fallback_name}")
    if seen_fallback_outside_rescue:
        fail(f"deploy-policy.yml fallback marker task appears outside rescue: {fallback_name}")
    if not seen_collection:
        fail(f"deploy-policy.yml missing required collection marker publication task: {collection_name}")

print("PASS: deploy-policy marker publication fallbacks are guarded by rescue blocks")

v3_sign = (ROOT / "playbooks" / "sign-attestation.yml").read_text(encoding="utf-8")
v3_promote = (ROOT / "playbooks" / "promote-policy-rpm.yml").read_text(encoding="utf-8")
v3_preflight = (ROOT / "playbooks" / "preflight.yml").read_text(encoding="utf-8")
v3_hbac_access = (ROOT / "playbooks" / "hbac-access-test.yml").read_text(encoding="utf-8")
v3_health = (ROOT / "playbooks" / "attestation-vault-health.yml").read_text(encoding="utf-8")
aap_vars = (ROOT / "aap" / "vars" / "blastwall-controller.yml").read_text(encoding="utf-8")
aap_controller = (ROOT / "aap" / "configure-controller.yml").read_text(encoding="utf-8")
for required_v3_file in [
    "policy/attestation-schema.json",
    "policy/attestation-envelope-schema.json",
    "policy/attestation-index-schema.json",
    "tools/blastwall_attestation_sign.py",
    "tools/blastwall_attestation_verify.py",
    "tools/blastwall_attestation_vault.py",
]:
    if not (ROOT / required_v3_file).exists():
        fail(f"missing v3 attestation file: {required_v3_file}")
for required_v3_doc in [
    "signed-attestation-design.md",
    "operator-runbook.md",
    "kra-topology-runbook.md",
    "revocation-and-breakglass.md",
    "stable-v3-readiness-checklist.md",
    "external-review-packet.md",
    "shell-and-collection-exceptions.md",
]:
    if not (ROOT / "docs" / "blastwall-v3" / required_v3_doc).exists():
        fail(f"missing v3 documentation file: docs/blastwall-v3/{required_v3_doc}")
for inventory_path in [
    ROOT / "inventory" / "blastwall-idm.yml",
    ROOT / "poc-calabi" / "inventory-eigenstate.yml",
    ROOT / "poc-calabi" / "aap" / "inventory" / "blastwall-idm.yml",
]:
    inventory_doc = yaml.safe_load(inventory_path.read_text(encoding="utf-8")) or {}
    hostvars_include = set(inventory_doc.get("hostvars_include", []))
    if "idm_userclass" not in hostvars_include:
        fail(f"{inventory_path} must request eigenstate.ipa normalized idm_userclass hostvars")
    for companion_hostvar in [
        "idm_userclass_raw",
        "idm_userclass_type",
        "idm_schema_warnings",
    ]:
        if companion_hostvar in hostvars_include:
            fail(
                f"{inventory_path} must not put eigenstate.ipa companion hostvar "
                f"{companion_hostvar} in hostvars_include; request idm_userclass and let "
                "the 1.18.1 inventory plugin emit companions"
            )
    inventory_text = inventory_path.read_text(encoding="utf-8")
    if inventory_path.name != "inventory-eigenstate.yml":
        for expected_signal in ["idm_userclass_type", "idm_schema_warnings"]:
            if expected_signal not in inventory_text:
                fail(f"{inventory_path} must consume eigenstate.ipa companion hostvar {expected_signal}")

poc_calabi_validation = (ROOT / "poc-calabi" / "15-validate-idm-with-eigenstate.yml").read_text(encoding="utf-8")
for expected_signal in ["idm_userclass_type", "idm_schema_warnings"]:
    if expected_signal not in poc_calabi_validation:
        fail(f"poc-calabi/15-validate-idm-with-eigenstate.yml must consume eigenstate.ipa companion hostvar {expected_signal}")
for required_signer_signal in [
    "Blastwall sign attestation",
    "blastwall_aap_attestation_idm_credential",
    "blastwall_aap_attestation_signer_credential",
    "blastwall_aap_attestation_verifier_credential",
    "BLASTWALL_ATTESTATION_SIGNER_KEY",
]:
    if required_signer_signal not in aap_vars + aap_controller + v3_sign:
        fail(f"v3 AAP signer workflow missing {required_signer_signal}")
signer_key_var = "blastwall_aap_attestation_signer_credential"
verifier_var = "blastwall_aap_attestation_verifier_credential"
if signer_key_var in v3_preflight or signer_key_var in v3_promote:
    fail("stable-v3 preflight/promotion must not receive the signer private-key credential")
if verifier_var not in aap_controller:
    fail("AAP stable-v3 preflight/promotion must attach verifier credential")
stable_v3_preflight_block = aap_controller.partition("Attach attestation verifier credential to stable-v3 preflight")[2].partition("Attach attestation verifier credential to stable-v3 marker promotion")[0]
if "blastwall_aap_attestation_idm_credential" not in stable_v3_preflight_block:
    fail("AAP stable-v3 preflight must authenticate with the attestation custody IdM credential for KRA reads")
idm_admin_credential_block = aap_controller.partition("Ensure Blastwall IdM admin credential exists")[2].partition("Ensure optional Blastwall OpenShift credential exists")[0]
if (
    'ipa_principal: "{{ blastwall_aap_idm_admin_principal }}"' not in idm_admin_credential_block
    or 'blastwall_identity: "{{ blastwall_aap_identity }}"' not in idm_admin_credential_block
):
    fail("AAP IdM admin credential must authenticate as admin while injecting the runtime Blastwall identity")
if (
    "BLASTWALL_TARGET_IDENTITY" not in stable_v3_preflight_block
    or "blastwall_target_identity" not in stable_v3_preflight_block
    or "blastwall_aap_identity" not in stable_v3_preflight_block
):
    fail("AAP stable-v3 preflight must validate the runtime Blastwall identity, not the KRA custody principal")
if (
    "BLASTWALL_TARGET_IDENTITY" not in aap_vars
    or "blastwall_target_identity" not in aap_vars
    or "blastwall_aap_attestation_extra_vars:" not in aap_vars
):
    fail("AAP attestation workflow extra vars must carry the runtime Blastwall target identity")
if "blastwall_aap_policy_idm_credential" in aap_vars.partition("blastwall_aap_v3_job_templates:")[2]:
    fail("AAP v3 attestation signing must not use the policy maintainer IdM credential for vault custody")
for required_sign_custody_signal in [
    "Build signed attestation envelope and latest index",
    "eigenstate.ipa.vault_artifact",
    "Archive attestation envelope with eigenstate vault artifact custody",
    "Archive latest index with eigenstate vault artifact custody",
    "Assert attestation vault read-back verified",
    "Verify stored signed attestation before marker publication",
    "build-artifacts",
    "verify-existing",
]:
    if required_sign_custody_signal not in v3_sign:
        fail(f"sign-attestation.yml does not enforce collection-backed custody signal: {required_sign_custody_signal}")
if "sign-store-readback" in v3_sign:
    fail("sign-attestation.yml must not use the raw-vault sign-store-readback default path")
if "Write FreeIPA client config for attestation vault writes" not in v3_sign:
    fail("sign-attestation.yml must configure the FreeIPA client before vault collection operations")
if "Install injected FreeIPA CA for attestation vault writes" not in v3_sign:
    fail("sign-attestation.yml must install the injected FreeIPA CA before vault collection operations")
if "blastwall_v3_attestation_marker_by_host" not in v3_sign:
    fail("sign-attestation.yml must propagate signed locator markers to downstream workflow jobs")
if "Use signed stable-v3 locator marker from pipeline signing evidence" not in v3_promote:
    fail("promote-policy-rpm.yml must consume signer-provided markers across AAP job boundaries")
if "--profile=\\\\1" in v3_sign or "--profile=\\\\1" in v3_promote:
    fail("stable-v3 signing/promotion must not emit literal --profile=\\1 argv entries")
if "map('regex_replace', '^', '--profile=')" not in v3_sign:
    fail("sign-attestation.yml must prefix required profiles without regex backrefs")
if "map('regex_replace', '^', '--profile=')" not in v3_promote:
    fail("promote-policy-rpm.yml must prefix required profiles without regex backrefs")
if "Verify stable-v3 attestation before marker publication" not in v3_promote:
    fail("promote-policy-rpm.yml does not verify stable-v3 artifacts before marker publication")
for required_live_preflight_signal in [
    "FreeIPA CLI fallback read live stable-v3 host marker hints from FreeIPA",
    "BLASTWALL_ALLOW_IPA_CLI_FALLBACK",
    "BLASTWALL_ALLOW_IPA_CLI_FALLBACK_REASON",
    "BLASTWALL_RUN_HBAC_OPERATION_TEST",
    "Check stable-v3 KRA vault health",
    "eigenstate.ipa.vault_health",
    "eigenstate.ipa.access_path",
    "hbac-access-test.yml",
    "Run collection-backed HBAC access test for group-scoped readiness",
    "eigenstate.ipa.sudo_risk",
    "Resolve stable-v3 signed attestation artifact locations",
    "Read stable-v3 attestation envelopes with eigenstate vault artifact custody",
    "Read stable-v3 latest indexes with eigenstate vault artifact custody",
    "resolve-existing",
    "eigenstate.ipa.vault_artifact",
    "blastwall_attestation_vault_servers",
    "blastwall_live_userclass_by_host",
    "blastwall_attestation_vault_server_list",
    "Resolve configured stable-v3 KRA vault servers",
    "blastwall_attestation_vault_primary in blastwall_attestation_vault_server_list",
]:
    if required_live_preflight_signal not in v3_preflight:
        fail(
            "stable-v3 preflight must fall back to live FreeIPA marker hints "
            f"when controller inventory propagation lags: {required_live_preflight_signal}"
        )
preflight_ipa_config_index = v3_preflight.find("Write FreeIPA client config for controller-side lookups")
preflight_vault_health_index = v3_preflight.find("Check stable-v3 KRA vault health")
preflight_hbac_diagnostic_index = v3_preflight.find("Run diagnostic collection-backed HBAC operation test")
preflight_hbac_test_index = v3_preflight.find("Run collection-backed HBAC access test for group-scoped readiness")
preflight_access_path_index = v3_preflight.find("Read Blastwall IdM access path")
if (
    preflight_ipa_config_index == -1
    or preflight_vault_health_index == -1
    or preflight_hbac_diagnostic_index == -1
    or preflight_hbac_test_index == -1
    or preflight_access_path_index == -1
):
    fail("stable-v3 preflight is missing FreeIPA client bootstrap, HBAC proof, KRA health, or access-path checks")
if preflight_ipa_config_index > preflight_access_path_index:
    fail("stable-v3 preflight must write FreeIPA client config before access-path checks")
if preflight_access_path_index > preflight_vault_health_index:
    fail("stable-v3 preflight must run access-path and sudo guard before KRA vault health")
hbac_operation_block = v3_preflight[preflight_hbac_diagnostic_index:preflight_access_path_index]
if "when: blastwall_run_hbac_operation_test | bool" not in hbac_operation_block:
    fail("stable-v3 isolated HBAC operation test must be diagnostic-only")
if "blastwall_target_identity" not in v3_preflight:
    fail("stable-v3 preflight must separate target identity from the IdM credential auth principal")
if 'principal: "{{ blastwall_target_identity }}"' not in v3_preflight:
    fail("stable-v3 preflight access-path proof must validate the runtime target identity")
if "blastwall_target_identity | string" not in v3_hbac_access:
    fail("stable-v3 isolated HBAC proof must pass target identity as a string to eigenstate.ipa.hbacrule")
if "targethost=blastwall_target_host | string" not in v3_hbac_access:
    fail("stable-v3 isolated HBAC proof must pass targethost as a string to eigenstate.ipa.hbacrule")
if "Write FreeIPA client config for isolated HBAC lookup" not in v3_hbac_access:
    fail("stable-v3 HBAC proof must bootstrap FreeIPA config inside the isolated process")
if "lookup('eigenstate.ipa.selinuxmap'" in v3_preflight:
    fail("stable-v3 preflight must use eigenstate.ipa.access_path instead of lookup('eigenstate.ipa.selinuxmap'")
if "lookup('eigenstate.ipa.hbacrule'" in v3_preflight:
    fail("stable-v3 preflight must run hbacrule lookup in an isolated process to avoid parent ipalib state drift")
if "lookup('eigenstate.ipa.hbacrule'" not in v3_hbac_access or "operation='test'" not in v3_hbac_access:
    fail("stable-v3 preflight may use hbacrule only for collection-backed operation=test group-scope proof")
if "blastwall_selinux_map.selinuxuser" in v3_preflight:
    fail("stable-v3 preflight report must not reference removed selinuxmap lookup state")
if "retrieve-existing" in v3_preflight:
    fail("stable-v3 preflight must use vault_artifact retrieval, not raw-vault retrieve-existing")
if "skeleton" in v3_health.lower() or "placeholder" in v3_health.lower():
    fail("attestation-vault-health.yml must not contain skeleton or placeholder health logic")
for required_health_signal in [
    "eigenstate.ipa.vault_health",
    "require_direct_kra: true",
    "FAIL_INFRA_VAULT_KRA",
    "FAIL_INFRA_VAULT_AUTH",
    "FAIL_INFRA_VAULT_TIMEOUT",
    "FAIL_CANARY_STALE",
    "canary_present",
    "canary_stale",
    "Resolve configured KRA vault servers",
]:
    if required_health_signal not in v3_health:
        fail(f"attestation-vault-health.yml missing real vault health signal {required_health_signal}")
if "^blastwall:.*(?:^blastwall:|;)v=3" in v3_preflight:
    fail("stable-v3 preflight marker selector does not match blastwall:v=3 prefix markers")
if "'sign_attestation'] if blastwall_aap_attestation_enabled" not in aap_controller:
    fail("AAP policy pipeline does not route verified candidates through sign_attestation before marker promotion")
v3_verifier = (ROOT / "tools" / "blastwall_attestation_verify.py").read_text(encoding="utf-8")
if "FAIL_ATTESTATION_NOT_VISIBLE" not in v3_verifier or "FAIL_INDEX_NOT_VISIBLE" not in v3_verifier:
    fail("stable-v3 preflight/verifier does not expose missing artifact/index failure states")
print("PASS: v3 signed attestation workflow keeps signer, verifier, and marker promotion separated")
