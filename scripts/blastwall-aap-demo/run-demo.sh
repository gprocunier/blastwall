#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/scripts/lib/demo-terminal.sh"

export PATH="${HOME}/.local/bin:/opt/openshift/aws-metal-openshift-demo/generated/tools/4.20.15/bin:${PATH}"
export KUBECONFIG="${KUBECONFIG:-${HOME}/etc/kubeconfig.local}"
export TOWER_HOST="${TOWER_HOST:-https://workshop-aap-controller-aap.apps.ocp.workshop.lan}"
export TOWER_VERIFY_SSL="${TOWER_VERIFY_SSL:-false}"
export TOWER_USERNAME="${TOWER_USERNAME:-blastwall-demo}"
if [[ -z "${TOWER_PASSWORD:-}" ]]; then
  TOWER_PASSWORD="$(oc get secret -n aap workshop-aap-admin-password -o jsonpath='{.data.password}' | base64 -d)"
  export TOWER_PASSWORD
fi

demo_section "Blastwall AAP proof: operator-paced Dirty Frag / Fragnesia evidence"
demo_note "controller: ${TOWER_HOST}"
demo_note "launcher: ${TOWER_USERNAME}"
demo_note "repo: https://github.com/gprocunier/blastwall.git main"

demo_section "Prove the Controller session"
demo_run "awx ping | jq '{controller_version: .version, active_node, capacity: .instances[0].capacity}'"
demo_run "awx me -f human"

demo_section "Inspect the AAP objects the workflow will use"
demo_run "awx projects list --name Blastwall -f human"
demo_run "awx execution_environments list --name 'Blastwall EE' -f human"
demo_run "awx inventory_sources list --name 'Blastwall IdM Inventory Source' -f human"
demo_run "awx credentials list --name 'Blastwall IdM Runtime' -f human"
demo_run "workflow_template_id=\"\$(awx workflow_job_templates list --name 'Blastwall runtime verification' -f json | jq -r '.results[0].id')\""
demo_run "awx workflow_job_template_nodes list --workflow_job_template \"\${workflow_template_id}\" -f json | jq -r '.results[] | [.identifier, .summary_fields.unified_job_template.name] | @tsv'"

demo_section "Mark the public-response timing"
demo_run "date -u '+Dirty Frag / Fragnesia response marker: %Y-%m-%d %H:%M:%S UTC'"
demo_run "echo 'Blastwall 0.5.2: verify xfrm, RxRPC, and AF_ALG are denied for confined automation'"

demo_section "Launch and monitor the runtime verification workflow"
demo_run "awx workflow_job_templates launch \"\${workflow_template_id}\" -f json | tee /tmp/blastwall-aap-launch.json | jq '{workflow_job, status, launched_by: .launched_by.name}'"
demo_run "workflow_id=\"\$(jq -r '.workflow_job' /tmp/blastwall-aap-launch.json)\""
demo_run "awx workflow_jobs monitor \"\${workflow_id}\""
demo_run "awx workflow_job_nodes list --workflow_job \"\${workflow_id}\" -f json | tee /tmp/blastwall-aap-nodes.json | jq -r '.results[] | [.identifier, .summary_fields.job.id, .summary_fields.job.type, .summary_fields.job.status] | @tsv'"

demo_section "Read the Controller-side gate and host-local proof"
demo_run "credential_id=\"\$(jq -r '.results[] | select(.identifier == \"credential_smoke\") | .summary_fields.job.id' /tmp/blastwall-aap-nodes.json)\""
demo_run "preflight_id=\"\$(jq -r '.results[] | select(.identifier == \"preflight\") | .summary_fields.job.id' /tmp/blastwall-aap-nodes.json)\""
demo_run "verify_id=\"\$(jq -r '.results[] | select(.identifier == \"verify_managed_host\") | .summary_fields.job.id' /tmp/blastwall-aap-nodes.json)\""
demo_run "awx jobs stdout \"\${credential_id}\" | grep -E 'credential_smoke|passed|blastwall-ssh'"
demo_run "awx jobs stdout \"\${preflight_id}\" | grep -E 'blastwall-root-local-map|blastwall-ssh|blastwall-root-local-sudo|\"candidate_hosts\"|\"selected_hosts\"|\"stale_hosts\"|\"selinux_user\"|mirror-registry.workshop.lan|stale-blastwall-01.workshop.lan|All assertions passed'"
demo_run "awx jobs stdout \"\${verify_id}\" | grep -E 'blastwall_u:blastwall_r:blastwall_t:s0|SKIP: could not create AF_ALG socket|Dirty Frag|Fragnesia|BLOCKED:|PLAY RECAP'"

demo_section "AAP proof complete"
