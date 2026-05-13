#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/scripts/lib/demo-terminal.sh"

POC_ROOT="${BLASTWALL_POC_ROOT:-${REPO_ROOT}/poc-calabi}"
if [[ -d /opt/openshift/aws-metal-openshift-demo/blastwall/poc-calabi ]]; then
  POC_ROOT="${BLASTWALL_POC_ROOT:-/opt/openshift/aws-metal-openshift-demo/blastwall/poc-calabi}"
fi
if [[ -z "${BLASTWALL_LAB_SSH_KEY:-}" && -f "${HOME}/.ssh/id_ed25519" ]]; then
  export BLASTWALL_LAB_SSH_KEY="${HOME}/.ssh/id_ed25519"
fi
export PATH="${HOME}/.local/bin:/opt/openshift/aws-metal-openshift-demo/generated/tools/4.20.15/bin:${PATH}"
export KUBECONFIG="${KUBECONFIG:-${HOME}/etc/kubeconfig.local}"
if [[ -z "${IPA_ADMIN_PASSWORD:-}" ]] && command -v oc >/dev/null && [[ -f "${KUBECONFIG}" ]]; then
  IPA_ADMIN_PASSWORD="$(oc get secret -n aap workshop-aap-admin-password -o jsonpath='{.data.password}' | base64 -d)"
  export IPA_ADMIN_PASSWORD
fi
export BLASTWALL_AUTO_PASSWORD="${BLASTWALL_AUTO_PASSWORD:-${IPA_ADMIN_PASSWORD:-}}"

demo_section "Blastwall Ansible proof: operator-paced Dirty Frag / Fragnesia evidence"
demo_note "repo: ${POC_ROOT%/poc-calabi}"
demo_note "target: mirror-registry.workshop.lan"

demo_section "Enter the bastion-local PoC tree"
demo_run "cd '${POC_ROOT}'"
demo_run "pwd"

demo_section "Build the policy RPM that carries the deny scopes"
demo_run "ansible-playbook 20-build-policy-rpm.yml | tee /tmp/blastwall-build.log"

demo_section "Deploy policy and run the managed-host proof"
demo_run "ansible-playbook 30-deploy-and-test.yml | tee /tmp/blastwall-proof.log"

demo_section "Mark the public-response timing"
demo_run "date -u '+Dirty Frag / Fragnesia response marker: %Y-%m-%d %H:%M:%S UTC'"
demo_run "echo 'Blastwall 0.5.2: verify xfrm, RxRPC, and AF_ALG are denied for confined automation'"

demo_section "Pull the high-signal proof out of the playbook log"
demo_run "grep -E 'blastwall_u:blastwall_r:blastwall_t:s0|BLOCKED:|Dirty Frag|Fragnesia|PLAY RECAP' /tmp/blastwall-proof.log"

demo_section "Run the combined Dirty Frag / Fragnesia probe directly as the mapped identity"
demo_run "printf '%s\\n' \"\${BLASTWALL_AUTO_PASSWORD}\" | kinit svc-ansible-runner >/dev/null"
demo_run "ssh -o GSSAPIAuthentication=yes svc-ansible-runner@mirror-registry.workshop.lan /usr/local/libexec/blastwall-poc/trigger-dirtyfrag-deny.py"

demo_section "Read target-side SELinux audit evidence"
demo_run "ansible automation_endpoints -i inventory.yml -b -m shell -a \"grep -a 'subj=blastwall' /var/log/audit/audit.log | tr '\\035' '\\n' | grep -E 'type=SYSCALL.*(syscall=41|syscall=321|syscall=272).*exit=-13|SYSCALL=(socket|bpf|unshare).*AUID=\\\"svc-ansible-runner\\\"' | tail -n 16\""

demo_section "Prove the policy protects itself after sudo expansion"
demo_run "ansible-playbook 35-test-self-protection.yml | tee /tmp/blastwall-selfprotect.log"
demo_run "grep -E 'sudo_expansion_seen|semodule_attempt_rc|semodule_attempt_stderr|Permission denied|blastwall-(alg|bpf|packet|userns|io-uring|xfrm|rxrpc|policy)' /tmp/blastwall-selfprotect.log"

demo_section "Ansible proof complete"
