#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/scripts/lib/demo-terminal.sh"

command -v oc >/dev/null

assert_can_i() {
  local expected="$1"
  shift
  set +e
  local actual
  actual="$(oc auth can-i "$@" 2>/dev/null)"
  local rc=$?
  set -e
  if [[ "${rc}" -gt 1 ]]; then
    return "${rc}"
  fi
  echo "${actual}"
  [[ "${actual}" == "${expected}" ]]
}

demo_section "Blastwall OpenShift/SPO proof: standard and nested workload classes"
demo_note "cluster: ${KUBECONFIG:-default kubeconfig}"
demo_note "scope: safe UBI probe pods across the lab node set"

demo_section "Verify the SPO API and apply the bundle"
demo_run "oc explain rawselinuxprofile.spec --api-version=security-profiles-operator.x-k8s.io/v1alpha2 | sed -n '1,32p'"
demo_run "oc apply -k openshift/spo"

demo_section "Wait for both profiles and inspect usage strings"
demo_run "oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwall --timeout=180s"
demo_run "oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwallnested --timeout=180s"
demo_run "oc -n blastwall-spo get rawselinuxprofile blastwall -o jsonpath='standard={.status.usage}{\"\\n\"}'"
demo_run "oc -n blastwall-spo get rawselinuxprofile blastwallnested -o jsonpath='nested={.status.usage}{\"\\n\"}'"

demo_section "Confirm SCC admission stays scoped to the right service accounts"
demo_run "oc get scc blastwall-confined -o jsonpath='{.seLinuxContext.seLinuxOptions.type}{\"\\n\"}'"
demo_run "oc get scc blastwall-nested -o jsonpath='{.seLinuxContext.seLinuxOptions.type}{\" userNamespaceLevel=\"}{.userNamespaceLevel}{\"\\n\"}'"
demo_run "assert_can_i yes use scc/blastwall-confined --as system:serviceaccount:blastwall-workloads:blastwall-runner -n blastwall-workloads"
demo_run "assert_can_i yes use scc/blastwall-nested --as system:serviceaccount:blastwall-workloads:blastwall-nested-runner -n blastwall-workloads"
demo_run "assert_can_i no use scc/blastwall-nested --as system:serviceaccount:blastwall-workloads:blastwall-runner -n blastwall-workloads"

demo_section "Run standard and nested UBI workloads under the required SCCs"
demo_run "oc apply -f openshift/spo/examples/blastwall-protected-deployment.yaml"
demo_run "oc apply -f openshift/spo/examples/blastwall-nested-deployment.yaml"
demo_run "oc -n blastwall-workloads rollout status deploy/blastwall-demo --timeout=180s"
demo_run "oc -n blastwall-workloads rollout status deploy/blastwall-nested-demo --timeout=180s"
demo_run "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-demo -o wide"
demo_run "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-nested-demo -o wide"
demo_run "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-demo -o jsonpath='{range .items[*]}{.metadata.name}{\" scc=\"}{.metadata.annotations.openshift\\.io/scc}{\"\\n\"}{end}'"
demo_run "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-nested-demo -o jsonpath='{range .items[*]}{.metadata.name}{\" scc=\"}{.metadata.annotations.openshift\\.io/scc}{\" hostUsers=\"}{.spec.hostUsers}{\"\\n\"}{end}'"
demo_run "oc -n blastwall-workloads exec deploy/blastwall-demo -- sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current'"
demo_run "oc -n blastwall-workloads exec deploy/blastwall-nested-demo -- sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current; cat /proc/self/uid_map; cat /proc/self/gid_map'"

demo_section "Run safe node validation probes"
demo_run "openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class both --all"

demo_section "OpenShift/SPO proof complete"
