#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --all
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --role worker
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class standard --role worker
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class nested --selector 'node-role.kubernetes.io/worker='

Options:
  --class NAME           standard, nested, or both. Default: both.
  --keep                 Keep validation pods for troubleshooting.
  --namespace NAME       Workload namespace. Default: blastwall-workloads.
  --profile-namespace N  SPO profile namespace. Default: blastwall-spo.
  --image IMAGE          UBI Python image to run. Default: BLASTWALL_SPO_TEST_IMAGE or ubi9/python-312.
USAGE
}

namespace="blastwall-workloads"
profile_namespace="blastwall-spo"
image="${BLASTWALL_SPO_TEST_IMAGE:-registry.access.redhat.com/ubi9/python-312:latest}"
selector=""
keep="false"
class_filter="both"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)
      selector=""
      shift
      ;;
    --role)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case "$2" in
        worker) selector="node-role.kubernetes.io/worker=" ;;
        infra) selector="node-role.kubernetes.io/infra=" ;;
        master|control-plane) selector="node-role.kubernetes.io/master=" ;;
        *) echo "Unknown role: $2" >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --selector)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      selector="$2"
      shift 2
      ;;
    --class)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case "$2" in
        standard|nested|both) class_filter="$2" ;;
        *) echo "Unknown class: $2" >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --keep)
      keep="true"
      shift
      ;;
    --namespace)
      namespace="$2"
      shift 2
      ;;
    --profile-namespace)
      profile_namespace="$2"
      shift 2
      ;;
    --image)
      image="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

command -v oc >/dev/null
command -v jq >/dev/null

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifact_dir="${repo_root}/artifacts/openshift-spo"
mkdir -p "${artifact_dir}"

oc apply -k "${repo_root}/openshift/spo" >/dev/null
oc -n "${profile_namespace}" wait --for=condition=ready rawselinuxprofile/blastwall --timeout=180s >/dev/null
oc -n "${profile_namespace}" wait --for=condition=ready rawselinuxprofile/blastwallnested --timeout=180s >/dev/null

node_json="$(
  if [[ -n "${selector}" ]]; then
    oc get nodes -l "${selector}" -o json
  else
    oc get nodes -o json
  fi
)"

mapfile -t skipped_nodes < <(
  jq -r '
    .items[]
    | select(
        ((.spec.unschedulable // false) == true)
        or (([.status.conditions[] | select(.type == "Ready")][0].status // "False") != "True")
      )
    | .metadata.name
  ' <<<"${node_json}"
)

mapfile -t nodes < <(
  jq -r '
    .items[]
    | select(
        ((.spec.unschedulable // false) == false)
        and (([.status.conditions[] | select(.type == "Ready")][0].status // "False") == "True")
      )
    | .metadata.name
  ' <<<"${node_json}"
)

for skipped_node in "${skipped_nodes[@]}"; do
  echo "SKIP: ${skipped_node}: node is not Ready and schedulable"
done

if [[ ${#nodes[@]} -eq 0 ]]; then
  echo "SKIP: no nodes matched selector '${selector:-all}'"
  exit 0
fi

case "${class_filter}" in
  standard) classes=(standard) ;;
  nested) classes=(nested) ;;
  both) classes=(standard nested) ;;
esac

summary="${artifact_dir}/spo-node-validation.jsonl"
: > "${summary}"
overall=0

for profile_class in "${classes[@]}"; do
  class_overall=0
  case "${profile_class}" in
    standard)
      scc="blastwall-confined"
      service_account="blastwall-runner"
      expected_type="${BLASTWALL_SPO_STANDARD_TYPE:-blastwall_.process}"
      pod_prefix="blastwall-spo"
      host_users_line=""
      ;;
    nested)
      scc="blastwall-nested"
      service_account="blastwall-nested-runner"
      expected_type="${BLASTWALL_SPO_NESTED_TYPE:-blastwallnested_.process}"
      pod_prefix="blastwall-nested-spo"
      host_users_line="  hostUsers: false"
      ;;
  esac

  for node in "${nodes[@]}"; do
    node_slug="$(echo "${node}" | tr '.[:upper:]' '-[:lower:]' | tr -cd 'a-z0-9-')"
    pod="${pod_prefix}-${node_slug}"
    oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=true >/dev/null
    cat <<EOF | oc apply -f - >/dev/null 2>"${artifact_dir}/${pod}.apply.warn"
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: blastwall
    app.kubernetes.io/component: validation
    blastwall.io/profile: openshift-spo
    blastwall.io/workload-class: ${profile_class}
  annotations:
    openshift.io/required-scc: ${scc}
spec:
${host_users_line}
  restartPolicy: Never
  serviceAccountName: ${service_account}
  nodeName: ${node}
  tolerations:
    - operator: Exists
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: ${image}
      command: ["python3", "/opt/blastwall/blastwall_spo_probe.py"]
      env:
        - name: BLASTWALL_EXPECTED_SELINUX_TYPE
          value: "${expected_type}"
        - name: BLASTWALL_PROFILE_CLASS
          value: "${profile_class}"
      volumeMounts:
        - name: probe
          mountPath: /opt/blastwall
          readOnly: true
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
  volumes:
    - name: probe
      configMap:
        name: blastwall-spo-probe
        defaultMode: 0555
EOF

    deadline=$((SECONDS + 120))
    phase=""
    while (( SECONDS < deadline )); do
      phase="$(oc -n "${namespace}" get pod "${pod}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      [[ "${phase}" == "Succeeded" || "${phase}" == "Failed" ]] && break
      sleep 2
    done

    admitted_scc="$(oc -n "${namespace}" get pod "${pod}" -o jsonpath='{.metadata.annotations.openshift\.io/scc}' 2>/dev/null || true)"
    if [[ "${admitted_scc}" != "${scc}" ]]; then
      echo "FAIL: ${profile_class}: ${node}: admitted with SCC '${admitted_scc:-missing}', expected '${scc}'"
      jq -nc --arg node "${node}" --arg class "${profile_class}" --arg status "FAIL" --arg detail "wrong SCC admission" \
        '{node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
      class_overall=1
      overall=1
      [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
      continue
    fi

    if [[ "${profile_class}" == "nested" ]]; then
      host_users="$(oc -n "${namespace}" get pod "${pod}" -o jsonpath='{.spec.hostUsers}' 2>/dev/null || true)"
      if [[ "${host_users}" != "false" ]]; then
        echo "FAIL: nested: ${node}: spec.hostUsers is '${host_users:-missing}', expected false"
        jq -nc --arg node "${node}" --arg class "${profile_class}" --arg status "FAIL" --arg detail "hostUsers is not false" \
          '{node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
        class_overall=1
        overall=1
        [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
        continue
      fi
    fi

    if [[ "${phase}" != "Succeeded" && "${phase}" != "Failed" ]]; then
      reason="$(oc -n "${namespace}" get pod "${pod}" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
      echo "FAIL: ${profile_class}: ${node}: pod did not complete (${phase:-unknown} ${reason:-unknown})"
      jq -nc --arg node "${node}" --arg class "${profile_class}" --arg status "FAIL" --arg detail "pod did not complete" \
        '{node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
      [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
      class_overall=1
      overall=1
      continue
    fi

    log_file="${artifact_dir}/${pod}.log"
    if oc -n "${namespace}" logs "${pod}" | tee "${log_file}"; then
      result_json="$(tail -n 1 "${log_file}" | jq -c --arg node "${node}" --arg scc "${scc}" '. + {node:$node,admitted_scc:$scc}')"
      echo "${result_json}" >> "${summary}"
      status="$(jq -r '.overall' <<<"${result_json}")"
      echo "${status}: ${profile_class}: ${node}: ${expected_type}"
      if [[ "${status}" != "PASS" ]]; then
        class_overall=1
        overall=1
      fi
    else
      echo "FAIL: ${profile_class}: ${node}: could not read validation logs"
      jq -nc --arg node "${node}" --arg class "${profile_class}" --arg status "FAIL" --arg detail "could not read logs" \
        '{node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
      class_overall=1
      overall=1
    fi

    [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
  done

  if [[ "${class_overall}" -eq 0 ]]; then
    echo "${profile_class}_profile: passed"
  else
    echo "${profile_class}_profile: failed"
  fi
done

echo "Validation summary: ${summary}"
exit "${overall}"
