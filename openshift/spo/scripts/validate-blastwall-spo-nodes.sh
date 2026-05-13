#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --all
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --role worker
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class standard --role worker
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class standard-strange --role worker
  openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class nested --selector 'node-role.kubernetes.io/worker='

Options:
  --class NAME           standard, nested, standard-strange, nested-strange, strange, or both. Default: both.
  --keep                 Keep validation pods for troubleshooting.
  --namespace NAME       Workload namespace. Default: blastwall-workloads.
  --profile-namespace N  SPO profile namespace. Default: blastwall-spo.
  --image IMAGE          UBI Python image to run. Default: BLASTWALL_SPO_TEST_IMAGE or ubi9/python-312.
  --usage-mode MODE      SPO usage->SCC mode: calabi-ocp420-rawprofile-underscore or status-usage-direct.
                        Default: BLASTWALL_SPO_SELINUX_TYPE_RESOLUTION_MODE or calabi-ocp420-rawprofile-underscore.
USAGE
}

namespace="blastwall-workloads"
profile_namespace="blastwall-spo"
image="${BLASTWALL_SPO_TEST_IMAGE:-registry.access.redhat.com/ubi9/python-312:latest}"
usage_mode="${BLASTWALL_SPO_SELINUX_TYPE_RESOLUTION_MODE:-calabi-ocp420-rawprofile-underscore}"
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
        standard|nested|standard-strange|nested-strange|strange|both) class_filter="$2" ;;
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
    --usage-mode)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case "$2" in
        calabi-ocp420-rawprofile-underscore|status-usage-direct)
          usage_mode="$2"
          ;;
        *)
          echo "Unknown usage mode: $2" >&2
          usage
          exit 2
          ;;
      esac
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

include_strange="false"
case "${class_filter}" in
  standard-strange|nested-strange|strange) include_strange="true" ;;
esac

command -v oc >/dev/null
command -v jq >/dev/null

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
artifact_dir="${repo_root}/artifacts/openshift-spo"
mkdir -p "${artifact_dir}"

get_spo_selinux_usage() {
  local profile_kind="$1"
  local namespace="$2"
  local name="$3"
  oc -n "${namespace}" get "${profile_kind}/${name}" -o jsonpath='{.status.usage}'
}

derive_selinux_type() {
  local usage="$1"
  if [[ "${usage_mode}" == "status-usage-direct" ]]; then
    printf '%s' "${usage}"
    return
  fi
  case "${usage}" in
    *_.process) printf '%s' "${usage}" ;;
    *.process) printf '%s_.process' "${usage%.process}" ;;
    *) printf '%s' "${usage}" ;;
  esac
}

patch_scc_usage() {
  local scc="$1"
  local selinux_type="$2"
  oc patch scc "${scc}" --type=merge \
    -p "$(jq -nc --arg selinux_type "${selinux_type}" '{seLinuxContext:{type:"MustRunAs",seLinuxOptions:{type:$selinux_type}}}')" >/dev/null
}

if [[ "${include_strange}" == "true" ]]; then
  oc -n "${namespace}" delete job \
    blastwall-strange-spo-validation \
    blastwall-nested-strange-spo-validation \
    --ignore-not-found=true >/dev/null
  oc apply -k "${repo_root}/openshift/spo-overlays/strange-socket-v1" >/dev/null
else
  oc apply -k "${repo_root}/openshift/spo" >/dev/null
fi
oc -n "${profile_namespace}" wait --for=condition=ready rawselinuxprofile/blastwall --timeout=180s >/dev/null
oc -n "${profile_namespace}" wait --for=condition=ready rawselinuxprofile/blastwallnested --timeout=180s >/dev/null
if [[ "${include_strange}" == "true" ]]; then
  oc -n "${profile_namespace}" wait --for=condition=ready rawselinuxprofile/blastwallstrange --timeout=180s >/dev/null
  oc -n "${profile_namespace}" wait --for=condition=ready rawselinuxprofile/blastwallnestedstrange --timeout=180s >/dev/null
fi

echo "SPO usage mode: ${usage_mode}"

standard_usage="${BLASTWALL_SPO_STANDARD_TYPE:-$(get_spo_selinux_usage rawselinuxprofile "${profile_namespace}" blastwall)}"
nested_usage="${BLASTWALL_SPO_NESTED_TYPE:-$(get_spo_selinux_usage rawselinuxprofile "${profile_namespace}" blastwallnested)}"
strange_usage="${BLASTWALL_SPO_STRANGE_TYPE:-}"
nested_strange_usage="${BLASTWALL_SPO_NESTED_STRANGE_TYPE:-}"
if [[ "${include_strange}" == "true" ]]; then
  if [[ -z "${strange_usage}" ]]; then
    strange_usage="$(get_spo_selinux_usage rawselinuxprofile "${profile_namespace}" blastwallstrange)"
  fi
  if [[ -z "${nested_strange_usage}" ]]; then
    nested_strange_usage="$(get_spo_selinux_usage rawselinuxprofile "${profile_namespace}" blastwallnestedstrange)"
  fi
fi
if [[ -z "${standard_usage}" || -z "${nested_usage}" ]]; then
  echo "FAIL: OpenShift/SPO profiles did not expose status.usage" >&2
  exit 1
fi
if [[ "${include_strange}" == "true" && ( -z "${strange_usage}" || -z "${nested_strange_usage}" ) ]]; then
  echo "FAIL: OpenShift/SPO strange profiles did not expose status.usage" >&2
  exit 1
fi
standard_selinux_type="$(derive_selinux_type "${standard_usage}")"
nested_selinux_type="$(derive_selinux_type "${nested_usage}")"
patch_scc_usage blastwall-confined "${standard_selinux_type}"
patch_scc_usage blastwall-nested "${nested_selinux_type}"
if [[ "${include_strange}" == "true" ]]; then
  strange_selinux_type="$(derive_selinux_type "${strange_usage}")"
  nested_strange_selinux_type="$(derive_selinux_type "${nested_strange_usage}")"
  patch_scc_usage blastwall-strange "${strange_selinux_type}"
  patch_scc_usage blastwall-nested-strange "${nested_strange_selinux_type}"
fi

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
  standard-strange) classes=(standard-strange) ;;
  nested-strange) classes=(nested-strange) ;;
  strange) classes=(standard-strange nested-strange) ;;
  both) classes=(standard nested) ;;
esac

summary="${artifact_dir}/spo-node-validation.jsonl"
: > "${summary}"
jq -nc --arg mode "${usage_mode}" '{mode:$mode}' >> "${summary}"
overall=0

for profile_class in "${classes[@]}"; do
  class_overall=0
  case "${profile_class}" in
    standard)
      scc="blastwall-confined"
      service_account="blastwall-runner"
      expected_type="${standard_selinux_type}"
      pod_prefix="blastwall-spo"
      host_users_line=""
      strange_env=""
      ;;
    nested)
      scc="blastwall-nested"
      service_account="blastwall-nested-runner"
      expected_type="${nested_selinux_type}"
      pod_prefix="blastwall-nested-spo"
      host_users_line="  hostUsers: false"
      strange_env=""
      ;;
    standard-strange)
      scc="blastwall-strange"
      service_account="blastwall-strange-runner"
      expected_type="${strange_selinux_type}"
      pod_prefix="blastwall-strange-spo"
      host_users_line=""
      strange_env="        - name: BLASTWALL_STRANGE_SOCKET_V1
          value: \"true\""
      ;;
    nested-strange)
      scc="blastwall-nested-strange"
      service_account="blastwall-nested-strange-runner"
      expected_type="${nested_strange_selinux_type}"
      pod_prefix="blastwall-nested-strange-spo"
      host_users_line="  hostUsers: false"
      strange_env="        - name: BLASTWALL_STRANGE_SOCKET_V1
          value: \"true\""
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
${strange_env}
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
        --arg mode "${usage_mode}" '{mode:$mode,node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
      class_overall=1
      overall=1
      [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
      continue
    fi

    if [[ "${profile_class}" == "nested" || "${profile_class}" == "nested-strange" ]]; then
      host_users="$(oc -n "${namespace}" get pod "${pod}" -o jsonpath='{.spec.hostUsers}' 2>/dev/null || true)"
      if [[ "${host_users}" != "false" ]]; then
        echo "FAIL: nested: ${node}: spec.hostUsers is '${host_users:-missing}', expected false"
        jq -nc --arg node "${node}" --arg class "${profile_class}" --arg status "FAIL" --arg detail "hostUsers is not false" \
          --arg mode "${usage_mode}" '{mode:$mode,node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
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
        --arg mode "${usage_mode}" '{mode:$mode,node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
      [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
      class_overall=1
      overall=1
      continue
    fi

    log_file="${artifact_dir}/${pod}.log"
    if oc -n "${namespace}" logs "${pod}" | tee "${log_file}"; then
      result_line="$(awk '/^\{.*\}$/ { line=$0 } END { print line }' "${log_file}")"
      if [[ -z "${result_line}" ]]; then
        echo "FAIL: ${profile_class}: ${node}: validation log did not contain JSON result"
        jq -nc --arg node "${node}" --arg class "${profile_class}" --arg status "FAIL" --arg detail "missing JSON result" \
          --arg mode "${usage_mode}" '{mode:$mode,node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
        class_overall=1
        overall=1
        [[ "${keep}" == "true" ]] || oc -n "${namespace}" delete pod "${pod}" --ignore-not-found --wait=false >/dev/null
        continue
      fi
      result_json="$(jq -c --arg mode "${usage_mode}" --arg node "${node}" --arg scc "${scc}" '. + {mode:$mode,node:$node,admitted_scc:$scc}' <<<"${result_line}")"
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
        --arg mode "${usage_mode}" '{mode:$mode,node:$node,profile_class:$class,status:$status,detail:$detail}' >> "${summary}"
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
