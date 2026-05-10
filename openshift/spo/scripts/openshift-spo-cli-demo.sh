#!/usr/bin/env bash
set -euo pipefail

command -v oc >/dev/null

echo "Blastwall OpenShift/SPO demo"
echo "1. Verify SPO RawSelinuxProfile schema"
oc explain rawselinuxprofile.spec --api-version=security-profiles-operator.x-k8s.io/v1alpha2

echo
echo "2. Apply the Blastwall SPO profile, SCC, RBAC, and validation harness"
oc apply -k openshift/spo

echo
echo "3. Wait for both profiles and inspect usage strings"
oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwall --timeout=180s
oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwallnested --timeout=180s
oc -n blastwall-spo get rawselinuxprofile blastwall -o jsonpath='standard={.status.usage}{"\n"}'
oc -n blastwall-spo get rawselinuxprofile blastwallnested -o jsonpath='nested={.status.usage}{"\n"}'

echo
echo "4. Confirm SCC and service account binding"
oc get scc blastwall-confined -o jsonpath='{.seLinuxContext.seLinuxOptions.type}{"\n"}'
oc get scc blastwall-nested -o jsonpath='{.seLinuxContext.seLinuxOptions.type}{" userNamespaceLevel="}{.userNamespaceLevel}{"\n"}'
oc auth can-i use scc/blastwall-confined \
  --as system:serviceaccount:blastwall-workloads:blastwall-runner \
  -n blastwall-workloads 2>/dev/null
oc auth can-i use scc/blastwall-nested \
  --as system:serviceaccount:blastwall-workloads:blastwall-nested-runner \
  -n blastwall-workloads 2>/dev/null
oc auth can-i use scc/blastwall-nested \
  --as system:serviceaccount:blastwall-workloads:blastwall-runner \
  -n blastwall-workloads 2>/dev/null

echo
echo "5. Run standard and nested example workloads under required SCCs"
oc apply -f openshift/spo/examples/blastwall-protected-deployment.yaml
oc apply -f openshift/spo/examples/blastwall-nested-deployment.yaml
oc -n blastwall-workloads rollout status deploy/blastwall-demo --timeout=180s
oc -n blastwall-workloads rollout status deploy/blastwall-nested-demo --timeout=180s
oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-demo -o wide
oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-nested-demo -o wide
oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-demo \
  -o jsonpath='{range .items[*]}{.metadata.name}{" scc="}{.metadata.annotations.openshift\.io/scc}{"\n"}{end}'
oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-nested-demo \
  -o jsonpath='{range .items[*]}{.metadata.name}{" scc="}{.metadata.annotations.openshift\.io/scc}{" hostUsers="}{.spec.hostUsers}{"\n"}{end}'
oc -n blastwall-workloads exec deploy/blastwall-demo -- sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current'
oc -n blastwall-workloads exec deploy/blastwall-nested-demo -- sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current; cat /proc/self/uid_map; cat /proc/self/gid_map'

echo
echo "6. Run safe node validation probes"
openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class both --all
