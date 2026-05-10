#!/usr/bin/env bash
set -euo pipefail

command -v asciinema >/dev/null

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "${REPO_ROOT}"

asciinema rec --overwrite \
  --title "blastwall OpenShift/SPO standard and nested workload classes" \
  docs/blastwall-openshift-spo.cast \
  --command scripts/blastwall-openshift-spo-demo/run-demo.sh
