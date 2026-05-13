#!/usr/bin/env bash

demo_type_delay="${DEMO_TYPE_DELAY:-0.004}"
demo_command_delay="${DEMO_COMMAND_DELAY:-0.35}"
demo_section_delay="${DEMO_SECTION_DELAY:-0.45}"

demo_section() {
  local title="$1"
  printf '\n>>> %s\n\n' "${title}"
  sleep "${demo_section_delay}"
}

demo_type_line() {
  local line="$1"
  local i
  printf '$ '
  for ((i = 0; i < ${#line}; i++)); do
    printf '%s' "${line:i:1}"
    sleep "${demo_type_delay}"
  done
  printf '\n'
}

demo_run() {
  local command="$1"
  demo_type_line "${command}"
  eval "${command}"
  sleep "${demo_command_delay}"
}

demo_note() {
  printf '%s\n' "$1"
  sleep "${demo_command_delay}"
}
