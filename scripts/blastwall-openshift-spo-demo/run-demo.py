#!/usr/bin/env python3
import fcntl
import os
import pty
import select
import struct
import sys
import tempfile
import termios
import textwrap
import time


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
TYPE_DELAY = float(os.environ.get("TYPE_DELAY", "0.03"))
SHORT_PAUSE = float(os.environ.get("SHORT_PAUSE", "1.1"))
LONG_PAUSE = float(os.environ.get("LONG_PAUSE", "2.2"))
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", "900"))
DEMO_COLS = int(os.environ.get("DEMO_COLS", "220"))
DEMO_ROWS = int(os.environ.get("DEMO_ROWS", "42"))
OC_BIN = os.environ.get(
    "OC",
    "/opt/openshift/aws-metal-openshift-demo/generated/tools/4.20.15/bin/oc",
)
KUBECONFIG = os.environ.get("KUBECONFIG", os.path.expanduser("~/etc/kubeconfig.local"))
PROMPT_MARKER_TEXT = "\\033]6973;blastwall-spo-prompt\\007"
PROMPT_MARKER = b"\x1b]6973;blastwall-spo-prompt\x07"
PENDING_PROMPT = b""
PROMPT_VISIBLE = False


def write_stdout(text):
    sys.stdout.write(text)
    sys.stdout.flush()


def set_pty_size(fd):
    size = struct.pack("HHHH", DEMO_ROWS, DEMO_COLS, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, size)


def set_input_echo(fd, enabled):
    attrs = termios.tcgetattr(fd)
    previous = list(attrs)
    if enabled:
        attrs[3] |= termios.ECHO
    else:
        attrs[3] &= ~termios.ECHO
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    return previous


def restore_termios(fd, attrs):
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def write_child_command(fd, command):
    os.write(fd, command.replace("\n", "\r").encode() + b"\r")


def title(text):
    bar = "-" * len(text)
    write_stdout(f"\n{bar}\n{text}\n{bar}\n")
    time.sleep(SHORT_PAUSE)


def disclose(fd, text):
    write_stdout("\n\n>>>\n")
    for line in textwrap.wrap(text, width=88):
        write_stdout(f">>> {line}\n")
    write_stdout(">>>\n\n")
    time.sleep(SHORT_PAUSE)
    queue_fresh_prompt(fd)
    time.sleep(0.2)


def type_text(text):
    for ch in text:
        os.write(sys.stdout.fileno(), b"\r\n" if ch == "\n" else ch.encode())
        time.sleep(TYPE_DELAY)


def collect_until_prompt(fd, hard_timeout=30, quiet_after_marker=0.18, emit=False):
    deadline = time.time() + hard_timeout
    buffered = b""
    chunks = []
    marker_seen = False
    last_data = time.time()
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return None
            if not data:
                return None
            chunks.append(data)
            if emit:
                os.write(sys.stdout.fileno(), data)
            buffered = (buffered + data)[-4096:]
            last_data = time.time()
            if PROMPT_MARKER in buffered:
                marker_seen = True
        elif marker_seen and time.time() - last_data >= quiet_after_marker:
            return b"".join(chunks)
    return None


def read_until_prompt(fd, hard_timeout=30, emit=True):
    global PROMPT_VISIBLE
    data = collect_until_prompt(fd, hard_timeout=hard_timeout, emit=emit)
    if data is None:
        return False
    PROMPT_VISIBLE = emit
    return True


def queue_fresh_prompt(fd, hard_timeout=5):
    global PENDING_PROMPT, PROMPT_VISIBLE
    PENDING_PROMPT = b""
    os.write(fd, b"\r")
    data = collect_until_prompt(fd, hard_timeout=hard_timeout)
    if data is None:
        raise TimeoutError("timed out waiting for shell prompt after narration")
    PENDING_PROMPT = data
    PROMPT_VISIBLE = False


def ensure_visible_prompt(fd, hard_timeout=5):
    global PENDING_PROMPT, PROMPT_VISIBLE
    if PENDING_PROMPT:
        os.write(sys.stdout.fileno(), PENDING_PROMPT)
        PENDING_PROMPT = b""
        PROMPT_VISIBLE = True
        return
    if PROMPT_VISIBLE:
        return
    os.write(fd, b"\r")
    data = collect_until_prompt(fd, hard_timeout=hard_timeout)
    if data is None:
        raise TimeoutError("timed out waiting for visible shell prompt")
    os.write(sys.stdout.fileno(), data)
    PROMPT_VISIBLE = True


def run_hidden_cmd(fd, command, hard_timeout=30, pause_after=0.2):
    global PENDING_PROMPT, PROMPT_VISIBLE
    PENDING_PROMPT = b""
    PROMPT_VISIBLE = False
    previous = set_input_echo(fd, False)
    try:
        write_child_command(fd, command)
        if not read_until_prompt(fd, hard_timeout=hard_timeout, emit=False):
            raise TimeoutError(f"timed out waiting for shell prompt after hidden command: {command!r}")
    finally:
        restore_termios(fd, previous)
    time.sleep(pause_after)


def run_cmd(fd, display, hard_timeout=30, pause_after=None):
    ensure_visible_prompt(fd)
    type_text(display)
    write_stdout("\r\n")
    previous = set_input_echo(fd, False)
    try:
        write_child_command(fd, display)
        if not read_until_prompt(fd, hard_timeout=hard_timeout):
            raise TimeoutError(f"timed out waiting for shell prompt after: {display!r}")
    finally:
        restore_termios(fd, previous)
    time.sleep(SHORT_PAUSE if pause_after is None else pause_after)


def read_until_quiet(fd, quiet=0.8, hard_timeout=8):
    deadline = time.time() + hard_timeout
    last = time.time()
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            if not data:
                return
            os.write(sys.stdout.fileno(), data)
            last = time.time()
        elif time.time() - last >= quiet:
            return


def create_demo_bashrc():
    handle = tempfile.NamedTemporaryFile(
        "w",
        prefix="blastwall-spo-demo-bashrc-",
        delete=False,
        encoding="utf-8",
    )
    with handle:
        handle.write(
            f'''export TERM="${{TERM:-xterm-256color}}"

if [ -r "$HOME/.bashrc" ]; then
  . "$HOME/.bashrc"
fi

__blastwall_spo_prompt_marker() {{
  printf '{PROMPT_MARKER_TEXT}'
}}

if [ -n "${{PROMPT_COMMAND:-}}" ]; then
  PROMPT_COMMAND="${{PROMPT_COMMAND}}; __blastwall_spo_prompt_marker"
else
  PROMPT_COMMAND=__blastwall_spo_prompt_marker
fi
'''
        )
    return handle.name


def main():
    demo_bashrc = create_demo_bashrc()
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = os.environ.get("BLASTWALL_DEMO_TERM", "xterm-256color")
        os.environ["COLUMNS"] = str(DEMO_COLS)
        os.environ["LINES"] = str(DEMO_ROWS)
        os.chdir(os.environ.get("HOME", "/"))
        os.execvp("bash", ["bash", "--rcfile", demo_bashrc, "-i"])

    try:
        set_pty_size(fd)
        if not read_until_prompt(fd, hard_timeout=8, emit=False):
            raise TimeoutError("timed out waiting for initial shell prompt")
        run_hidden_cmd(fd, "stty -echo", hard_timeout=10)
        run_hidden_cmd(fd, "PS2=''", hard_timeout=10)
        run_hidden_cmd(fd, f"stty cols {DEMO_COLS} rows {DEMO_ROWS}", hard_timeout=10)
        run_hidden_cmd(fd, "set -euo pipefail", hard_timeout=10)
        run_hidden_cmd(fd, f"export PATH=\"{os.path.dirname(OC_BIN)}:$HOME/.local/bin:$PATH\"", hard_timeout=10)
        run_hidden_cmd(fd, f"export KUBECONFIG={KUBECONFIG}", hard_timeout=10)
        run_hidden_cmd(fd, f"cd {PROJECT_ROOT}", hard_timeout=10)
        run_hidden_cmd(
            fd,
            "oc -n blastwall-workloads delete deploy blastwall-demo blastwall-nested-demo "
            "--ignore-not-found --wait=true >/dev/null 2>&1 || true",
            hard_timeout=90,
        )

        title("blastwall OpenShift/SPO workload confinement with UBI probes")

        disclose(
            fd,
            "This recording starts from the bastion checkout. OpenShift is the workload "
            "target, Security Profiles Operator carries the SELinux policy, SCC admission "
            "selects the workload class, and UBI runs the safe probe harness.",
        )
        run_cmd(fd, "hostnamectl --static && oc whoami && oc version | sed -n '1,8p'", hard_timeout=30)

        disclose(
            fd,
            "First prove the SPO API is available. Blastwall uses RawSelinuxProfile here "
            "because the policy needs CIL deny and neverallow behavior.",
        )
        run_cmd(
            fd,
            "oc get crd rawselinuxprofiles.security-profiles-operator.x-k8s.io &&\n"
            "oc explain rawselinuxprofile.spec --api-version=security-profiles-operator.x-k8s.io/v1alpha2 | sed -n '1,34p'",
            hard_timeout=45,
        )

        disclose(
            fd,
            "Apply the OpenShift bundle. This installs the two SPO profiles, the SCCs, "
            "separate service accounts, RBAC bindings, the probe ConfigMap, and validation jobs.",
        )
        run_cmd(fd, "oc apply -k openshift/spo", hard_timeout=90)

        disclose(
            fd,
            "Wait for both workload profiles. Profile readiness proves SPO accepted and "
            "installed the raw policy. The runtime proof comes next from SCC admission and "
            "the pod SELinux context.",
        )
        run_cmd(
            fd,
            "oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwall --timeout=180s &&\n"
            "oc -n blastwall-spo wait --for=condition=ready rawselinuxprofile/blastwallnested --timeout=180s &&\n"
            "oc -n blastwall-spo get rawselinuxprofile \\\n"
            "  -o custom-columns=NAME:.metadata.name,STATUS:.status.status,USAGE:.status.usage",
            hard_timeout=240,
        )

        disclose(
            fd,
            "Now prove the admission boundary. Each service account can use only its own "
            "SCC, and the normal runner cannot borrow the nested exception. The SCCs use "
            "the validated runtime types shown by pod id -Z output in this lab.",
        )
        run_cmd(
            fd,
            "oc get scc blastwall-confined blastwall-nested \\\n"
            "  -o custom-columns=NAME:.metadata.name,TYPE:.seLinuxContext.seLinuxOptions.type,USERNS:.userNamespaceLevel,PRIV:.allowPrivilegedContainer &&\n"
            "oc auth can-i use scc/blastwall-confined \\\n"
            "  --as system:serviceaccount:blastwall-workloads:blastwall-runner \\\n"
            "  -n blastwall-workloads 2>/dev/null &&\n"
            "oc auth can-i use scc/blastwall-nested \\\n"
            "  --as system:serviceaccount:blastwall-workloads:blastwall-nested-runner \\\n"
            "  -n blastwall-workloads 2>/dev/null &&\n"
            "(oc auth can-i use scc/blastwall-nested \\\n"
            "  --as system:serviceaccount:blastwall-workloads:blastwall-runner \\\n"
            "  -n blastwall-workloads 2>/dev/null || true)",
            hard_timeout=60,
        )

        disclose(
            fd,
            "Launch the example UBI workloads. The nested workload sets hostUsers=false; "
            "the standard workload does not need pod-level user namespace behavior.",
        )
        run_cmd(
            fd,
            "oc apply -f openshift/spo/examples/blastwall-protected-deployment.yaml &&\n"
            "oc apply -f openshift/spo/examples/blastwall-nested-deployment.yaml &&\n"
            "oc -n blastwall-workloads rollout status deploy/blastwall-demo --timeout=180s &&\n"
            "oc -n blastwall-workloads rollout status deploy/blastwall-nested-demo --timeout=180s",
            hard_timeout=300,
        )

        disclose(
            fd,
            "Read the pod evidence. The important output is the selected SCC, the "
            "OpenShift SELinux type, and the nested uid/gid map evidence.",
        )
        run_cmd(
            fd,
            "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-demo -o wide &&\n"
            "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-nested-demo -o wide &&\n"
            "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-demo \\\n"
            "  -o jsonpath='{range .items[*]}{.metadata.name}{\" scc=\"}{.metadata.annotations.openshift\\.io/scc}{\"\\n\"}{end}' &&\n"
            "oc -n blastwall-workloads get pods -l app.kubernetes.io/name=blastwall-nested-demo \\\n"
            "  -o jsonpath='{range .items[*]}{.metadata.name}{\" scc=\"}{.metadata.annotations.openshift\\.io/scc}{\" hostUsers=\"}{.spec.hostUsers}{\"\\n\"}{end}' &&\n"
            "oc -n blastwall-workloads exec deploy/blastwall-demo -- \\\n"
            "  sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current' &&\n"
            "oc -n blastwall-workloads exec deploy/blastwall-nested-demo -- \\\n"
            "  sh -c 'id -Z 2>/dev/null || cat /proc/self/attr/current; cat /proc/self/uid_map; cat /proc/self/gid_map'",
            hard_timeout=90,
        )

        disclose(
            fd,
            "Run the safe UBI probe harness across the node set. The strongest proof is the "
            "combination of SPO readiness, SCC admission, pod SELinux context, and blocked "
            "or skipped safe entry-point probes from the confined domain.",
        )
        run_cmd(
            fd,
            "openshift/spo/scripts/validate-blastwall-spo-nodes.sh --class both --all",
            hard_timeout=COMMAND_TIMEOUT,
        )

        disclose(
            fd,
            "The OpenShift path is not the RHEL IdM login-domain path. It confines selected "
            "pods as OpenShift workloads with MCS categories, while keeping the high-risk "
            "kernel surfaces denied for both standard and nested classes.",
        )
        time.sleep(LONG_PAUSE)
        os.write(fd, b"exit\r")
        read_until_quiet(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(demo_bashrc)
        except OSError:
            pass


if __name__ == "__main__":
    main()
