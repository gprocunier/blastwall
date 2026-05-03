# Calabi Blastwall Lab Exercise

This directory is the public lab exercise that matches the recorded Blastwall
demo. It assumes a [`Calabi`](https://gprocunier.github.io/calabi/) style lab:
a controlled nested-KVM environment with IdM, a bastion host, a mirror registry,
Kerberos, and managed RHEL endpoints close enough to real operations that the
result is worth testing.

Calabi is my lab project, not a Blastwall dependency. If you already have an
IdM-enrolled RHEL environment with the same service boundaries, the important
parts are the roles and flow: run from a bastion-like control point, configure
IdM, validate state through `eigenstate.ipa`, deploy the policy RPM to the
managed endpoint, and prove the SELinux denials from the mapped automation
identity.

It uses [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) as
the read-side gate.  The FreeIPA modules and the `ipa` CLI create IdM state,
then [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) queries
that state before
the policy is deployed to the target.  The goal is to prove the primitive:

1. configure IdM on `idm-01`;
2. verify the IdM view with [`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/);
3. build a `blastwall-selinux` RPM on `bastion-01`;
4. install that RPM on the automation endpoint;
5. SSH as an IdM automation user mapped to `blastwall_u`;
6. prove that the Copy Fail AF_ALG/authencesn path and BPF entry points return permission denied;
7. temporarily expose `/usr/sbin/semodule` through sudo and prove SELinux still blocks policy manipulation;
8. show matching SELinux audit evidence from the target host.

## Execution Boundary

Run these playbooks on `bastion-01`, not directly from the workstation.

From the workstation, use the existing Calabi bastion staging flow to copy this
directory under `/opt/openshift/aws-metal-openshift-demo/blastwall/poc-calabi`
or another bastion-local path.  The playbooks assume they are run from this
directory on the bastion.

## Inputs

Set the IdM admin password through the environment or an extra var:

```bash
export IPA_ADMIN_PASSWORD='...'
```

Optional overrides:

```bash
export BLASTWALL_AUTO_PASSWORD='...'
export BLASTWALL_LAB_SSH_KEY='/path/to/lab/private-key'
```

The `svc-ansible-runner` proof path uses Kerberos/GSSAPI. If
`BLASTWALL_AUTO_PASSWORD` is not set, the PoC uses `IPA_ADMIN_PASSWORD` as the
lab service-account password and stores the service TGT in a local ccache under
`/var/tmp/blastwall-poc/` during validation.

`BLASTWALL_LAB_SSH_KEY` is only needed when your lab inventory requires an SSH
private key for bootstrap access. The GSSAPI proof path still uses Kerberos for
the automation identity.

Install the required collections on bastion:

```bash
ansible-galaxy collection install -r requirements.yml -p ./collections
```

For this PoC, use an
[`eigenstate.ipa`](https://gprocunier.github.io/eigenstate-ipa/) version that
includes the `selinuxmap`, `hbacrule`, `sudo`, and `idm` inventory plugins.

## Run

```bash
ansible-playbook 00-preflight.yml
ansible-playbook 10-configure-idm.yml
ansible-playbook 15-validate-idm-with-eigenstate.yml
ansible-playbook 20-build-policy-rpm.yml
ansible-playbook 30-deploy-and-test.yml
ansible-playbook 35-test-self-protection.yml
```

Cleanup, when needed:

```bash
ansible-playbook 99-cleanup.yml
```

## Expected Result

The final playbook should show:

- `svc-ansible-runner` can SSH to the automation endpoint with GSSAPI;
- `id -Z` returns `blastwall_u:blastwall_r:blastwall_t:s0` or the
  `blastwall_root_local_t` alias;
- `sudo -n /usr/bin/id -u` returns `0`;
- `sudo -n /usr/bin/id -Z` remains in the Blastwall SELinux role/type;
- the AF_ALG/authencesn probe prints `BLOCKED`;
- the BPF probe prints `BLOCKED` for `BPF_MAP_CREATE` and `BPF_PROG_LOAD`;
- the self-protection play temporarily adds `/usr/sbin/semodule` to sudo, then receives `Permission denied` from SELinux rather than a sudo policy rejection;
- a target-side `grep` shows SELinux syscall and AVC denial evidence for `blastwall_t`.

This proves the Blastwall pattern as an IdM-mapped SELinux user plus a
versioned policy RPM.  It does not try to replace Anthony Green's
`block-copyfail` BPF LSM precision path.
