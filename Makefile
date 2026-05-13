PYTHON ?= python3
NPM ?= npm
SELINUX_DEVEL ?= /usr/share/selinux/devel

.PHONY: help test test-fast registry-check pytest test-policy test-openshift test-docs diff-check policy-check policy-build rpm

help:
	@printf '%s\n' \
		'Blastwall validation targets:' \
		'  make test-fast     Run registry, drift, Python, policy, OpenShift, and diff checks.' \
		'  make test          Run test-fast plus Playwright documentation rendering.' \
		'  make policy-check  Check local SELinux policy build prerequisites and policy source.' \
		'  make policy-build  Build policy/blastwall.pp with the local SELinux devel Makefile.' \
		'  make rpm           Explain the supported RHEL/AAP RPM build boundary.'

test-fast: registry-check pytest test-policy test-openshift diff-check

test: test-fast test-docs

registry-check:
	$(PYTHON) tools/validate_blastwall_profiles.py --registry policy/profiles.yml
	$(PYTHON) tools/check_blastwall_drift.py --registry policy/profiles.yml

pytest:
	$(PYTHON) -m pytest -q tests

test-policy:
	$(NPM) run test:policy

test-openshift:
	$(NPM) run test:openshift

test-docs:
	$(NPM) run test:docs

diff-check:
	@if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
		git diff --check; \
	else \
		printf '%s\n' "SKIP: git diff --check requires a Git checkout."; \
	fi

policy-check:
	@if [ ! -f "$(SELINUX_DEVEL)/Makefile" ]; then \
		printf '%s\n' \
			"ERROR: $(SELINUX_DEVEL)/Makefile is missing." \
			"Install selinux-policy-devel on this host, or run policy/RPM builds on the RHEL bastion/AAP build target."; \
		exit 2; \
	fi
	$(MAKE) -C policy check SELINUX_DEVEL="$(SELINUX_DEVEL)"

policy-build: policy-check
	$(MAKE) -C policy SELINUX_DEVEL="$(SELINUX_DEVEL)"

rpm:
	@printf '%s\n' \
		'ERROR: local RPM packaging is not a root Makefile contract.' \
		'Build release RPMs through playbooks/build-policy-rpm.yml on a RHEL-capable bastion/AAP target.' \
		'Example: BLASTWALL_POLICY_VERSION=0.6.1 BLASTWALL_POLICY_RELEASE=0.rc1 ansible-playbook playbooks/build-policy-rpm.yml'
	@exit 2
