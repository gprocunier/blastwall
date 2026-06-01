POLICY := blastwall
SUPPORT_POLICIES := blastwall-sshd-login
DENY_POLICIES := blastwall-alg-socket-deny blastwall-bpf-deny blastwall-policy-selfprotect blastwall-packet-socket-deny blastwall-userns-deny blastwall-io-uring-deny blastwall-xfrm-deny blastwall-rxrpc-deny
VERSION := 0.5.2
SELINUX_DEVEL ?= /usr/share/selinux/devel

ROLE_CIL := blastwall-role.cil
SUPPORT_CIL := $(addsuffix .cil,$(SUPPORT_POLICIES))
DENY_CIL := $(addsuffix .cil,$(DENY_POLICIES))
ALL_CIL := $(ROLE_CIL) $(SUPPORT_CIL) $(DENY_CIL)
CONTEXT_FILE := contexts/blastwall_u
CONTEXT_DIR := /etc/selinux/targeted/contexts/users
SELINUX_MCS ?= s0

.PHONY: all clean install uninstall check

all: $(POLICY).pp

$(POLICY).pp: $(POLICY).te
	$(MAKE) -f $(SELINUX_DEVEL)/Makefile $(POLICY).pp

check:
	test -f "$(SELINUX_DEVEL)/Makefile"
	test -f "$(POLICY).te"
	@for f in $(ALL_CIL); do test -f "$$f" || { echo "missing $$f"; exit 1; }; done

install: $(POLICY).pp
	semodule -i $(POLICY).pp $(ALL_CIL)
	install -m 0644 $(CONTEXT_FILE) $(CONTEXT_DIR)/blastwall_u
	semanage user -a -R "blastwall_r" -r "$(SELINUX_MCS)" blastwall_u 2>/dev/null || \
		semanage user -m -R "blastwall_r" -r "$(SELINUX_MCS)" blastwall_u

uninstall:
	@for p in $(DENY_POLICIES); do semodule -r $$p 2>/dev/null || true; done
	@for p in $(SUPPORT_POLICIES); do semodule -r $$p 2>/dev/null || true; done
	-semodule -r blastwall-role
	-semodule -r $(POLICY)
	-semanage user -d blastwall_u 2>/dev/null
	-rm -f $(CONTEXT_DIR)/blastwall_u

clean:
	rm -f *.pp *.mod *.fc.tmp
	rm -rf tmp
