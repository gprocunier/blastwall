POLICY := blastwall
SUPPORT_POLICIES := blastwall-sshd-login
DENY_POLICIES := blastwall-alg-socket-deny blastwall-bpf-deny blastwall-policy-selfprotect blastwall-packet-socket-deny blastwall-userns-deny blastwall-io-uring-deny blastwall-xfrm-deny blastwall-rxrpc-deny
VERSION := 0.5.2
SELINUX_DEVEL ?= /usr/share/selinux/devel

SUPPORT_CIL := $(addsuffix .cil,$(SUPPORT_POLICIES))
DENY_CIL := $(addsuffix .cil,$(DENY_POLICIES))
ALL_CIL := $(SUPPORT_CIL) $(DENY_CIL)

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

uninstall:
	@for p in $(DENY_POLICIES); do semodule -r $$p 2>/dev/null || true; done
	@for p in $(SUPPORT_POLICIES); do semodule -r $$p 2>/dev/null || true; done
	-semodule -r $(POLICY)

clean:
	rm -f *.pp *.mod *.fc.tmp
	rm -rf tmp
