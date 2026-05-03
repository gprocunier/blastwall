POLICY := blastwall
DENY_POLICIES := blastwall-alg-socket-deny blastwall-bpf-deny blastwall-policy-selfprotect blastwall-packet-socket-deny blastwall-userns-deny
VERSION := 0.4.0
SELINUX_DEVEL ?= /usr/share/selinux/devel

DENY_CIL := $(addsuffix .cil,$(DENY_POLICIES))

.PHONY: all clean install uninstall check

all: $(POLICY).pp

$(POLICY).pp: $(POLICY).te
	$(MAKE) -f $(SELINUX_DEVEL)/Makefile $(POLICY).pp

check:
	test -f "$(SELINUX_DEVEL)/Makefile"
	test -f "$(POLICY).te"
	@for f in $(DENY_CIL); do test -f "$$f" || { echo "missing $$f"; exit 1; }; done

install: $(POLICY).pp
	semodule -i $(POLICY).pp $(DENY_CIL)

uninstall:
	@for p in $(DENY_POLICIES); do semodule -r $$p 2>/dev/null || true; done
	-semodule -r $(POLICY)

clean:
	rm -f *.pp *.mod *.fc.tmp
	rm -rf tmp
