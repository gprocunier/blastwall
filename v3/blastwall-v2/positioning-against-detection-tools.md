# Positioning Against Detection Tools

Blastwall is a prevention layer for privileged automation. It is complementary to Falco, Tetragon, and similar runtime detection systems.

Blastwall's value is narrow and specific: under the confined automation identity, selected risky kernel interfaces are denied before the operation succeeds. Detection tools can alert after observing behavior; Blastwall prevents the operation under the scoped identity.

Blastwall is not a replacement for patching, EDR, seccomp, BPF LSM, gVisor, Kubernetes isolation, or runtime detection. It depends on trusted IdM, AAP, SSH, SSSD, PAM, SELinux enforcing mode, and reviewed sudo expansion.

Position the project as a RHEL/SELinux/IdM/AAP control for privileged automation, not as a general endpoint security platform.
