package hardening

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

//go:embed assets/moby-seccomp.json
var mobyProfile []byte

const ProfileSource = "https://github.com/moby/profiles/blob/4b8214fc4971e06172938a1f1554ccff6647ee80/seccomp/default.json"

var forbiddenCalls = strings.Fields("ptrace process_vm_readv process_vm_writev pidfd_getfd kcmp bpf perf_event_open mount umount umount2 pivot_root chroot unshare setns fsopen fsconfig fsmount fspick move_mount open_tree mount_setattr io_uring_setup io_uring_enter io_uring_register keyctl add_key request_key userfaultfd open_by_handle_at init_module finit_module delete_module kexec_load kexec_file_load reboot swapon swapoff socketcall execveat")

type condition struct {
	Caps   []string `json:"caps"`
	Arches []string `json:"arches"`
}
type syscallRule struct {
	Names    []string          `json:"names"`
	Action   string            `json:"action"`
	Args     []json.RawMessage `json:"args,omitempty"`
	ErrnoRet *uint             `json:"errnoRet,omitempty"`
	Includes *condition        `json:"includes,omitempty"`
	Excludes *condition        `json:"excludes,omitempty"`
}

// Seccomp resolves Docker-specific conditions into an OCI profile for a
// cap-drop-ALL workload. User-supplied syscall lists can only narrow this policy.
func Seccomp(c Config) ([]byte, error) {
	var base struct {
		Syscalls []syscallRule `json:"syscalls"`
	}
	if err := json.Unmarshal(mobyProfile, &base); err != nil {
		return nil, err
	}
	arch := strings.TrimPrefix(c.Platform, "linux/")
	native := "SCMP_ARCH_X86_64"
	if arch == "arm64" {
		native = "SCMP_ARCH_AARCH64"
	}
	var rules []syscallRule
	seen := map[string]bool{}
	for _, r := range base.Syscalls {
		if r.Includes != nil && (len(r.Includes.Caps) > 0 || (len(r.Includes.Arches) > 0 && !slices.Contains(r.Includes.Arches, arch))) {
			continue
		}
		if r.Excludes != nil && slices.Contains(r.Excludes.Arches, arch) {
			continue
		}
		r.Includes = nil
		r.Excludes = nil
		var names []string
		for _, n := range r.Names {
			if slices.Contains(forbiddenCalls, n) {
				continue
			}
			// Preserve ENOSYS fallbacks (notably clone3) even in a narrowed profile.
			if r.Action == "SCMP_ACT_ALLOW" && len(c.Syscalls) > 0 && !slices.Contains(c.Syscalls, n) {
				continue
			}
			names = append(names, n)
			seen[n] = true
		}
		if len(names) > 0 {
			r.Names = names
			rules = append(rules, r)
		}
	}
	for _, n := range c.Syscalls {
		if !seen[n] {
			return nil, fmt.Errorf("syscall %q is unsupported or forbidden by the baseline", n)
		}
	}
	return json.MarshalIndent(map[string]any{"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1, "architectures": []string{native}, "syscalls": rules}, "", "  ")
}
