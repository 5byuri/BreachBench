package imagehardening

import (
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenericProbeArchitectureMappings(t *testing.T) {
	for _, tc := range []struct{ in, arch, arm string }{{"linux/amd64", "amd64", ""}, {"arm64", "arm64", ""}, {"arm64/v8", "arm64", ""}, {"arm/v7", "arm", "7"}, {"linux/arm/v7", "arm", "7"}, {"armv6l", "arm", "6"}, {"riscv64", "riscv64", ""}} {
		a, b, _, err := genericProbeTarget(tc.in)
		if err != nil || a != tc.arch || b != tc.arm {
			t.Fatalf("%s -> %s/%s %v", tc.in, a, b, err)
		}
	}
	for _, arch := range []string{"", "../../amd64", "amd64;echo", "windows/amd64", "wasm"} {
		if _, _, _, err := genericProbeTarget(arch); err == nil {
			t.Fatalf("accepted architecture %q", arch)
		}
	}
}

func TestGenericProbeHasOnlyItsReadOnlyHostMount(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	for _, hardened := range []bool{false, true} {
		args, err := genericProbeRunArgs("app:local", "/private/tmp/containment-probe-amd64", "owned-name", "1000:0", nonce, hardened, []string{"/run/app"})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		for _, required := range []string{"--pull=never", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--entrypoint=/.hardening-probe", "target=/.hardening-probe,readonly", "app:local --nonce " + nonce} {
			if !strings.Contains(joined, required) {
				t.Errorf("missing %s", required)
			}
		}
		mounts := 0
		for _, arg := range args {
			if strings.HasPrefix(arg, "--mount=") {
				mounts++
			}
		}
		if mounts != 1 || strings.Contains(joined, "--privileged") || strings.Contains(joined, "docker.sock") {
			t.Fatal("host resources exposed")
		}
		if strings.Contains(joined, "--user") != hardened || strings.Contains(joined, "--read-only") != hardened {
			t.Fatal("original baseline USER changed or candidate policy missing")
		}
		if hardened && !strings.Contains(joined, "--tmpfs=/run/app:rw,noexec,nosuid,nodev") {
			t.Fatal("declared writable exception missing")
		}
	}
}

func TestGenericProbeRejectsMountAndUserInjection(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	for _, directory := range []string{"/", "relative", "/tmp/../etc", "/tmp,x", "/tmp:rw", "/proc", "/dev/shm", "/.hardening-probe"} {
		if _, err := genericProbeRunArgs("image", "/private/tmp/containment-probe-amd64", "owned", "1000:1000", nonce, true, []string{directory}); err == nil {
			t.Fatalf("accepted writable path %q", directory)
		}
	}
	for _, user := range []string{"0:0", "root", "1000:group", "4294967296:1"} {
		if _, err := genericProbeRunArgs("image", "/private/tmp/containment-probe-amd64", "owned", user, nonce, true, nil); err == nil {
			t.Fatalf("accepted user %q", user)
		}
	}
	if _, err := genericProbeRunArgs("image", "/tmp/file,target=/secret", "owned", "1000:1000", nonce, true, nil); err == nil {
		t.Fatal("accepted mount source injection")
	}
}

func TestGenericProbeCompilerForcesOfflineStaticBuild(t *testing.T) {
	env := genericProbeBuildEnvironment([]string{"GOFLAGS=-toolexec=bad", "CGO_ENABLED=1", "GOOS=darwin", "GEMINI_API_KEY=unused-test-key", "GOOGLE_API_KEY=unused-test-key", "UNRELATED=value"}, "arm", "7")
	joined := strings.Join(env, "\n")
	for _, required := range []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm", "GOARM=7", "GOPROXY=off", "GOTOOLCHAIN=local", "GOENV=off", "UNRELATED=value"} {
		if !strings.Contains(joined, required) {
			t.Errorf("missing %s", required)
		}
	}
	if strings.Contains(joined, "-toolexec") {
		t.Fatal("inherited Go flags not cleared")
	}
	if strings.Contains(joined, "GEMINI_API_KEY=") || strings.Contains(joined, "GOOGLE_API_KEY=") || strings.Contains(joined, "unused-test-key") {
		t.Fatal("provider credentials forwarded to the public static helper compiler")
	}
}

func TestBuildGenericProbeProducesStaticLinuxArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles embedded standard-library helper")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := buildGenericProbe(context.Background(), "amd64", dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("probe must be executable by an image's original numeric USER: %v %v", info, err)
	}
	f, err := elf.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Machine != elf.EM_X86_64 {
		t.Fatal("probe is not Linux amd64 ELF")
	}
	for _, program := range f.Progs {
		if program.Type == elf.PT_INTERP {
			t.Fatal("probe requires an image dynamic linker")
		}
	}
	if !strings.HasPrefix(filepath.Base(file), "containment-probe-") {
		t.Fatal("unexpected probe artifact name")
	}
	if _, err := buildGenericProbe(context.Background(), "amd64", dir); err == nil {
		t.Fatal("overwrote existing helper artifact")
	}
}
