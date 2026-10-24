package imagehardening

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type toolOperationEvidence struct {
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

type toolRuntimeEvidence struct {
	Nonce             string                `json:"nonce"`
	UID               *int                  `json:"uid"`
	RuntimeSHA256     string                `json:"runtime_sha256"`
	ApplicationSHA256 string                `json:"application_sha256"`
	ProtectedWrite    toolOperationEvidence `json:"protected_root_write"`
	LocalToolInstall  toolOperationEvidence `json:"local_tool_install"`
}

type toolShellEvidence struct {
	Command []string `json:"command"`
	pentestCheck
}

type toolImageContainment struct {
	Image       string               `json:"image"`
	ImageID     string               `json:"image_id"`
	Application pentestCheck         `json:"application"`
	Shells      []toolShellEvidence  `json:"shells"`
	Runtime     *toolRuntimeEvidence `json:"runtime,omitempty"`
}

type toolContainmentReport struct {
	Scope                   string               `json:"scope"`
	Baseline                toolImageContainment `json:"baseline"`
	Candidate               toolImageContainment `json:"candidate"`
	Passed                  bool                 `json:"passed"`
	ImprovementDemonstrated bool                 `json:"improvement_demonstrated"`
	Improvements            []string             `json:"improvements"`
	Limitations             []string             `json:"limitations"`
}

// toolContainment supports the declared finite, offline Node workload at /app/app.js.
func toolContainment(ctx context.Context, baseline, candidate, user string) (toolContainmentReport, error) {
	report := toolContainmentReport{
		Scope:    "Offline Node workload: original image USER and ENTRYPOINT/CMD baseline versus a candidate with explicit runtime restrictions; no remote exploit",
		Baseline: toolImageContainment{Image: baseline}, Candidate: toolImageContainment{Image: candidate},
		Improvements: []string{},
		Limitations: []string{
			"Only the unchanged finite application workload and six listed shell paths are tested; workload coverage is declared, not inferred",
			"Both sides share no network, dropped capabilities, no-new-privileges and resource limits; this does not measure production deployment or network-policy improvements",
			"Docker daemon default seccomp/LSM settings apply; this comparator does not load or verify generated security profiles",
			"Denied root writes and local tool installation apply to protected root paths only; writable mounts and language runtimes may still execute code",
			"Local tool installation creates and executes a benign JavaScript file under /hardening-local-tool-*; package-manager absence is not a passing test",
			"Hash equality verifies /app/app.js and the executed Node binary, not every application dependency; no upgrades or application fixes are performed by these tests",
		},
	}
	for _, image := range []string{baseline, candidate} {
		if err := imageReference(image); err != nil {
			return report, err
		}
	}
	if _, err := hardenedArgs(candidate, user, "", "", nil); err != nil {
		return report, err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return report, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	for index, target := range []*toolImageContainment{&report.Baseline, &report.Candidate} {
		data, err := capture(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", "--", target.Image)
		if err != nil {
			return report, fmt.Errorf("cannot resolve local image %s: %w", target.Image, err)
		}
		target.ImageID = strings.TrimSpace(string(data))
		if !strings.HasPrefix(target.ImageID, "sha256:") || !toolDigest(target.ImageID[7:]) {
			return report, errors.New("Docker returned an invalid local image ID")
		}
		hardened := index == 1
		stdout, stderr, code, runErr := toolContainmentRun(ctx, target.ImageID, user, hardened, nil)
		target.Application = toolApplicationCheck(stdout, stderr, code, runErr)
		if target.Application.Status != "passed" {
			return report, fmt.Errorf("%s original ENTRYPOINT/CMD application check %s", target.Image, target.Application.Status)
		}
		for _, shell := range [][]string{{"/bin/sh"}, {"/bin/bash"}, {"/bin/ash"}, {"/usr/bin/sh"}, {"/busybox", "sh"}, {"/bin/busybox", "sh"}} {
			command := append(append([]string{}, shell...), "-c", "printf '%s' '"+nonce+"'")
			stdout, stderr, code, runErr = toolContainmentRun(ctx, target.ImageID, user, hardened, command)
			check := pentestClassifyShell(shell[0], nonce, stdout, stderr, code, runErr)
			target.Shells = append(target.Shells, toolShellEvidence{Command: shell, pentestCheck: check})
			if check.Status == "inconclusive" {
				return report, fmt.Errorf("%s shell probe %s is inconclusive", target.Image, shell[0])
			}
		}
		stdout, stderr, code, runErr = toolContainmentRun(ctx, target.ImageID, user, hardened, []string{"node", "-e", toolRuntimeScript(nonce)})
		if runErr != nil || code != 0 {
			return report, fmt.Errorf("%s Node runtime probe is inconclusive: %s", target.Image, pentestDetail(stdout, stderr, runErr))
		}
		var runtime toolRuntimeEvidence
		if err := json.Unmarshal(stdout, &runtime); err != nil || runtime.Nonce != nonce || runtime.UID == nil || *runtime.UID < 0 || !toolDigest(runtime.RuntimeSHA256) || !toolDigest(runtime.ApplicationSHA256) {
			return report, fmt.Errorf("%s runtime probe returned incomplete evidence", target.Image)
		}
		target.Runtime = &runtime
	}
	err := evaluateToolContainment(&report)
	return report, err
}

func evaluateToolContainment(report *toolContainmentReport) error {
	report.Passed, report.ImprovementDemonstrated = false, false
	report.Improvements = []string{}
	a, b := report.Baseline.Runtime, report.Candidate.Runtime
	if report.Baseline.Application.Status != "passed" || report.Candidate.Application.Status != "passed" || a == nil || b == nil || a.UID == nil || b.UID == nil {
		return errors.New("application or runtime evidence is incomplete")
	}
	if !toolDigest(a.RuntimeSHA256) || !toolDigest(a.ApplicationSHA256) || a.RuntimeSHA256 != b.RuntimeSHA256 || a.ApplicationSHA256 != b.ApplicationSHA256 {
		return errors.New("application or executed runtime bytes changed; the comparison cannot demonstrate hardening alone")
	}
	if *b.UID == 0 {
		return errors.New("candidate still executes as root")
	}
	for _, operation := range []struct {
		name              string
		baseline, current toolOperationEvidence
	}{{"protected_root_write", a.ProtectedWrite, b.ProtectedWrite}, {"local_tool_install", a.LocalToolInstall, b.LocalToolInstall}} {
		if !toolOperationKnown(operation.baseline) || !toolOperationKnown(operation.current) {
			return fmt.Errorf("%s result is inconclusive", operation.name)
		}
		if operation.current.Status != "denied" {
			return fmt.Errorf("candidate still allows %s", operation.name)
		}
		if operation.baseline.Status == "allowed" {
			report.Improvements = append(report.Improvements, operation.name+" newly denied")
		}
	}
	if len(report.Baseline.Shells) != 6 || len(report.Candidate.Shells) != 6 {
		return errors.New("shell evidence is incomplete")
	}
	for i, shell := range report.Candidate.Shells {
		before := report.Baseline.Shells[i]
		if strings.Join(shell.Command, "\x00") != strings.Join(before.Command, "\x00") || (before.Status != "accessible" && before.Status != "unavailable") || shell.Status != "unavailable" {
			return fmt.Errorf("candidate shell %s is accessible or evidence is inconclusive", strings.Join(shell.Command, " "))
		}
		if before.Status == "accessible" {
			report.Improvements = append(report.Improvements, strings.Join(shell.Command, " ")+" newly unavailable")
		}
	}
	if *a.UID == 0 {
		report.Improvements = append(report.Improvements, "execution changed from root to non-root")
	}
	report.Passed = true
	report.ImprovementDemonstrated = len(report.Improvements) > 0
	return nil
}

func toolOperationKnown(e toolOperationEvidence) bool {
	return e.Status == "allowed" || (e.Status == "denied" && (e.ErrorCode == "EROFS" || e.ErrorCode == "EACCES" || e.ErrorCode == "EPERM"))
}

func toolDigest(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func toolApplicationCheck(stdout, stderr []byte, code int, err error) pentestCheck {
	check := pentestCheck{Status: "passed", ExitCode: code, Evidence: "original image ENTRYPOINT/CMD exited successfully"}
	if err != nil || code >= 125 || code < 0 {
		check.Status = "inconclusive"
	} else if code != 0 {
		check.Status = "failed"
	}
	if check.Status != "passed" {
		check.Evidence = pentestDetail(stdout, stderr, err)
	}
	return check
}

func toolContainmentRunArgs(image, name, user string, hardened bool, command []string) ([]string, error) {
	var args []string
	if hardened {
		var err error
		args, err = hardenedArgs(image, user, "", "", nil)
		if err != nil {
			return nil, err
		}
	} else {
		args = []string{"--rm", "--pull=never", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--network=none", "--memory=512m", "--cpus=1", "--pids-limit=128", image}
	}
	prefix := []string{"run", "--name", name, "--label=container-hardening-work-bench.containment=true"}
	if len(command) > 0 {
		prefix = append(prefix, "--entrypoint="+command[0])
		args = append(args, command[1:]...)
	}
	return append(prefix, args...), nil
}

func toolContainmentRun(ctx context.Context, image, user string, hardened bool, command []string) ([]byte, []byte, int, error) {
	data := make([]byte, 12)
	if _, err := rand.Read(data); err != nil {
		return nil, nil, -1, err
	}
	name := "hardening-containment-" + hex.EncodeToString(data)
	args, err := toolContainmentRunArgs(image, name, user, hardened, command)
	if err != nil {
		return nil, nil, -1, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
	}()
	probe, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probe, "docker", args...)
	var stdout, stderr pentestOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if probe.Err() != nil {
		return stdout.Bytes(), stderr.Bytes(), -1, probe.Err()
	}
	if err == nil {
		return stdout.Bytes(), stderr.Bytes(), 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.Bytes(), stderr.Bytes(), exit.ExitCode(), nil
	}
	return stdout.Bytes(), stderr.Bytes(), -1, err
}

func toolRuntimeScript(nonce string) string {
	return `const fs = require('node:fs'), crypto = require('node:crypto'), cp = require('node:child_process');
const nonce = '` + nonce + `';
function operation(fn) { try { fn(); return {status:'allowed'}; } catch(e) { return {status:['EROFS','EACCES','EPERM'].includes(e.code)?'denied':'inconclusive',error_code:e.code||'UNKNOWN'}; } }
async function digest(file) { const h=crypto.createHash('sha256'); for await (const block of fs.createReadStream(file)) h.update(block); return h.digest('hex'); }
(async () => {
  const runtime_sha256 = await digest(process.execPath), application_sha256 = await digest('/app/app.js');
  const protected_root_write = operation(() => { const p='/hardening-write-'+nonce; fs.writeFileSync(p,nonce,{flag:'wx'}); fs.unlinkSync(p); });
  const local_tool_install = operation(() => {
    const dir='/hardening-local-tool-'+nonce, file=dir+'/tool.js'; let created=false;
    try { fs.mkdirSync(dir); created=true; fs.writeFileSync(file,'process.stdout.write('+JSON.stringify(nonce)+')',{flag:'wx',mode:0o755}); if(cp.execFileSync(process.execPath,[file],{encoding:'utf8',timeout:2000})!==nonce) throw new Error('local tool marker mismatch'); }
    finally { if(created) fs.rmSync(dir,{recursive:true,force:true}); }
  });
  process.stdout.write(JSON.stringify({nonce,uid:process.getuid(),runtime_sha256,application_sha256,protected_root_write,local_tool_install}));
})().catch(()=>{process.stderr.write('runtime evidence collection failed');process.exitCode=1;});`
}
