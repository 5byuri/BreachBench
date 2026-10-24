// This standalone standard-library program is embedded and cross-compiled by the CLI.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type operation struct {
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	Stage     string `json:"stage,omitempty"`
}

type writeEvidence struct {
	Path string `json:"path"`
	operation
}

type shellEvidence struct {
	Command   []string `json:"command"`
	Status    string   `json:"status"`
	ExitCode  int      `json:"exit_code"`
	ErrorCode string   `json:"error_code,omitempty"`
}

type evidence struct {
	Version          string          `json:"version"`
	Nonce            string          `json:"nonce"`
	UID              uint32          `json:"uid"`
	GID              uint32          `json:"gid"`
	ProtectedWrites  []writeEvidence `json:"protected_writes"`
	LocalToolInstall operation       `json:"local_tool_install"`
	Shells           []shellEvidence `json:"shells"`
	WritablePaths    []writeEvidence `json:"writable_paths"`
	EgressTested     bool            `json:"egress_tested"`
	Scope            string          `json:"scope"`
}

type paths []string

func (p *paths) String() string         { return strings.Join(*p, ",") }
func (p *paths) Set(value string) error { *p = append(*p, value); return nil }

func validNonce(value string) bool {
	return len(value) == 32 && strings.Trim(value, "0123456789abcdef") == ""
}

func main() {
	marker := flag.String("marker", "", "Print a fixed local marker")
	nonce := flag.String("nonce", "", "Expected random measurement nonce")
	httpJSON := flag.String("http-checks-json", "", "Fixed HTTP assertions against the supplied loopback port")
	port := flag.Int("port", 0, "Local application port")
	timeout := flag.Int("timeout-seconds", 30, "HTTP startup and assertion deadline, at most 120 seconds")
	canonicalJSON := flag.String("canonical-writable-paths-json", "", "Resolve declared writable paths in the original image")
	var writable paths
	flag.Var(&writable, "writable-path", "Declared writable directory to measure")
	flag.Parse()
	if *httpJSON != "" {
		if flag.NArg() != 0 || *canonicalJSON != "" || *marker != "" || *nonce != "" || len(writable) != 0 {
			fmt.Fprintln(os.Stderr, "invalid HTTP probe arguments")
			os.Exit(2)
		}
		passed, err := checkHTTP(*httpJSON, *port, *timeout, os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid HTTP workload specification")
			os.Exit(2)
		}
		if !passed {
			os.Exit(1)
		}
		return
	}
	if *canonicalJSON != "" {
		if flag.NArg() != 0 || *marker != "" || *nonce != "" || len(writable) != 0 {
			fmt.Fprintln(os.Stderr, "invalid path probe arguments")
			os.Exit(2)
		}
		resolved, err := canonicalPaths(*canonicalJSON)
		if err != nil {
			fmt.Fprintln(os.Stderr, "writable path is invalid, inaccessible, or overlaps a protected tree")
			os.Exit(2)
		}
		if json.NewEncoder(os.Stdout).Encode(struct {
			Version string   `json:"version"`
			Paths   []string `json:"paths"`
		}{"generic-paths-v1", resolved}) != nil {
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 0 || (*marker != "" && !validNonce(*marker)) || (*marker == "" && !validNonce(*nonce)) || len(writable) > 17 {
		fmt.Fprintln(os.Stderr, "invalid fixed probe arguments")
		os.Exit(2)
	}
	if *marker != "" {
		fmt.Print(*marker)
		return
	}
	r := evidence{Version: "generic-containment-v1", Nonce: *nonce, UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), WritablePaths: []writeEvidence{}, Scope: "Fixed post-code-execution probes in an instrumented disposable container. Only protected root paths, declared writable directories and listed shell commands are measured. Installing this local helper under a protected root directory is not a package-manager or writable-mount installation test. No network reachability or vulnerability exploitation is tested."}
	for _, directory := range []string{"/", "/usr", "/etc"} {
		r.ProtectedWrites = append(r.ProtectedWrites, writeEvidence{Path: directory, operation: protectedWriteProbe(directory, *nonce)})
	}
	for _, directory := range writable {
		if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(directory) > 256 || strings.ContainsAny(directory, "\x00\r\n") {
			fmt.Fprintln(os.Stderr, "invalid declared writable directory")
			os.Exit(2)
		}
		r.WritablePaths = append(r.WritablePaths, writeEvidence{Path: directory, operation: writeProbe(directory, *nonce)})
	}
	r.LocalToolInstall = installProbe(*nonce)
	for _, command := range [][]string{{"/bin/sh"}, {"/bin/bash"}, {"/bin/ash"}, {"/usr/bin/sh"}, {"/usr/bin/bash"}, {"/usr/bin/ash"}, {"/bin/dash"}, {"/usr/bin/dash"}, {"/bin/zsh"}, {"/usr/bin/zsh"}, {"/busybox", "sh"}, {"/bin/busybox", "sh"}, {"/usr/bin/busybox", "sh"}} {
		r.Shells = append(r.Shells, shellProbe(command, *nonce))
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(1)
	}
}

func errorCode(err error) string {
	for _, item := range []struct {
		value error
		code  string
	}{{syscall.EROFS, "EROFS"}, {syscall.EACCES, "EACCES"}, {syscall.EPERM, "EPERM"}, {syscall.ENOENT, "ENOENT"}, {syscall.ENOTDIR, "ENOTDIR"}, {syscall.EEXIST, "EEXIST"}, {syscall.ENOSPC, "ENOSPC"}} {
		if errors.Is(err, item.value) {
			return item.code
		}
	}
	if os.IsNotExist(err) {
		return "ENOENT"
	}
	if os.IsPermission(err) {
		return "EACCES"
	}
	return "OTHER"
}

func result(err error) operation {
	if err == nil {
		return operation{Status: "allowed"}
	}
	code := errorCode(err)
	status := "inconclusive"
	if code == "EROFS" || code == "EACCES" || code == "EPERM" {
		status = "denied"
	}
	if code == "ENOENT" || code == "ENOTDIR" {
		status = "target_unavailable"
	}
	return operation{Status: status, ErrorCode: code}
}

func writeProbe(directory, nonce string) operation {
	file := filepath.Join(directory, ".hardening-write-"+nonce)
	f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result(err)
	}
	defer os.Remove(file)
	_, writeErr := f.WriteString(nonce)
	closeErr := f.Close()
	if writeErr != nil {
		return result(writeErr)
	}
	return result(closeErr)
}

// Called only for the fixed protected roots; missing roots still require a real denied write.
func protectedWriteProbe(directory, nonce string) operation {
	info, err := os.Lstat(directory)
	if err == nil {
		if !info.IsDir() {
			return operation{Status: "inconclusive", ErrorCode: "NOT_DIRECTORY_OR_ALIAS"}
		}
		return writeProbe(directory, nonce)
	}
	if !os.IsNotExist(err) || directory == "/" {
		return result(err)
	}
	if err := os.Mkdir(directory, 0755); err != nil {
		measured := result(err)
		if measured.Status != "denied" {
			measured.Status = "inconclusive"
		}
		return measured
	}
	defer os.Remove(directory)
	return writeProbe(directory, nonce)
}

func installProbe(nonce string) (measured operation) {
	stage := "create_directory"
	defer func() { measured.Stage = stage }()
	directory := "/.hardening-local-tool-" + nonce
	if err := os.Mkdir(directory, 0700); err != nil {
		return result(err)
	}
	defer os.RemoveAll(directory)
	stage = "read_probe"
	in, err := os.Open("/.hardening-probe")
	if err != nil {
		return operation{Status: "inconclusive", ErrorCode: errorCode(err)}
	}
	defer in.Close()
	file := filepath.Join(directory, "local-tool")
	stage = "create_file"
	out, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return result(err)
	}
	stage = "copy_file"
	written, copyErr := io.Copy(out, io.LimitReader(in, 32*1024*1024+1))
	closeErr := out.Close()
	if copyErr != nil {
		return result(copyErr)
	}
	if closeErr != nil {
		return result(closeErr)
	}
	if written > 32*1024*1024 {
		return operation{Status: "inconclusive", ErrorCode: "TOO_LARGE"}
	}
	stage = "execute_marker"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, file, "--marker", nonce)
	cmd.WaitDelay = 100 * time.Millisecond
	var stdout boundedOutput
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return operation{Status: "inconclusive", ErrorCode: "TIMEOUT"}
		}
		return result(err)
	}
	if stdout.String() != nonce {
		return operation{Status: "inconclusive", ErrorCode: "MARKER_MISMATCH"}
	}
	return operation{Status: "allowed"}
}

func shellProbe(command []string, nonce string) shellEvidence {
	r := shellEvidence{Command: command, Status: "inconclusive", ExitCode: -1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := append(append([]string{}, command[1:]...), "-c", "printf '%s' '"+nonce+"'")
	cmd := exec.CommandContext(ctx, command[0], args...)
	cmd.WaitDelay = 100 * time.Millisecond
	var stdout boundedOutput
	cmd.Stdout = &stdout
	err := cmd.Run()
	if ctx.Err() != nil {
		r.ErrorCode = "TIMEOUT"
		return r
	}
	if err == nil {
		r.ExitCode = 0
		if stdout.String() == nonce {
			r.Status = "accessible"
		} else {
			r.ErrorCode = "MARKER_MISMATCH"
		}
		return r
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		r.ExitCode = exit.ExitCode()
	}
	r.ErrorCode = errorCode(err)
	if r.ErrorCode == "ENOENT" || r.ErrorCode == "ENOTDIR" {
		r.Status = "unavailable"
	}
	if r.ErrorCode == "EACCES" || r.ErrorCode == "EPERM" {
		r.Status = "denied"
	}
	return r
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 4096 - b.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

type httpCheck struct {
	Path         string `json:"path"`
	Status       int    `json:"status"`
	BodyContains string `json:"body_contains"`
}

type httpCheckEvidence struct {
	Path       string `json:"path"`
	Status     int    `json:"status"`
	BodySHA256 string `json:"body_sha256"`
	Passed     bool   `json:"passed"`
	ErrorCode  string `json:"error_code,omitempty"`
}

func parseHTTPChecks(specification string, port, seconds int) ([]httpCheck, error) {
	if len(specification) > 16384 || port < 1 || port > 65535 || seconds < 1 || seconds > 120 {
		return nil, errors.New("invalid HTTP specification")
	}
	var checks []httpCheck
	decoder := json.NewDecoder(strings.NewReader(specification))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&checks) != nil || len(checks) == 0 || len(checks) > 16 {
		return nil, errors.New("invalid HTTP checks")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing HTTP specification data")
	}
	for _, check := range checks {
		uri, err := url.ParseRequestURI(check.Path)
		if err != nil || !strings.HasPrefix(check.Path, "/") || strings.HasPrefix(check.Path, "//") || len(check.Path) > 2048 || uri.IsAbs() || uri.Host != "" || uri.Fragment != "" || strings.ContainsAny(check.Path, "\x00\r\n") || check.Status < 100 || check.Status > 599 || len(check.BodyContains) > 4096 {
			return nil, errors.New("invalid loopback assertion")
		}
	}
	return checks, nil
}

func checkHTTP(specification string, port, seconds int, writer io.Writer) (bool, error) {
	checks, err := parseHTTPChecks(specification, port, seconds)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 64 * 1024}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	results := make([]httpCheckEvidence, 0, len(checks))
	all := true
	for _, check := range checks {
		measured := httpCheckEvidence{Path: check.Path, ErrorCode: "NO_RESPONSE"}
		for ctx.Err() == nil {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, check.Path), nil)
			if err != nil {
				return false, errors.New("invalid local request")
			}
			response, err := client.Do(request)
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
				response.Body.Close()
				measured.Status = response.StatusCode
				if readErr != nil {
					measured.ErrorCode = "BODY_READ_FAILED"
				} else if len(body) > 1024*1024 {
					measured.ErrorCode = "BODY_TOO_LARGE"
				} else {
					hash := sha256.Sum256(body)
					measured.BodySHA256 = hex.EncodeToString(hash[:])
					measured.Passed = response.StatusCode == check.Status && bytes.Contains(body, []byte(check.BodyContains))
					measured.ErrorCode = "ASSERTION_FAILED"
					if measured.Passed {
						measured.ErrorCode = ""
						break
					}
				}
			} else {
				measured.ErrorCode = "HTTP_REQUEST_FAILED"
			}
			select {
			case <-ctx.Done():
			case <-time.After(100 * time.Millisecond):
			}
		}
		all = all && measured.Passed
		results = append(results, measured)
	}
	report := struct {
		Version string              `json:"version"`
		Checks  []httpCheckEvidence `json:"checks"`
		Passed  bool                `json:"passed"`
	}{"generic-http-v1", results, all}
	return all, json.NewEncoder(writer).Encode(report)
}

func protectedPath(value string) bool {
	if value == "/" {
		return true
	}
	for _, root := range []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/boot", "/root", "/.hardening-probe"} {
		if value == root || strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}

func canonicalPaths(specification string) ([]string, error) {
	var values []string
	if len(specification) > 8192 || json.Unmarshal([]byte(specification), &values) != nil || len(values) > 17 {
		return nil, errors.New("invalid paths")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n,:") || protectedPath(value) {
			return nil, errors.New("invalid path")
		}
		ancestor := value
		tail := []string{}
		for {
			_, err := os.Lstat(ancestor)
			if err == nil {
				break
			}
			if !os.IsNotExist(err) || ancestor == "/" {
				return nil, errors.New("inaccessible ancestor")
			}
			tail = append(tail, filepath.Base(ancestor))
			ancestor = filepath.Dir(ancestor)
		}
		resolved, err := filepath.EvalSymlinks(ancestor)
		if err != nil {
			return nil, errors.New("unresolved path")
		}
		if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
			return nil, errors.New("writable target is not a directory")
		}
		for i := len(tail) - 1; i >= 0; i-- {
			resolved = filepath.Join(resolved, tail[i])
		}
		if protectedPath(resolved) {
			return nil, errors.New("protected path")
		}
		if !seen[resolved] {
			result = append(result, resolved)
			seen[resolved] = true
		}
	}
	return result, nil
}
