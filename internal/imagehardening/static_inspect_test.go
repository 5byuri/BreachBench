package imagehardening

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type staticTestFile struct {
	name, body, link string
	kind             byte
}

func staticTestArchive(t *testing.T, files ...staticTestFile) *bytes.Reader {
	t.Helper()
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	for _, file := range files {
		kind := file.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: file.name, Mode: 0755, Typeflag: kind, Linkname: file.link}
		if kind == tar.TypeReg {
			header.Size = int64(len(file.body))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			if _, err := writer.Write([]byte(file.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(data.Bytes())
}

func staticTestMetadata(user string) localImageMetadata {
	encodedUser, _ := json.Marshal(user)
	return localImageMetadata{ID: "sha256:" + strings.Repeat("a", 64), Architecture: "arm64", OS: "linux", Config: map[string]json.RawMessage{
		"User": encodedUser, "Entrypoint": json.RawMessage(`["/custom/app"]`),
	}}
}

func TestStaticInspectionResolvesGraphifyUserAndPythonUsrmergeAliases(t *testing.T) {
	metadata := staticTestMetadata("graphify")
	metadata.Config["Entrypoint"] = json.RawMessage(`["python","--private=DO_NOT_RETURN_ARG"]`)
	metadata.Config["Cmd"] = json.RawMessage(`["/data/graph.json","--transport","http"]`)
	metadata.Config["Env"] = json.RawMessage(`["PATH=/usr/local/bin:/usr/bin:/bin","PRIVATE=DO_NOT_RETURN_ENV"]`)
	metadata.Config["Labels"] = json.RawMessage(`{"private":"DO_NOT_RETURN_LABEL"}`)
	metadata.Config["Volumes"] = json.RawMessage(`{"/data":{}}`)
	metadata.Config["ExposedPorts"] = json.RawMessage(`{"8080/tcp":{},"9999/udp":{}}`)
	archive := staticTestArchive(t,
		staticTestFile{name: "etc/passwd", body: "root:x:0:0::/root:/bin/sh\ngraphify:x:10001:10001::/home/graphify:/bin/sh\n"},
		staticTestFile{name: "etc/group", body: "graphify:x:10001:\n"},
		staticTestFile{name: "bin", kind: tar.TypeSymlink, link: "usr/bin"},
		staticTestFile{name: "usr/bin/sh", kind: tar.TypeSymlink, link: "dash"},
		staticTestFile{name: "usr/bin/dash", body: "\x7fELF-shell"},
		staticTestFile{name: "usr/bin/bash", body: "\x7fELF-shell"},
		staticTestFile{name: "usr/bin/apt", body: "\x7fELF-package-manager"},
		staticTestFile{name: "usr/local/bin/python", kind: tar.TypeSymlink, link: "python3"},
		staticTestFile{name: "usr/local/bin/python3", kind: tar.TypeSymlink, link: "python3.12"},
		staticTestFile{name: "usr/local/bin/python3.12", body: "\x7fELF-runtime"},
		staticTestFile{name: "tmp", kind: tar.TypeDir},
	)
	result, err := analyzeStaticRootfs(context.Background(), metadata, archive, genericRuntimePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if result.User != "10001:10001" || result.UserChanged || result.ShellRequired {
		t.Fatalf("existing identity or direct Python executable was misidentified: %+v", result)
	}
	if strings.Join(result.EligibleRemovals, ",") != "/usr/bin/sh,/usr/bin/bash,/usr/bin/dash,/usr/bin/apt" {
		t.Fatalf("usrmerge tool entries not inventoried: %v", result.EligibleRemovals)
	}
	if strings.Join(result.DeclaredVolumes, ",") != "/data" || strings.Join(result.ExposedPorts, ",") != "8080/tcp,9999/udp" {
		t.Fatal("safe declared metadata missing")
	}
	encoded, _ := json.Marshal(result)
	for _, secret := range []string{"DO_NOT_RETURN", "Entrypoint", "Labels", "Config", "/data/graph.json"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("private metadata returned: %s", secret)
		}
	}
}

func TestStaticInspectionShebangAndOpaqueStartupRetainShells(t *testing.T) {
	for _, body := range []string{"#!/usr/bin/env -S bash -eu\nexit 0\n", "opaque executable"} {
		result, err := analyzeStaticRootfs(context.Background(), staticTestMetadata("10001:10001"), staticTestArchive(t,
			staticTestFile{name: "custom/app", body: body},
			staticTestFile{name: "usr/bin/bash", body: "\x7fELF"},
			staticTestFile{name: "usr/bin/apt", body: "\x7fELF"},
		), genericRuntimePolicy{})
		if err != nil || !result.ShellRequired || len(result.EligibleRemovals) != 0 {
			t.Fatalf("required/unknown shell was removable: %+v %v", result, err)
		}
	}
	metadata := staticTestMetadata("10001:10001")
	metadata.Config["Healthcheck"] = json.RawMessage(`{"Test":["CMD-SHELL","curl localhost"]}`)
	result, err := analyzeStaticRootfs(context.Background(), metadata, staticTestArchive(t, staticTestFile{name: "usr/bin/curl", body: "\x7fELF"}), genericRuntimePolicy{})
	if err != nil || !result.ShellRequired || len(result.EligibleRemovals) != 0 {
		t.Fatal("healthcheck requirements were ignored", err)
	}
}

func TestStaticStartupAliasesRetainEveryRequiredToolTarget(t *testing.T) {
	metadata := staticTestMetadata("10001:10001")
	metadata.Config["Entrypoint"] = json.RawMessage(`["/entrypoint"]`)
	metadata.Config["Cmd"] = json.RawMessage(`["--argument-only"]`)
	result, err := analyzeStaticRootfs(context.Background(), metadata, staticTestArchive(t,
		staticTestFile{name: "entrypoint", kind: tar.TypeSymlink, link: "/usr/bin/wget"},
		staticTestFile{name: "usr/bin/wget", kind: tar.TypeSymlink, link: "curl"},
		staticTestFile{name: "usr/bin/curl", body: "\x7fELF"},
		staticTestFile{name: "usr/bin/apt", body: "\x7fELF"},
	), genericRuntimePolicy{})
	// Fixed tool paths also cover aliases outside the startup directory.
	if err != nil || result.ShellRequired || strings.Join(result.EligibleRemovals, ",") != "/usr/bin/apt" {
		t.Fatalf("required alias target was removable: %+v %v", result, err)
	}
}

func TestStaticOpaqueAliasRetainsAllToolsAndLauncherArgumentsAreRequired(t *testing.T) {
	for _, entrypoint := range []string{`["/entrypoint"]`, `["/usr/bin/env","bash"]`} {
		metadata := staticTestMetadata("10001:10001")
		metadata.Config["Entrypoint"] = json.RawMessage(entrypoint)
		result, err := analyzeStaticRootfs(context.Background(), metadata, staticTestArchive(t,
			staticTestFile{name: "entrypoint", kind: tar.TypeSymlink, link: "/opt/start"},
			staticTestFile{name: "opt/start", kind: tar.TypeSymlink, link: "/usr/bin/curl"},
			staticTestFile{name: "usr/bin/curl", body: "\x7fELF"},
			staticTestFile{name: "usr/bin/bash", body: "\x7fELF"},
			staticTestFile{name: "usr/bin/env", body: "\x7fELF"},
			staticTestFile{name: "usr/bin/apt", body: "\x7fELF"},
		), genericRuntimePolicy{})
		if err != nil || !result.ShellRequired {
			t.Fatalf("unknown alias or declared shell launcher ignored: %+v %v", result, err)
		}
		for _, removal := range result.EligibleRemovals {
			if entrypoint == `["/entrypoint"]` || isShellTool(removal) {
				t.Fatal("required or opaque dependency was removable", removal)
			}
		}
	}
}

func TestStaticShebangInterpreterToolIsRetained(t *testing.T) {
	result, err := analyzeStaticRootfs(context.Background(), staticTestMetadata("10001:10001"), staticTestArchive(t,
		staticTestFile{name: "custom/app", body: "#!/usr/bin/curl\n"},
		staticTestFile{name: "usr/bin/curl", body: "\x7fELF"},
		staticTestFile{name: "usr/bin/apt", body: "\x7fELF"},
	), genericRuntimePolicy{})
	if err != nil || strings.Join(result.EligibleRemovals, ",") != "/usr/bin/apt" {
		t.Fatal("startup interpreter was removable", err)
	}
}

func TestStaticUserResolutionAndExplicitOverride(t *testing.T) {
	passwd := []byte("root:x:0:0::/:/bin/sh\ngraphify:x:10001:10001::/:/bin/sh\nother:x:123:456::/:/bin/sh\n")
	group := []byte("staff:x:789:\n")
	for _, test := range []struct{ declared, expected string }{
		{"", "0:0"}, {"root", "0:0"}, {"0", "0:0"}, {"000:999", "0:0"},
		{"graphify", "10001:10001"}, {"graphify:staff", "10001:789"}, {"graphify:234", "10001:234"},
		{"123", "123:456"}, {"123:staff", "123:789"}, {"123:", "123:456"},
		{"500", "500:0"}, {"4294967295:4294967295", "4294967295:4294967295"},
	} {
		resolved, err := resolveStaticUser(test.declared, passwd, group)
		if err != nil || resolved != test.expected {
			t.Errorf("%q resolved %q, want %q: %v", test.declared, resolved, test.expected, err)
		}
	}
	for _, declared := range []string{"unknown", "graphify:unknown", "4294967296:1", "-1:1", "+1:1", "1:2:3", "graphify\n"} {
		if _, err := resolveStaticUser(declared, passwd, group); err == nil {
			t.Errorf("unresolvable identity accepted: %q", declared)
		}
	}
	for _, user := range []string{"", "root", "0:0"} {
		result, err := analyzeStaticRootfs(context.Background(), staticTestMetadata(user), staticTestArchive(t), genericRuntimePolicy{})
		if err != nil || result.User != "65532:65532" || !result.UserChanged {
			t.Fatalf("root not replaced: %+v %v", result, err)
		}
	}
	metadata := staticTestMetadata("unresolved")
	if _, err := analyzeStaticRootfs(context.Background(), metadata, staticTestArchive(t), genericRuntimePolicy{}); err == nil || !strings.Contains(err.Error(), "policy.user") {
		t.Fatal("missing explicit-user action", err)
	}
	result, err := analyzeStaticRootfs(context.Background(), metadata, staticTestArchive(t), genericRuntimePolicy{User: "10001:10001"})
	if err != nil || result.User != "10001:10001" || !result.UserChanged {
		t.Fatal("explicit user did not resolve the ambiguity", err)
	}
	for _, database := range []string{"graphify:x:not-a-uid:1:::", "graphify:x:1:1:::\ngraphify:x:2:2:::"} {
		if _, err := resolveStaticUser("graphify", []byte(database), nil); err == nil {
			t.Fatal("malformed or ambiguous account accepted")
		}
	}
	if result, err := resolveStaticUser("123", []byte("123:x:999:999:::\nother:x:123:456:::\n"), nil); err != nil || result != "123:456" {
		t.Fatal("numeric UID was mistaken for a numeric account name", result, err)
	}
	if result, err := resolveStaticUser("root", []byte("root:x:10001:10001:::\n"), nil); err != nil || result != "10001:10001" {
		t.Fatal("a resolvable non-root named account was rewritten", result, err)
	}
}

func TestStaticWritablePathsRejectAliasesAndFiles(t *testing.T) {
	for _, test := range []struct {
		file   staticTestFile
		policy genericRuntimePolicy
	}{
		{staticTestFile{name: "tmp", kind: tar.TypeSymlink, link: "var/tmp"}, genericRuntimePolicy{}},
		{staticTestFile{name: "tmp", kind: tar.TypeLink, link: "other"}, genericRuntimePolicy{}},
		{staticTestFile{name: "app", kind: tar.TypeSymlink, link: "/usr"}, genericRuntimePolicy{WritablePaths: []string{"/app/cache"}}},
		{staticTestFile{name: "app/cache", body: "not a directory"}, genericRuntimePolicy{WritablePaths: []string{"/app/cache"}}},
	} {
		_, err := analyzeStaticRootfs(context.Background(), staticTestMetadata("10001:10001"), staticTestArchive(t, test.file), test.policy)
		if err == nil || !strings.Contains(err.Error(), "alias or non-directory") {
			t.Fatalf("unsafe writable path accepted: %+v %v", test, err)
		}
	}
}

func TestStaticArchiveRejectsTraversalDuplicatesUnsafeLinksAndLargeAccounts(t *testing.T) {
	for _, file := range []staticTestFile{
		{name: "../outside"}, {name: "/absolute"}, {name: "app/../elsewhere"},
		{name: "app\\outside"}, {name: "odd\nname"},
		{name: "other", kind: tar.TypeLink, link: "../outside"},
	} {
		if _, err := analyzeStaticRootfs(context.Background(), staticTestMetadata("1:1"), staticTestArchive(t, file), genericRuntimePolicy{}); err == nil {
			t.Errorf("unsafe archive entry accepted: %q", file.name)
		}
	}
	for _, files := range [][]staticTestFile{
		{{name: "usr/bin/sh"}, {name: "usr/bin/sh"}},
		{{name: "etc/passwd", body: strings.Repeat("x", 1024*1024+1)}},
	} {
		if _, err := analyzeStaticRootfs(context.Background(), staticTestMetadata("1:1"), staticTestArchive(t, files...), genericRuntimePolicy{}); err == nil {
			t.Fatal("ambiguous or excessive input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := analyzeStaticRootfs(ctx, staticTestMetadata("1:1"), staticTestArchive(t), genericRuntimePolicy{}); err == nil {
		t.Fatal("cancelled inspection continued")
	}
}
