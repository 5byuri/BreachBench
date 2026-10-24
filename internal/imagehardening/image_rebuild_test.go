package imagehardening

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestRootfsFiltersToolsWithoutChangingAppBytes(t *testing.T) {
	var source, destination bytes.Buffer
	w := tar.NewWriter(&source)
	for _, item := range []struct{ name, body string }{{"usr/bin/sh", "shell"}, {"app/custom/server.js", "original vulnerable application bytes"}, {"usr/bin/node", "same runtime"}} {
		if err := w.WriteHeader(&tar.Header{Name: item.name, Mode: 0755, Size: int64(len(item.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(item.body))
	}
	_ = w.Close()
	evidence, err := filterRootfs(context.Background(), &source, &destination, []string{"/usr/bin/sh"})
	if err != nil || len(evidence.RemovedEntries) != 1 || evidence.RetainedEntries != 2 || evidence.ApplicationFilesModified {
		t.Fatalf("bad evidence: %+v %v", evidence, err)
	}
	r := tar.NewReader(&destination)
	for _, expected := range []string{"original vulnerable application bytes", "same runtime"} {
		if _, err := r.Next(); err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r)
		if string(body) != expected {
			t.Fatal("retained file changed")
		}
	}
}

func TestRootfsRejectsAppRemovalTraversalAndBrokenHardlinks(t *testing.T) {
	if validateToolRemovals([]string{"/app/server.js"}) == nil {
		t.Fatal("app removal accepted")
	}
	for _, header := range []*tar.Header{{Name: "../../outside", Typeflag: tar.TypeReg}, {Name: "usr/bin/other", Typeflag: tar.TypeLink, Linkname: "usr/bin/sh"}, {Name: "usr/bin/other", Typeflag: tar.TypeLink, Linkname: "/usr/bin/sh"}, {Name: "usr/bin/other", Typeflag: tar.TypeLink, Linkname: "../usr/bin/sh"}, {Name: "usr/bin/sh", Typeflag: tar.TypeDir}} {
		var input, output bytes.Buffer
		w := tar.NewWriter(&input)
		_ = w.WriteHeader(header)
		_ = w.Close()
		if _, err := filterRootfs(context.Background(), &input, &output, []string{"/usr/bin/sh"}); err == nil {
			t.Fatalf("unsafe entry accepted: %+v", header)
		}
	}
}

func TestRebuiltConfigPreservesApplicationMetadataButSetsUser(t *testing.T) {
	original := localImageMetadata{Architecture: "arm64", OS: "linux", Config: map[string]json.RawMessage{"Env": json.RawMessage(`["PRIVATE=kept locally"]`), "Entrypoint": json.RawMessage(`["/custom/runtime","serve"]`), "Healthcheck": json.RawMessage(`{"Test":["CMD","check"]}`), "WorkingDir": json.RawMessage(`"/custom"`), "User": json.RawMessage(`"root"`)}}
	data, err := rebuiltConfig(original, "1000:1000", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct{ Config map[string]json.RawMessage }
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for key, value := range original.Config {
		if key != "User" && string(decoded.Config[key]) != string(value) {
			t.Fatalf("changed %s", key)
		}
	}
	if string(decoded.Config["User"]) != `"1000:1000"` || string(original.Config["User"]) != `"root"` {
		t.Fatal("user or source changed")
	}
}

func TestShellEntrypointAndHealthcheckAreNotBlindlyRemoved(t *testing.T) {
	for _, config := range []map[string]json.RawMessage{{"Entrypoint": json.RawMessage(`["/bin/sh","-c"]`)}, {"Entrypoint": json.RawMessage(`["/usr/local/bin/docker-entrypoint.sh"]`)}, {"Healthcheck": json.RawMessage(`{"Test":["CMD-SHELL","curl /health"]}`)}} {
		for _, item := range defaultToolRemovals(localImageMetadata{Config: config}) {
			if isShellTool(item) {
				t.Fatal("required shell removed")
			}
		}
	}
	var archive bytes.Buffer
	if err := writeImageArchive(&archive, []byte(`{"architecture":"arm64"}`), strings.NewReader("layer"), 5, "candidate:test"); err != nil {
		t.Fatal(err)
	}
	r := tar.NewReader(&archive)
	count := 0
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(h.Name, "..") {
			t.Fatal("unsafe generated archive")
		}
		count++
	}
	if count != 3 {
		t.Fatal("missing image components")
	}
}
