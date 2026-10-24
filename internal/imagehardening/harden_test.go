package imagehardening

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHardenedArgs(t *testing.T) {
	for _, user := range []string{"0:0", "000:0", "root", "name:group", ""} {
		if _, err := hardenedArgs("image", user, "", "", nil); err == nil {
			t.Fatalf("accepted unsafe user %q", user)
		}
	}
	args, err := hardenedArgs("image", "65532:65532", "", "", []string{"php", "-v"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--read-only", "--cap-drop=ALL", "--network=none", "--pids-limit=128", "image php -v"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestVerifyDoesNotApprovePrivilegedContainer(t *testing.T) {
	data := []byte(`[{"Config":{"User":"0"},"HostConfig":{"Privileged":true,"NetworkMode":"host"},"Mounts":[{"Type":"bind","Destination":"/var/run/docker.sock"}]}]`)
	result, err := verifyReport(data)
	if err != nil {
		t.Fatal(err)
	}
	report := result.(map[string]any)
	if report["baseline_passed"] != false {
		t.Fatal("unsafe container passed")
	}
	if len(report["failures"].([]string)) < 5 {
		t.Fatal("missing baseline failures")
	}
}

func TestInspectRedactsSecrets(t *testing.T) {
	result, err := inspectReport([]byte(`[{"Config":{"Env":["TOKEN=secret"]},"HostConfig":{"Binds":["/secret:/data"]}}]`))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "secret") {
		t.Fatal("secret metadata exposed")
	}
}
