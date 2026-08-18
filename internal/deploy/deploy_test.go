package deploy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"selfu/internal/catalog"
)

func TestComposeRender(t *testing.T) {
	m := &catalog.Manifest{
		ID: "gitea", Version: "1", Metadata: catalog.Metadata{Name: "Gitea"},
		Deployment: catalog.Deployment{Engine: catalog.EngineDockerCompose, Image: "gitea/gitea:1.22.2"},
		Storage:    []catalog.Storage{{Name: "data", Type: "persistent"}},
	}
	out, err := Compose("01234567-89ab", m, map[string]string{"APP_BASE_URL": "https://git.example.com"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	// Must be valid YAML.
	var tree map[string]any
	if err := yaml.Unmarshal(out, &tree); err != nil {
		t.Fatalf("rendered compose not valid yaml: %v\n%s", err, out)
	}
	// Project name from the platform id, not user input (§20).
	if !strings.Contains(string(out), "name: platform-01234567-89ab") {
		t.Errorf("project name missing platform id:\n%s", out)
	}
	if !strings.Contains(string(out), "image: \"gitea/gitea:1.22.2\"") {
		t.Errorf("image missing:\n%s", out)
	}
	if !strings.Contains(string(out), "data:/srv/data") {
		t.Errorf("persistent volume missing:\n%s", out)
	}
	if !strings.Contains(string(out), "APP_BASE_URL") {
		t.Errorf("env missing:\n%s", out)
	}
}

// Project names must be derived from ids and sanitized (spec §20).
func TestInvalidInstanceIDRejected(t *testing.T) {
	m := &catalog.Manifest{Deployment: catalog.Deployment{Engine: catalog.EngineDockerCompose, Image: "x"}}
	if _, err := Compose("", m, nil); err == nil {
		t.Error("Compose('') = nil error, want error")
	}
}
