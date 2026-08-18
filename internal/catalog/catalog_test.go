package catalog

import (
	"strings"
	"testing"
)

const giteaYAML = `
id: gitea
version: "1"
metadata:
  name: Gitea
  description: Git hosting
  category: development
deployment:
  engine: docker-compose
  image: gitea/gitea:1.22.2
network:
  http:
    container_port: 3000
storage:
  - name: data
    type: persistent
database:
  type: postgres
authentication:
  mode: oidc
email:
  required: true
  sender:
    mode: platform-managed
    local_part: notifications
  smtp:
    required: true
`

func TestParseValidManifest(t *testing.T) {
	m, err := Parse([]byte(giteaYAML))
	if err != nil {
		t.Fatalf("Parse(giteaYAML) error = %v", err)
	}
	if m.ID != "gitea" || m.Metadata.Name != "Gitea" || m.Authentication.Mode != AuthOIDC {
		t.Errorf("parsed manifest wrong: %+v", m)
	}
	if m.Deployment.Image != "gitea/gitea:1.22.2" {
		t.Errorf("image = %q", m.Deployment.Image)
	}
}

// Spec §18: a catalog entry must not smuggle arbitrary Compose/Traefik
// fragments — unknown fields must be rejected.
func TestParseRejectsUnknownFields(t *testing.T) {
	bad := giteaYAML + "  labels:\n    - traefik.enable=true\n  arbitrary_thing:\n    - x\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("Parse() with unknown fields = nil error, want rejection (spec §18)")
	}
}

func TestParseRejectsBadEngineAndEmptyImage(t *testing.T) {
	for _, tc := range []string{
		strings.Replace(giteaYAML, "engine: docker-compose", "engine: kubernetes", 1),
		"id: x\nversion: '1'\nmetadata:\n  name: X\ndeployment:\n  engine: docker-compose\n",
	} {
		if _, err := Parse([]byte(tc)); err == nil {
			t.Errorf("Parse(%q) = nil error, want rejection", tc)
		}
	}
}

func TestBuiltInsValidate(t *testing.T) {
	for _, m := range BuiltIns() {
		if err := m.Validate(); err != nil {
			t.Errorf("built-in %s failed validation: %v", m.ID, err)
		}
	}
}
