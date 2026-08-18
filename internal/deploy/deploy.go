// Package deploy renders isolated Docker Compose projects for application
// instances (spec §20). It is a pure function: no I/O, no docker. Project
// names derive from platform instance ids, never arbitrary user input (§20).
package deploy

import (
	"fmt"
	"strings"

	"selfu/internal/catalog"
)

// Compose returns the compose.yaml content for an isolated project.
func Compose(instanceID string, m *catalog.Manifest, extraEnv map[string]string) ([]byte, error) {
	if instanceID == "" {
		return nil, fmt.Errorf("deploy: instance id is required")
	}
	if m == nil || m.Deployment.Engine != catalog.EngineDockerCompose {
		return nil, fmt.Errorf("deploy: catalog entry is not docker-compose")
	}
	volumes := []string{}
	for _, s := range m.Storage {
		if s.Type == "persistent" {
			volumes = append(volumes, "      - "+s.Name+":/srv/"+s.Name)
		}
	}
	envLines := []string{}
	for _, k := range sortedKeys(extraEnv) {
		envLines = append(envLines, fmt.Sprintf("      %s: %q", k, extraEnv[k]))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "name: platform-%s\n", sanitize(instanceID))
	b.WriteString("services:\n")
	b.WriteString("  app:\n")
	fmt.Fprintf(&b, "    image: %q\n", m.Deployment.Image)
	b.WriteString("    restart: unless-stopped\n")
	if len(envLines) > 0 {
		b.WriteString("    environment:\n")
		for _, l := range envLines {
			b.WriteString(l + "\n")
		}
	}
	if len(volumes) > 0 {
		b.WriteString("    volumes:\n")
		for _, v := range volumes {
			b.WriteString(v + "\n")
		}
	}
	if len(m.Storage) > 0 {
		b.WriteString("volumes:\n")
		for _, s := range m.Storage {
			fmt.Fprintf(&b, "  %s:\n", s.Name)
		}
	}
	return []byte(b.String()), nil
}

// sanitize makes an id safe for a compose project name (lowercase [a-z0-9-_]).
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			b.WriteRune(r - 'A' + 'a')
		}
	}
	out := b.String()
	if out == "" {
		out = "app"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
