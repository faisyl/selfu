// Package catalog defines the declarative application catalog manifest
// (spec §13). The schema is the ONLY allowed surface: pars/validation reject
// any unknown field, so arbitrary Compose or Traefik fragments cannot be
// smuggled in (spec §18).
package catalog

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Engine values.
const EngineDockerCompose = "docker-compose"

// Authentication modes (spec §14).
const (
	AuthOIDC        = "oidc"
	AuthForwardAuth = "forward-auth"
	AuthNative      = "native"
	AuthNone        = "none"
)

// Database types.
const (
	DBPostgres = "postgres"
	DBNone     = "none"
)

// Email sender modes (spec §70).
const SenderPlatformManaged = "platform-managed"

// Manifest mirrors the catalog spec §13/§70 schema exactly. Unknown fields
// are rejected by strict YAML decoding.
type Manifest struct {
	ID             string         `yaml:"id"`
	Version        string         `yaml:"version"`
	Metadata       Metadata       `yaml:"metadata"`
	Deployment     Deployment     `yaml:"deployment"`
	Network        Network        `yaml:"network"`
	Storage        []Storage      `yaml:"storage"`
	Database       Database       `yaml:"database"`
	Authentication Authentication `yaml:"authentication"`
	Email          *Email         `yaml:"email"`
}

// Metadata is display metadata.
type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Category    string `yaml:"category"`
}

// Deployment declares how the app is deployed.
type Deployment struct {
	Engine string `yaml:"engine"`
	Image  string `yaml:"image"`
}

// Network describes HTTP exposure.
type Network struct {
	HTTP *HTTP `yaml:"http"`
}

// HTTP describes the container's HTTP port.
type HTTP struct {
	ContainerPort int `yaml:"container_port"`
}

// Storage declares a named volume.
type Storage struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // persistent | ephemeral
}

// Database declares the app's database needs.
type Database struct {
	Type string `yaml:"type"`
}

// Authentication declares the auth mode (spec §14).
type Authentication struct {
	Mode string `yaml:"mode"`
}

// Email declares nullable app email needs (spec §70).
type Email struct {
	Required bool   `yaml:"required"`
	Sender   Sender `yaml:"sender"`
	SMTP     SMTP   `yaml:"smtp"`
}

// Sender declares a platform-managed sender identity.
type Sender struct {
	Mode      string `yaml:"mode"`
	LocalPart string `yaml:"local_part"`
}

// SMTP declares SMTP requirements.
type SMTP struct {
	Required bool `yaml:"required"`
}

// Parse strictly decodes and validates a catalog manifest.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // any unknown field -> error (spec §18)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("catalog manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks the manifest against the schema's allowed values.
func (m *Manifest) Validate() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("catalog manifest: id is required")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("catalog manifest: version is required")
	}
	if m.Deployment.Engine != EngineDockerCompose {
		return fmt.Errorf("catalog manifest: unsupported deployment engine %q", m.Deployment.Engine)
	}
	if m.Deployment.Engine == EngineDockerCompose && strings.TrimSpace(m.Deployment.Image) == "" {
		return fmt.Errorf("catalog manifest: deployment.image is required for docker-compose")
	}
	if m.Network.HTTP != nil && m.Network.HTTP.ContainerPort <= 0 {
		return fmt.Errorf("catalog manifest: http.container_port must be > 0")
	}
	for _, s := range m.Storage {
		switch s.Type {
		case "persistent", "ephemeral":
		default:
			return fmt.Errorf("catalog manifest: invalid storage type %q", s.Type)
		}
	}
	switch m.Authentication.Mode {
	case AuthOIDC, AuthForwardAuth, AuthNative, AuthNone:
	default:
		return fmt.Errorf("catalog manifest: invalid authentication mode %q", m.Authentication.Mode)
	}
	switch m.Database.Type {
	case DBPostgres, DBNone:
	default:
		return fmt.Errorf("catalog manifest: unsupported database type %q", m.Database.Type)
	}
	if m.Email != nil && m.Email.Sender.Mode != "" && m.Email.Sender.Mode != SenderPlatformManaged {
		return fmt.Errorf("catalog manifest: invalid email.sender.mode %q", m.Email.Sender.Mode)
	}
	if m.Email != nil && m.Email.Sender.LocalPart != "" && strings.ContainsAny(m.Email.Sender.LocalPart, "@ \t") {
		return fmt.Errorf("catalog manifest: invalid email.sender.local_part")
	}
	return nil
}

// BuiltIns returns the curated catalog seeded into the platform.
func BuiltIns() []*Manifest {
	return []*Manifest{
		{
			ID:      "gitea",
			Version: "1",
			Metadata: Metadata{
				Name:        "Gitea",
				Description: "Lightweight Git hosting",
				Category:    "development",
			},
			Deployment:     Deployment{Engine: EngineDockerCompose, Image: "gitea/gitea:1.22.2"},
			Network:        Network{HTTP: &HTTP{ContainerPort: 3000}},
			Storage:        []Storage{{Name: "data", Type: "persistent"}},
			Database:       Database{Type: DBPostgres},
			Authentication: Authentication{Mode: AuthOIDC},
			Email: &Email{
				Required: true,
				Sender:   Sender{Mode: SenderPlatformManaged, LocalPart: "notifications"},
				SMTP:     SMTP{Required: true},
			},
		},
	}
}
