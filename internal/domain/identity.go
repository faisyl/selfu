package domain

import (
	"errors"
	"strings"
	"time"
)

// OrgRole is a user's role within an organization (spec §7).
type OrgRole string

// Roles are ordered owner > admin > member.
const (
	RoleOwner  OrgRole = "owner"
	RoleAdmin  OrgRole = "admin"
	RoleMember OrgRole = "member"
)

// Valid reports whether r is a known role.
func (r OrgRole) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember:
		return true
	}
	return false
}

// Rank orders roles; larger rank is more privileged.
func (r OrgRole) Rank() int {
	switch r {
	case RoleOwner:
		return 3
	case RoleAdmin:
		return 2
	case RoleMember:
		return 1
	default:
		return 0
	}
}

// CanManage reports whether a user holding role r may perform an action that
// requires at least required.
func (r OrgRole) CanManage(required OrgRole) bool {
	return r.Valid() && required.Valid() && r.Rank() >= required.Rank()
}

// Organization is the primary administrative/security boundary (spec §5).
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewOrganization validates and creates an organization with a derived slug.
func NewOrganization(name string) (Organization, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Organization{}, errors.New("organization name is required")
	}
	if len(name) > 128 {
		return Organization{}, errors.New("organization name too long")
	}
	return Organization{
		Name:   name,
		Slug:   Slugify(name),
		Status: "active",
	}, nil
}

// Slugify produces a URL-safe slug from a display name.
func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "org"
	}
	return out
}

// OrganizationMembership links a user to an organization with a role
// (spec §7).
type OrganizationMembership struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           OrgRole   `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
}

// Group is an organization-scoped collection of users used for application
// authorization and (later) mail policy (spec §8).
type Group struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Description    string `json:"description"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewGroup validates and creates a group with a derived, org-local slug.
func NewGroup(organizationID, name, description string) (Group, error) {
	name = strings.TrimSpace(name)
	if organizationID == "" {
		return Group{}, errors.New("organization id is required")
	}
	if name == "" {
		return Group{}, errors.New("group name is required")
	}
	if len(name) > 128 {
		return Group{}, errors.New("group name too long")
	}
	return Group{
		OrganizationID: organizationID,
		Name:           name,
		Slug:           Slugify(name),
		Description:    strings.TrimSpace(description),
	}, nil
}

// GroupMembership links a user to a group (spec §8).
type GroupMembership struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id"`
}

// External provider resource types (spec §16, §22). These MUST be stable:
// they are stored in external_resources.
const (
	ResTypeAuthentikUser        = "authentik_user"
	ResTypeAuthentikGroup       = "authentik_group"
	ResTypeAuthentikApplication = "authentik_application"
	ResTypeAuthentikProvider    = "authentik_provider"
)

// External resource lifecycle statuses (spec §22).
const (
	ExtProvisioning = "provisioning"
	ExtActive       = "active"
	ExtFailed       = "failed"
	ExtRemoved      = "removed"
)

// ExternalResource maps a platform object to its external provider
// counterpart, with the external id stored explicitly (never inferred from
// names, spec §16).
type ExternalResource struct {
	ID               string    `json:"id"`
	ResourceType     string    `json:"resource_type"`
	PlatformObjectID string    `json:"platform_object_id"`
	Provider         string    `json:"provider"`
	ExternalID       string    `json:"external_id"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}
