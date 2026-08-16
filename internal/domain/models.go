// Package domain holds the platform's core entities and their validation
// rules. It is a pure Go package: no database, no I/O, no framework imports.
package domain

import (
	"errors"
	"strings"
	"time"
)

// UserStatus is the lifecycle state of a platform user.
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

// Valid reports whether s is a known user status.
func (s UserStatus) Valid() bool {
	switch s {
	case UserStatusActive, UserStatusDisabled:
		return true
	}
	return false
}

// User is a platform identity. Email is the login address and is stored
// normalized to lowercase; auth_identity_id references the authenticated
// identity in the external identity provider (authentik), never inferred
// from display names (spec §6, §16).
type User struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"display_name"`
	Status         UserStatus `json:"status"`
	IsAdmin        bool       `json:"is_admin"`
	AuthProvider   string     `json:"-"`
	AuthIdentityID string     `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// NewUser validates the identity-bearing fields of a user created from an
// external identity provider claim.
func NewUser(email, displayName, authProvider, authIdentityID string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return User{}, errors.New("email is required")
	}
	if !looksLikeEmail(email) {
		return User{}, errors.New("email is not a valid address")
	}
	if strings.TrimSpace(authProvider) == "" {
		return User{}, errors.New("auth provider is required")
	}
	if strings.TrimSpace(authIdentityID) == "" {
		return User{}, errors.New("auth identity id is required")
	}
	displayName = strings.TrimSpace(displayName)
	return User{
		Email:          email,
		DisplayName:    displayName,
		Status:         UserStatusActive,
		AuthProvider:   authProvider,
		AuthIdentityID: authIdentityID,
	}, nil
}

// looksLikeEmail performs a conservative structural validation suitable for
// identity emails. It requires exactly one @, a non-empty local part, and a
// dotted domain without spaces.
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') {
		return false
	}
	domain := s[at+1:]
	if domain == "" || strings.ContainsAny(domain, " \t") {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	return true
}

// AuditEvent records an auditable platform action. Message content and
// secrets must never be stored here (spec §68, §69).
type AuditEvent struct {
	ID           string         `json:"id"`
	OccurredAt   time.Time      `json:"occurred_at"`
	ActorUserID  *string        `json:"actor_user_id,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
}

// Valid reports whether the event carries the mandatory fields.
func (e AuditEvent) Valid() bool {
	return strings.TrimSpace(e.Action) != "" && len(e.Action) <= 128
}
