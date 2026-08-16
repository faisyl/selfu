package domain

import (
	"strings"
	"testing"
)

func TestNewUserNormalizesEmail(t *testing.T) {
	u, err := NewUser("  Alice@Example.COM ", "Alice", "https://auth.example", "sub-1")
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("Email = %q, want lowercase trimmed", u.Email)
	}
	if u.DisplayName != "Alice" {
		t.Errorf("DisplayName = %q, want trimmed", u.DisplayName)
	}
	if u.Status != UserStatusActive {
		t.Errorf("Status = %q, want active", u.Status)
	}
}

func TestNewUserRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		email   string
		prov    string
		id      string
		wantErr bool
	}{
		{"empty email", "", "p", "i", true},
		{"no at", "notanemail", "p", "i", true},
		{"double at", "a@b@c", "p", "i", true},
		{"no dot domain", "a@b", "p", "i", true},
		{"space in domain", "a@b c", "p", "i", true},
		{"empty provider", "a@b.co", "", "i", true},
		{"empty identity", "a@b.co", "p", "", true},
		{"valid", "a@b.co", "p", "i", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewUser(tc.email, "x", tc.prov, tc.id)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewUser(%q) err = %v, wantErr %v", tc.email, err, tc.wantErr)
			}
		})
	}
}

func TestUserStatusValid(t *testing.T) {
	if !UserStatusActive.Valid() || !UserStatusDisabled.Valid() {
		t.Error("known statuses must be valid")
	}
	if UserStatus("bogus").Valid() {
		t.Error("bogus status must be invalid")
	}
}

func TestAuditEventValid(t *testing.T) {
	ok := AuditEvent{Action: "auth.login.succeeded"}
	if !ok.Valid() {
		t.Error("valid event rejected")
	}
	if (AuditEvent{Action: ""}).Valid() {
		t.Error("empty action accepted")
	}
	if (AuditEvent{Action: strings.Repeat("x", 129)}).Valid() {
		t.Error("overlong action accepted")
	}
}
