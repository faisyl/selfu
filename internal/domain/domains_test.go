package domain

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"Example.COM":     "example.com",
		"example.com.":    "example.com",
		"  example.com ":  "example.com",
		"münchen.de":      "xn--mnchen-3ya.de", // IDNA -> punycode
		"sub.example.com": "sub.example.com",
	}
	for in, want := range ok {
		got, err := NormalizeDomain(in)
		if err != nil {
			t.Errorf("NormalizeDomain(%q) error = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", ".", "a b.com", "-bad.com", "bad-.com", "exa mple.com", strings.Repeat("x", 300)} {
		if _, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) = nil error, want error", in)
		}
	}
}

// HostnameWithinDomain must reject look-alikes (spec §12: no naive suffix).
func TestHostnameWithinDomain(t *testing.T) {
	cases := []struct {
		hostname, domain string
		want             bool
	}{
		{"git.example.com", "example.com", true},
		{"cloud.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"evil-example.com", "example.com", false},
		{"example.com.attacker.io", "example.com", false},
		{"example.com.attacker.com", "example.com", false},
		{"a.b.example.com", "b.example.com", true},
		{"b.example.com", "example.com", true},
		{"", "example.com", false},
	}
	for _, c := range cases {
		if got := HostnameWithinDomain(c.hostname, c.domain); got != c.want {
			t.Errorf("HostnameWithinDomain(%q, %q) = %v, want %v", c.hostname, c.domain, got, c.want)
		}
	}
}

func TestDomainStatusValid(t *testing.T) {
	for _, s := range []DomainStatus{DomainPending, DomainVerificationRequired, DomainVerified, DomainSuspended} {
		if !s.Valid() {
			t.Errorf("%q must be valid", s)
		}
	}
	if DomainStatus("bogus").Valid() {
		t.Error("bogus status must be invalid")
	}
}
