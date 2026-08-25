package access

import (
	"context"
	"errors"
	"testing"

	"selfu/internal/dns"
)

func TestNewDispatch(t *testing.T) {
	manual, err := New("manual", Config{})
	if err != nil {
		t.Fatalf("New(manual): %v", err)
	}
	if manual.Name() != "manual" {
		t.Errorf("manual name = %q", manual.Name())
	}

	cf, err := New("cloudflare", Config{APIToken: "t", ZoneID: "z"})
	if err != nil {
		t.Fatalf("New(cloudflare): %v", err)
	}
	if cf.Name() != "cloudflare" {
		t.Errorf("cloudflare name = %q", cf.Name())
	}
	if _, ok := cf.DNS().(*dns.CloudflareProvider); !ok {
		t.Errorf("cloudflare DNS = %T, want *CloudflareProvider", cf.DNS())
	}
	if cf.ACME() != "dnschallenge.provider=cloudflare" {
		t.Errorf("cloudflare ACME = %q", cf.ACME())
	}

	if _, err := New("nope", Config{}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("New(nope) err = %v, want ErrUnknownProvider", err)
	}
}

func TestManualNeverAutoProvisions(t *testing.T) {
	m := NewManual()
	if err := m.Validate(context.Background()); err != nil {
		t.Fatalf("manual Validate: %v", err)
	}
	if err := m.DNS().SetTXT(context.Background(), "_x.example.com", "v"); !errors.Is(err, dns.ErrManual) {
		t.Errorf("manual SetTXT err = %v, want ErrManual", err)
	}
	if err := m.DNS().SetAddr(context.Background(), "a.example.com", "1.2.3.4"); !errors.Is(err, dns.ErrManual) {
		t.Errorf("manual SetAddr err = %v, want ErrManual", err)
	}
	if m.ACME() != "" {
		t.Errorf("manual ACME = %q, want empty", m.ACME())
	}
}

func TestACMEChallengeFor(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"cloudflare", "dnschallenge.provider=cloudflare"},
		{"manual", ""},
		{"unknown", ""},
	}
	for _, c := range cases {
		if got := ACMEChallengeFor(c.name, Config{}); got != c.want {
			t.Errorf("ACMEChallengeFor(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
