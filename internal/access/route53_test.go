package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	"selfu/internal/dns"
)

// fakeRoute53 records every change-batch and serves canned zone lookups.
type fakeRoute53 struct {
	batches   map[string][]Route53ChangeBatch // bare zone id -> batches
	zones     map[string]string               // domain (lower, no dot) -> bare zone id
	zoneNames map[string]string               // bare zone id -> zone name
	getErr    error
	findErr   error
}

func (f *fakeRoute53) ChangeRRSet(_ context.Context, hostedZoneID string, batch Route53ChangeBatch) error {
	if f.batches == nil {
		f.batches = map[string][]Route53ChangeBatch{}
	}
	f.batches[hostedZoneID] = append(f.batches[hostedZoneID], batch)
	return nil
}

func (f *fakeRoute53) GetHostedZone(_ context.Context, hostedZoneID string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	name, ok := f.zoneNames[hostedZoneID]
	if !ok {
		return "", errors.New("no such hosted zone")
	}
	return name, nil
}

func (f *fakeRoute53) FindHostedZoneID(_ context.Context, domain string) (string, error) {
	if f.findErr != nil {
		return "", f.findErr
	}
	id, ok := f.zones[strings.ToLower(strings.TrimSuffix(domain, "."))]
	if !ok {
		return "", errors.New("zone not found")
	}
	return id, nil
}

func newTestRoute53(api *fakeRoute53) *Route53 {
	return NewRoute53(
		Config{ZoneID: "Z123", AWSAccessKeyID: "AKIA", AWSSecretAccessKey: "s", AWSRegion: "us-east-1"},
		WithRoute53Client(api),
	)
}

func TestNewDispatchRoute53(t *testing.T) {
	p, err := New("route53", Config{ZoneID: "Z123"})
	if err != nil {
		t.Fatalf("New(route53): %v", err)
	}
	if p.Name() != "route53" {
		t.Errorf("route53 name = %q", p.Name())
	}
	if _, ok := p.DNS().(*Route53DNS); !ok {
		t.Errorf("route53 DNS = %T, want *Route53DNS", p.DNS())
	}
	if p.ACME() != "dnschallenge.provider=route53" {
		t.Errorf("route53 ACME = %q", p.ACME())
	}
	if ar, ok := p.(AutomatedReporter); !ok || !ar.Automated() {
		t.Error("route53 should report automated=true")
	}

	if _, err := New("manual", Config{}); err != nil {
		t.Fatalf("New(manual): %v", err)
	}
	if _, err := New("still-nope", Config{}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("New(still-nope) err = %v, want ErrUnknownProvider", err)
	}
	if got := ACMEChallengeFor("route53", Config{}); got != "dnschallenge.provider=route53" {
		t.Errorf("ACMEChallengeFor(route53) = %q", got)
	}
}

func TestRoute53SetTXTBuildsChangeBatch(t *testing.T) {
	api := &fakeRoute53{}
	p := newTestRoute53(api)

	if err := p.DNS().SetTXT(context.Background(), "_platform-verification.example.com", "platform=abc"); err != nil {
		t.Fatalf("SetTXT: %v", err)
	}
	batches := api.batches["Z123"]
	if len(batches) != 1 || len(batches[0].Changes) != 1 {
		t.Fatalf("batches = %+v, want one change-batch with one change", batches)
	}
	ch := batches[0].Changes[0]
	if ch.Action != "UPSERT" {
		t.Errorf("action = %q, want UPSERT", ch.Action)
	}
	rr := ch.ResourceRecordSet
	if rr.Name != "_platform-verification.example.com." {
		t.Errorf("name = %q, want trailing-dot FQDN", rr.Name)
	}
	if rr.Type != "TXT" {
		t.Errorf("type = %q, want TXT", rr.Type)
	}
	if rr.TTL != route53TTL {
		t.Errorf("ttl = %d, want %d", rr.TTL, route53TTL)
	}
	if len(rr.ResourceRecords) != 1 || rr.ResourceRecords[0].Value != `"platform=abc"` {
		t.Errorf("values = %+v, want quoted \"platform=abc\"", rr.ResourceRecords)
	}
}

func TestRoute53RemoveTXTBuildsDelete(t *testing.T) {
	api := &fakeRoute53{}
	p := newTestRoute53(api)

	if err := p.DNS().RemoveTXT(context.Background(), "_x.example.com", "v"); err != nil {
		t.Fatalf("RemoveTXT: %v", err)
	}
	ch := api.batches["Z123"][0].Changes[0]
	if ch.Action != "DELETE" {
		t.Errorf("action = %q, want DELETE", ch.Action)
	}
	if ch.ResourceRecordSet.Type != "TXT" || ch.ResourceRecordSet.ResourceRecords[0].Value != `"v"` {
		t.Errorf("rrset = %+v, want DELETE of quoted TXT v", ch.ResourceRecordSet)
	}
}

func TestRoute53AddrRecords(t *testing.T) {
	api := &fakeRoute53{}
	p := newTestRoute53(api)

	if err := p.DNS().SetAddr(context.Background(), "app.example.com.", "203.0.113.7"); err != nil {
		t.Fatalf("SetAddr: %v", err)
	}
	ch := api.batches["Z123"][0].Changes[0]
	if ch.Action != "UPSERT" || ch.ResourceRecordSet.Type != "A" {
		t.Errorf("set addr change = %+v, want UPSERT A", ch)
	}
	if ch.ResourceRecordSet.Name != "app.example.com." {
		t.Errorf("name = %q, want normalized trailing dot", ch.ResourceRecordSet.Name)
	}
	if ch.ResourceRecordSet.ResourceRecords[0].Value != "203.0.113.7" {
		t.Errorf("A value = %+v, want unquoted ip", ch.ResourceRecordSet.ResourceRecords)
	}

	if err := p.DNS().RemoveAddr(context.Background(), "app.example.com", "203.0.113.7"); err != nil {
		t.Fatalf("RemoveAddr: %v", err)
	}
	ch = api.batches["Z123"][1].Changes[0]
	if ch.Action != "DELETE" || ch.ResourceRecordSet.Type != "A" {
		t.Errorf("remove addr change = %+v, want DELETE A", ch)
	}
}

func TestRoute53ResolveZoneAndValidate(t *testing.T) {
	api := &fakeRoute53{
		zones:     map[string]string{"example.com": "Z123"},
		zoneNames: map[string]string{"Z123": "example.com."},
	}
	p := newTestRoute53(api)

	zone, err := p.ResolveZone(context.Background(), "Example.COM")
	if err != nil {
		t.Fatalf("ResolveZone: %v", err)
	}
	if zone != "Z123" {
		t.Errorf("zone = %q, want Z123", zone)
	}
	if err := p.Validate(context.Background()); err != nil {
		t.Errorf("Validate ok case: %v", err)
	}

	api.getErr = errors.New("credentials rejected")
	if err := p.Validate(context.Background()); err == nil {
		t.Error("Validate should fail when the zone is unreachable")
	}
	api.getErr = nil
	api.findErr = errors.New("zone not found")
	if _, err := p.ResolveZone(context.Background(), "other.com"); err == nil {
		t.Error("ResolveZone should surface lookup failure")
	}
}

func TestManualReportsInstructionsAndNotAutomated(t *testing.T) {
	m := NewManual()
	if ar, ok := any(m).(AutomatedReporter); !ok || ar.Automated() {
		t.Error("manual must report automated=false")
	}
	err := m.DNS().SetTXT(context.Background(), "_x.example.com", "v")
	if !errors.Is(err, dns.ErrManual) {
		t.Fatalf("SetTXT err = %v, want dns.ErrManual wrapped", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "_x.example.com") || !strings.Contains(msg, `"v"`) {
		t.Errorf("instructions missing record name/value: %s", msg)
	}
	if err := m.DNS().SetAddr(context.Background(), "a.example.com", "1.2.3.4"); !errors.Is(err, dns.ErrManual) {
		t.Errorf("SetAddr err = %v, want dns.ErrManual wrapped", err)
	}
	if err := m.Validate(context.Background()); err != nil {
		t.Errorf("manual Validate: %v", err)
	}
	if m.ACME() != "" {
		t.Errorf("manual ACME = %q, want empty", m.ACME())
	}
}
