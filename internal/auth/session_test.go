package auth

import (
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SessionStore {
	t.Helper()
	s, err := NewSessionStore(SessionStoreOptions{
		Name:   "selfu_session",
		Secret: []byte(strings.Repeat("s", 32)),
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	return s
}

func TestSessionRoundTrip(t *testing.T) {
	s := newTestStore(t)
	tok, err := s.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sess, err := s.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sess.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", sess.UserID)
	}
}

func TestSessionRejectsTampering(t *testing.T) {
	s := newTestStore(t)
	tok, err := s.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	body, sig, ok := strings.Cut(tok, sep)
	if !ok {
		t.Fatal("token missing separator")
	}
	tampered := body + sep + flipLastByte(sig)
	if _, err := s.Validate(tampered); err == nil {
		t.Error("Validate(tampered signature) = nil, want error")
	}

	// Alter the payload (user id) without re-signing.
	other := base64URL(t, `{"u":"user-2","e":9999999999}`) + sep + sig
	if _, err := s.Validate(other); err == nil {
		t.Error("Validate(tampered payload) = nil, want error")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	tok, err := s.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	s.now = func() time.Time { return now.Add(2 * time.Hour) } // past 1h TTL
	if _, err := s.Validate(tok); err == nil {
		t.Error("Validate(expired) = nil, want error")
	}
}

func TestSessionRejectsGarbage(t *testing.T) {
	s := newTestStore(t)
	for _, tok := range []string{"", "a.b", "!!!!", "a.b.c"} {
		if _, err := s.Validate(tok); err == nil {
			t.Errorf("Validate(%q) = nil, want error", tok)
		}
	}
}

func TestNewSessionStoreRejectsWeakSecret(t *testing.T) {
	if _, err := NewSessionStore(SessionStoreOptions{Name: "x", Secret: []byte("short")}); err == nil {
		t.Error("NewSessionStore(short secret) = nil error, want error")
	}
}

func TestOIDCStateCookieRoundTrip(t *testing.T) {
	s := newTestStore(t)
	rr := newRecorder()
	if err := s.SetOIDCStateCookie(rr, OIDCState{State: "st", Nonce: "nn"}); err != nil {
		t.Fatalf("SetOIDCStateCookie: %v", err)
	}
	req := newRequest(rr.header.Get("Set-Cookie"))
	got, err := s.GetOIDCStateCookie(req)
	if err != nil {
		t.Fatalf("GetOIDCStateCookie: %v", err)
	}
	if got.State != "st" || got.Nonce != "nn" {
		t.Errorf("got %+v, want st/nn", got)
	}
}

func TestOIDCStateCookieMissing(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetOIDCStateCookie(newRequest("")); err == nil {
		t.Error("GetOIDCStateCookie(no cookie) = nil error, want error")
	}
}
