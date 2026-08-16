// Package auth implements the platform's own session layer and the OIDC
// integration against authentik (spec §15: the platform has no password
// database; sessions are issued after authentik authentication).
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Session is the platform session payload carried in a signed cookie.
type Session struct {
	UserID    string
	ExpiresAt time.Time
}

// ErrSessionInvalid is returned for malformed, tampered or expired tokens.
var ErrSessionInvalid = errors.New("auth: invalid session")

// SessionStore signs and verifies session cookies with HMAC-SHA256 keyed by
// SHA-256 of the configured secret. Sessions are stateless; revocation
// happens at the identity provider (authentik) per spec §4.
type SessionStore struct {
	name    string
	key     []byte
	ttl     time.Duration
	secure  bool
	now     func() time.Time
	oidcTTL time.Duration
}

// SessionStoreOptions configures a SessionStore.
type SessionStoreOptions struct {
	// Name is the session cookie name.
	Name   string
	Secret []byte
	TTL    time.Duration
	// Secure sets the Secure cookie attribute (require HTTPS).
	Secure bool
	// OIDCStateTTL bounds the OIDC authorization state cookie lifetime.
	OIDCStateTTL time.Duration
}

// NewSessionStore validates options and builds the signing key.
func NewSessionStore(opts SessionStoreOptions) (*SessionStore, error) {
	if len(opts.Secret) < 32 {
		return nil, errors.New("auth: session secret must be at least 32 bytes")
	}
	if opts.Name == "" {
		return nil, errors.New("auth: session cookie name must be set")
	}
	oidcTTL := opts.OIDCStateTTL
	if oidcTTL <= 0 {
		oidcTTL = 10 * time.Minute
	}
	key := sha256.Sum256(opts.Secret)
	return &SessionStore{
		name:    opts.Name,
		key:     key[:],
		ttl:     opts.TTL,
		secure:  opts.Secure,
		now:     time.Now,
		oidcTTL: oidcTTL,
	}, nil
}

// CookieName returns the session cookie name.
func (s *SessionStore) CookieName() string { return s.name }

// Issue creates a signed session token for the given user.
func (s *SessionStore) Issue(userID string) (string, error) {
	return s.encode(Session{UserID: userID, ExpiresAt: s.now().Add(s.ttl)})
}

// Validate checks the token's signature and expiry and returns the session.
func (s *SessionStore) Validate(token string) (*Session, error) {
	sess, err := s.decode(token)
	if err != nil {
		return nil, err
	}
	if !sess.ExpiresAt.After(s.now()) {
		return nil, ErrSessionInvalid
	}
	return sess, nil
}

// SetCookie writes the session token as an HttpOnly cookie.
func (s *SessionStore) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, s.Cookie(token, s.ttl))
}

// ClearCookie expires the session cookie.
func (s *SessionStore) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, s.Cookie("", -1))
}

// Cookie builds the session cookie for token with the given lifetime.
func (s *SessionStore) Cookie(token string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     s.name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge / time.Second),
	}
}

// OIDCState is the CSRF protection payload carried across the OIDC
// authorization round trip.
type OIDCState struct {
	State string `json:"s"`
	Nonce string `json:"n"`
}

// oidcStateCookieName is the cookie holding the OIDC state/nonce.
const oidcStateCookieName = "selfu_oidc_state"

// SetOIDCStateCookie stores the state+nonce pair in a short-lived cookie.
func (s *SessionStore) SetOIDCStateCookie(w http.ResponseWriter, st OIDCState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    v,
		Path:     "/api/v1/auth",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.oidcTTL / time.Second),
	})
	return nil
}

// GetOIDCStateCookie reads the state cookie.
func (s *SessionStore) GetOIDCStateCookie(r *http.Request) (OIDCState, error) {
	var st OIDCState
	c, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		return st, ErrSessionInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return st, ErrSessionInvalid
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, ErrSessionInvalid
	}
	if st.State == "" || st.Nonce == "" {
		return st, ErrSessionInvalid
	}
	return st, nil
}

// ClearOIDCStateCookie expires the state cookie.
func (s *SessionStore) ClearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/api/v1/auth",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

const sep = "."

func (s *SessionStore) encode(sess Session) (string, error) {
	payload, err := json.Marshal(sessionPayload{
		UserID: sess.UserID,
		Exp:    sess.ExpiresAt.Unix(),
	})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return p + sep + sig, nil
}

type sessionPayload struct {
	UserID string `json:"u"`
	Exp    int64  `json:"e"`
}

func (s *SessionStore) decode(token string) (*Session, error) {
	payloadB64, sigB64, ok := strings.Cut(token, sep)
	if !ok || payloadB64 == "" || sigB64 == "" {
		return nil, ErrSessionInvalid
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrSessionInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrSessionInvalid
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payloadB64))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrSessionInvalid
	}
	var p sessionPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, ErrSessionInvalid
	}
	if p.UserID == "" {
		return nil, ErrSessionInvalid
	}
	return &Session{UserID: p.UserID, ExpiresAt: time.Unix(p.Exp, 0)}, nil
}
