package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

type headerRecorder struct{ header http.Header }

func (h *headerRecorder) Header() http.Header         { return h.header }
func (h *headerRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (h *headerRecorder) WriteHeader(int)             {}

func newRecorder() *headerRecorder {
	return &headerRecorder{header: make(http.Header)}
}

// newRequest builds a request carrying the given raw Cookie header value.
func newRequest(cookieHeader string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://selfu.local/api/v1/auth/callback", nil)
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	return req
}

func base64URL(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func flipLastByte(s string) string {
	b := []byte(s)
	b[len(b)-1] ^= 0x01
	return string(b)
}
