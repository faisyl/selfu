package recon

import (
	"context"
	"log/slog"
	"testing"

	"selfu/internal/domain"
)

type fakeExistence struct {
	byType map[string]map[string]bool // resourceType -> externalID -> exists
}

func (f *fakeExistence) ResourceExists(_ context.Context, resourceType, externalID string) (bool, error) {
	if m, ok := f.byType[resourceType]; ok {
		return m[externalID], nil
	}
	return false, nil
}

// fakeReconStore is a minimal ExternalStore for the external sync test.
type fakeReconStore struct {
	resources []domain.ExternalResource
	observed  map[string]struct {
		status, hash, lastErr string
	}
}

func (f *fakeReconStore) ListExternalResourcesByProvider(_ context.Context, _ string) ([]domain.ExternalResource, error) {
	return f.resources, nil
}
func (f *fakeReconStore) SetExternalObserved(_ context.Context, id, status, observedHash, lastErr string) error {
	if f.observed == nil {
		f.observed = map[string]struct{ status, hash, lastErr string }{}
	}
	f.observed[id] = struct{ status, hash, lastErr string }{status, observedHash, lastErr}
	return nil
}

func TestSyncExternalActiveAndMissing(t *testing.T) {
	st := &fakeReconStore{resources: []domain.ExternalResource{
		{ID: "r1", ResourceType: domain.ResTypeAuthentikUser, ExternalID: "u1"},
		{ID: "r2", ResourceType: domain.ResTypeAuthentikGroup, ExternalID: "g-missing"},
	}}
	check := &fakeExistence{byType: map[string]map[string]bool{
		domain.ResTypeAuthentikUser:  {"u1": true},
		domain.ResTypeAuthentikGroup: {"g-missing": false},
	}}
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	if err := SyncExternal(context.Background(), st, check, "issuer", logger); err != nil {
		t.Fatalf("SyncExternal: %v", err)
	}
	if st.observed["r1"].status != domain.ExtActive {
		t.Errorf("r1 status = %q, want active", st.observed["r1"].status)
	}
	if st.observed["r2"].status != domain.ExtFailed {
		t.Errorf("r2 status = %q, want failed", st.observed["r2"].status)
	}
	if st.observed["r2"].lastErr == "" {
		t.Error("r2 should record a last_error")
	}
	if st.observed["r1"].hash == "" || st.observed["r2"].hash == "" {
		t.Error("observed hash should be recorded")
	}
}

// TestSyncExternalApplicationViaProvider: an application whose sibling
// provider exists is marked active even if the wrapper 404s (the documented
// authentik behaviour).
func TestSyncExternalApplicationViaProvider(t *testing.T) {
	inst := "instance-1"
	st := &fakeReconStore{resources: []domain.ExternalResource{
		{ID: "p", ResourceType: domain.ResTypeAuthentikProvider, PlatformObjectID: inst, ExternalID: "99"},
		{ID: "a", ResourceType: domain.ResTypeAuthentikApplication, PlatformObjectID: inst, ExternalID: "wrapper-404"},
	}}
	check := &fakeExistence{byType: map[string]map[string]bool{
		domain.ResTypeAuthentikProvider:    {"99": true},
		domain.ResTypeAuthentikApplication: {"wrapper-404": false},
	}}
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	if err := SyncExternal(context.Background(), st, check, "issuer", logger); err != nil {
		t.Fatalf("SyncExternal: %v", err)
	}
	if st.observed["a"].status != domain.ExtActive {
		t.Errorf("application status = %q, want active (checked via provider)", st.observed["a"].status)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
