package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"selfu/internal/domain"
	"selfu/internal/store"
)

// --- fakes ---------------------------------------------------------------

// fakeInvites is an in-memory InviteStore for the invite tests.
type fakeInvites struct {
	invites map[string]store.Invite // by id
	byHash  map[string]string       // token hash -> invite id
	expired int
}

func newFakeInvites() *fakeInvites {
	return &fakeInvites{invites: map[string]store.Invite{}, byHash: map[string]string{}}
}

func (f *fakeInvites) CreateInvite(_ context.Context, inv store.Invite) (store.Invite, error) {
	f.invites[inv.ID] = inv
	f.byHash[inv.TokenHash] = inv.ID
	return inv, nil
}

func (f *fakeInvites) ExpirePendingInvites(_ context.Context, orgID, userID string) error {
	for id, inv := range f.invites {
		if inv.OrganizationID == orgID && inv.UserID == userID && inv.AcceptedAt == nil {
			now := time.Now()
			inv.AcceptedAt = &now
			f.invites[id] = inv
			f.expired++
		}
	}
	return nil
}

func (f *fakeInvites) GetInviteByTokenHash(_ context.Context, tokenHash string) (store.Invite, error) {
	if id, ok := f.byHash[tokenHash]; ok {
		return f.invites[id], nil
	}
	return store.Invite{}, store.ErrNotFound
}

func (f *fakeInvites) ConsumeInvite(_ context.Context, id string) (store.Invite, error) {
	inv, ok := f.invites[id]
	if !ok {
		return store.Invite{}, store.ErrNotFound
	}
	if inv.AcceptedAt != nil || time.Now().After(inv.ExpiresAt) {
		return store.Invite{}, store.ErrConflict
	}
	now := time.Now()
	inv.AcceptedAt = &now
	f.invites[id] = inv
	return inv, nil
}

// fakePasswordSetter records SetUserPassword calls; fail simulates an
// authentik outage.
type fakePasswordSetter struct {
	calls []string // external pks
	fail  bool
}

func (f *fakePasswordSetter) SetUserPassword(_ context.Context, pk, _ string) error {
	if f.fail {
		return errors.New("authentik unavailable")
	}
	f.calls = append(f.calls, pk)
	return nil
}

// --- helpers --------------------------------------------------------------

func newInviteFixture(t *testing.T) (*onboardFixture, *fakeInvites, *fakePasswordSetter) {
	t.Helper()
	f := newOnboardFixture(t, false)
	invites := newFakeInvites()
	setter := &fakePasswordSetter{}
	f.h.d.Invites = invites
	f.h.d.PasswordSetter = setter
	return f, invites, setter
}

func postInvite(t *testing.T, f *onboardFixture, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/org-1/invites",
		strings.NewReader(body))
	if token != "" {
		req.AddCookie(&http.Cookie{Name: f.sessions.CookieName(), Value: token})
	}
	w := httptest.NewRecorder()
	f.h.BuildRouter().ServeHTTP(w, req)
	return w
}

type inviteRespBody struct {
	User   domain.User `json:"user"`
	Invite struct {
		ID        string    `json:"id"`
		Role      string    `json:"role"`
		ExpiresAt time.Time `json:"expires_at"`
		Token     string    `json:"token"`
	} `json:"invite"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeInvite(t *testing.T, w *httptest.ResponseRecorder) inviteRespBody {
	t.Helper()
	var body inviteRespBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (%s)", err, w.Body.String())
	}
	return body
}

// --- tests ----------------------------------------------------------------

func TestCreateInviteHappyPath(t *testing.T) {
	f, invites, setter := newInviteFixture(t)

	w := postInvite(t, f, f.token, `{"email":"Dana@Acme.test","display_name":"Dana"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("invite status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	body := decodeInvite(t, w)

	if body.User.Email != "dana@acme.test" || body.User.ID == "" {
		t.Errorf("user = %+v, want created dana@acme.test with id", body.User)
	}
	if body.Invite.Token == "" {
		t.Error("token must be present at issue time")
	}
	if body.Invite.Role != string(domain.RoleMember) {
		t.Errorf("role = %q, want member", body.Invite.Role)
	}
	if body.Invite.ExpiresAt.Before(time.Now().Add(inviteTTL - time.Hour)) {
		t.Errorf("expires_at = %v, want ~7 days out", body.Invite.ExpiresAt)
	}
	if len(invites.invites) != 1 {
		t.Fatalf("invites stored = %d, want 1", len(invites.invites))
	}
	stored := invites.invites[body.Invite.ID]
	if stored.TokenHash == body.Invite.Token || stored.TokenHash == "" {
		t.Error("raw token must never be stored; only its hash")
	}
	// No membership yet — access lands only on acceptance.
	if _, ok := f.idStore.members["org-1|"+body.User.ID]; ok {
		t.Error("invitee must not gain membership before accepting")
	}
	if len(setter.calls) != 0 {
		t.Errorf("password set calls = %v, want none at invite time", setter.calls)
	}
	foundAudit := false
	for _, e := range f.audit.events {
		if e.Action == "user.invited" && e.ResourceID == "org-1" && e.Details["email"] == "dana@acme.test" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Errorf("audit events %+v, want user.invited for dana@acme.test", f.audit.events)
	}
}

func TestCreateInviteReissueSupersedesPending(t *testing.T) {
	f, invites, _ := newInviteFixture(t)

	first := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))
	second := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))

	if first.Invite.Token == second.Invite.Token {
		t.Error("re-invite must mint a fresh token")
	}
	if invites.expired != 1 {
		t.Errorf("expired pending invites = %d, want 1 (old link superseded)", invites.expired)
	}
	old := invites.invites[first.Invite.ID]
	if old.AcceptedAt == nil {
		t.Error("superseded invite must be burned so it cannot be redeemed")
	}
}

func TestCreateInviteExistingMemberConflict(t *testing.T) {
	f, _, _ := newInviteFixture(t)
	first := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))
	f.idStore.members["org-1|"+first.User.ID] = domain.RoleMember

	w := postInvite(t, f, f.token, `{"email":"dana@acme.test"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s, want 409", w.Code, w.Body.String())
	}
	body := decodeInvite(t, w)
	if body.Error == nil || body.Error.Code != "conflict" {
		t.Errorf("error = %+v, want conflict", body.Error)
	}
}

func TestCreateInviteOwnerRoleRequiresOwnerActor(t *testing.T) {
	orgAdmin := domain.User{ID: "user-orgadmin", Email: "oa@x.test", Status: domain.UserStatusActive, IsAdmin: false}
	platformAdmin := domain.User{ID: "user-platform", Email: "pa@x.test", Status: domain.UserStatusActive, IsAdmin: true}
	users := &fakeUsers{byID: map[string]domain.User{orgAdmin.ID: orgAdmin, platformAdmin.ID: platformAdmin}}
	h, _, sessions, _ := newHandler(t, users)
	h.d.IdentityStore = func() *fakeOnboardIdentities {
		fs := newFakeOnboardIdentities()
		fs.members["org-1|"+orgAdmin.ID] = domain.RoleAdmin // org admin, not owner
		return fs
	}()
	h.d.Invites = newFakeInvites()
	h.d.PasswordSetter = &fakePasswordSetter{}
	fx := &onboardFixture{h: h, sessions: sessions}

	// An org admin (not owner) inviting with the owner role is denied...
	tokOrg, err := sessions.Issue(orgAdmin.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	w := postInvite(t, fx, tokOrg, `{"email":"dana@acme.test","role":"owner"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-owner inviting owner status = %d body=%s, want 403", w.Code, w.Body.String())
	}

	// ...but a platform admin superuser bypasses.
	tokPlat, err := sessions.Issue(platformAdmin.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	w = postInvite(t, fx, tokPlat, `{"email":"erin@acme.test","role":"owner"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("platform admin inviting owner status = %d body=%s, want 200", w.Code, w.Body.String())
	}
}

func TestAcceptInviteHappyPath(t *testing.T) {
	f, invites, setter := newInviteFixture(t)
	created := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))
	// Link the external identity the accept flow sets the password against.
	f.idStore.externals[created.User.ID] = domain.ExternalResource{
		ResourceType:     domain.ResTypeAuthentikUser,
		PlatformObjectID: created.User.ID,
		Provider:         "authentik",
		ExternalID:       "42",
		Status:           domain.ExtActive,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept",
		strings.NewReader(`{"token":"`+created.Invite.Token+`","password":"correct horse battery"}`))
	w := httptest.NewRecorder()
	f.h.BuildRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("accept status = %d body=%s, want 200", w.Code, w.Body.String())
	}

	if len(setter.calls) != 1 || setter.calls[0] != "42" {
		t.Errorf("password set calls = %v, want [42]", setter.calls)
	}
	if got := f.idStore.members["org-1|"+created.User.ID]; got != domain.RoleMember {
		t.Errorf("membership role after accept = %q, want member", got)
	}
	consumed := invites.invites[created.Invite.ID]
	if consumed.AcceptedAt == nil {
		t.Error("invite must be consumed on acceptance (single use)")
	}
	foundAudit := false
	for _, e := range f.audit.events {
		if e.Action == "user.activated" && e.ResourceID == created.User.ID {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Errorf("audit events %+v, want user.activated", f.audit.events)
	}
}

func TestAcceptInviteReplayRejected(t *testing.T) {
	f, invites, _ := newInviteFixture(t)
	created := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))
	f.idStore.externals[created.User.ID] = domain.ExternalResource{
		ResourceType: domain.ResTypeAuthentikUser, PlatformObjectID: created.User.ID,
		ExternalID: "42", Status: domain.ExtActive,
	}
	payload := `{"token":"` + created.Invite.Token + `","password":"correct horse battery"}`
	first := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept", strings.NewReader(payload))
	f.h.BuildRouter().ServeHTTP(httptest.NewRecorder(), first)
	if invites.invites[created.Invite.ID].AcceptedAt == nil {
		t.Fatal("first redemption must consume the invite")
	}

	replay := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	f.h.BuildRouter().ServeHTTP(rec, replay)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
}

func TestAcceptInviteBadTokenAndWeakPassword(t *testing.T) {
	f, _, _ := newInviteFixture(t)

	for name, payload := range map[string]string{
		"bad token":   `{"token":"nope","password":"correct horse battery"}`,
		"weak pass":   `{"token":"whatever","password":"short"}`,
		"missing all": `{}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept", strings.NewReader(payload))
		rec := httptest.NewRecorder()
		f.h.BuildRouter().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d body=%s, want 400", name, rec.Code, rec.Body.String())
		}
	}
}

func TestAcceptInviteSetterFailureDoesNotBurnToken(t *testing.T) {
	f, invites, setter := newInviteFixture(t)
	created := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))
	f.idStore.externals[created.User.ID] = domain.ExternalResource{
		ResourceType: domain.ResTypeAuthentikUser, PlatformObjectID: created.User.ID,
		ExternalID: "42", Status: domain.ExtActive,
	}
	payload := `{"token":"` + created.Invite.Token + `","password":"correct horse battery"}`

	setter.fail = true
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	f.h.BuildRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("setter-fail status = %d body=%s, want 502", rec.Code, rec.Body.String())
	}
	if invites.invites[created.Invite.ID].AcceptedAt != nil {
		t.Fatal("failed attempt must not consume the invite")
	}

	setter.fail = false
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept", strings.NewReader(payload))
	rec2 := httptest.NewRecorder()
	f.h.BuildRouter().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("retry after fix status = %d body=%s, want 200", rec2.Code, rec2.Body.String())
	}
	if len(f.idStore.users) != 1 {
		t.Errorf("users = %d, want 1", len(f.idStore.users))
	}
}

func TestAcceptInviteMissingExternalIdentityFailsClosed(t *testing.T) {
	f, invites, setter := newInviteFixture(t)
	created := decodeInvite(t, postInvite(t, f, f.token, `{"email":"dana@acme.test"}`))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/invites/accept",
		strings.NewReader(`{"token":"`+created.Invite.Token+`","password":"correct horse battery"}`))
	rec := httptest.NewRecorder()
	f.h.BuildRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s, want 503", rec.Code, rec.Body.String())
	}
	if setter.calls != nil {
		t.Errorf("password set calls = %v, want none", setter.calls)
	}
	if invites.invites[created.Invite.ID].AcceptedAt != nil {
		t.Error("invite must stay redeemable when no upstream identity exists")
	}
}
