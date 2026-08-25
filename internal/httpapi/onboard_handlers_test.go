package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"selfu/internal/chasquid"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// --- fakes ---------------------------------------------------------------

// fakeOnboardIdentities is an in-memory IdentityStore covering what the
// onboard-user handler needs; unlisted methods are inert.
type fakeOnboardIdentities struct {
	users      map[string]domain.User // by id
	emails     map[string]string      // email -> user id
	members    map[string]domain.OrgRole
	groups     map[string]domain.Group
	groupMemb  map[string]map[string]bool
	externals  map[string]domain.ExternalResource
	nextUserID int
}

func newFakeOnboardIdentities() *fakeOnboardIdentities {
	return &fakeOnboardIdentities{
		users:     map[string]domain.User{},
		emails:    map[string]string{},
		members:   map[string]domain.OrgRole{},
		groups:    map[string]domain.Group{},
		groupMemb: map[string]map[string]bool{},
		externals: map[string]domain.ExternalResource{},
	}
}

func (f *fakeOnboardIdentities) CreateOrganization(_ context.Context, o domain.Organization) (domain.Organization, error) {
	return o, nil
}
func (f *fakeOnboardIdentities) GetOrganizationByID(_ context.Context, _ string) (domain.Organization, error) {
	return domain.Organization{}, store.ErrNotFound
}
func (f *fakeOnboardIdentities) ListOrganizations(_ context.Context, _ int) ([]domain.Organization, error) {
	return nil, nil
}
func (f *fakeOnboardIdentities) DeleteOrganization(_ context.Context, _ string) error { return nil }

func (f *fakeOnboardIdentities) SetMembership(_ context.Context, orgID, userID string, role domain.OrgRole) (domain.OrganizationMembership, error) {
	f.members[orgID+"|"+userID] = role
	return domain.OrganizationMembership{
		ID: "m-" + orgID + "-" + userID, OrganizationID: orgID,
		UserID: userID, Role: role,
	}, nil
}
func (f *fakeOnboardIdentities) GetMembershipRole(_ context.Context, orgID, userID string) (domain.OrgRole, error) {
	if role, ok := f.members[orgID+"|"+userID]; ok {
		return role, nil
	}
	return "", store.ErrNotFound
}
func (f *fakeOnboardIdentities) ListMemberships(_ context.Context, _ string) ([]store.Member, error) {
	return nil, nil
}
func (f *fakeOnboardIdentities) RemoveMembership(_ context.Context, _, _ string) error       { return nil }
func (f *fakeOnboardIdentities) RemoveAllMemberships(_ context.Context, _ string) error      { return nil }
func (f *fakeOnboardIdentities) RemoveAllGroupMemberships(_ context.Context, _ string) error { return nil }

func (f *fakeOnboardIdentities) CreateGroup(_ context.Context, g domain.Group) (domain.Group, error) {
	g.ID = "g-new"
	f.groups[g.ID] = g
	return g, nil
}
func (f *fakeOnboardIdentities) GetGroupByID(_ context.Context, id string) (domain.Group, error) {
	if g, ok := f.groups[id]; ok {
		return g, nil
	}
	return domain.Group{}, store.ErrNotFound
}
func (f *fakeOnboardIdentities) ListGroupsByOrg(_ context.Context, _ string) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeOnboardIdentities) DeleteGroup(_ context.Context, _ string) error { return nil }
func (f *fakeOnboardIdentities) AddGroupMember(_ context.Context, groupID, userID string) error {
	if f.groupMemb[groupID] == nil {
		f.groupMemb[groupID] = map[string]bool{}
	}
	f.groupMemb[groupID][userID] = true
	return nil
}
func (f *fakeOnboardIdentities) RemoveGroupMember(_ context.Context, _, _ string) error { return nil }
func (f *fakeOnboardIdentities) ListGroupMembers(_ context.Context, groupID string) ([]store.GroupMember, error) {
	var out []store.GroupMember
	for uid := range f.groupMemb[groupID] {
		out = append(out, store.GroupMember{UserID: uid})
	}
	return out, nil
}

func (f *fakeOnboardIdentities) GetUserByEmail(_ context.Context, email string) (domain.User, error) {
	if id, ok := f.emails[email]; ok {
		return f.users[id], nil
	}
	return domain.User{}, store.ErrNotFound
}
func (f *fakeOnboardIdentities) CreateUser(_ context.Context, email, displayName, authProvider, authIdentityID string) (domain.User, error) {
	f.nextUserID++
	u := domain.User{
		ID: "u-" + string(rune('0'+f.nextUserID)), Email: email,
		DisplayName: displayName, Status: domain.UserStatusActive,
		AuthProvider: authProvider, AuthIdentityID: authIdentityID,
	}
	f.users[u.ID] = u
	f.emails[u.Email] = u.ID
	return u, nil
}
func (f *fakeOnboardIdentities) SetUserStatus(_ context.Context, _ string, _ domain.UserStatus) error {
	return nil
}
func (f *fakeOnboardIdentities) SetUserAdmin(_ context.Context, _ string, _ bool) error { return nil }
func (f *fakeOnboardIdentities) ListUsers(_ context.Context, _ int) ([]domain.User, error) {
	return nil, nil
}

func (f *fakeOnboardIdentities) UpsertExternalResource(_ context.Context, res domain.ExternalResource) (domain.ExternalResource, error) {
	res.ID = "ext-" + res.PlatformObjectID
	f.externals[res.PlatformObjectID] = res
	return res, nil
}
func (f *fakeOnboardIdentities) GetExternalResource(_ context.Context, _, platformObjectID string) (domain.ExternalResource, error) {
	if res, ok := f.externals[platformObjectID]; ok {
		return res, nil
	}
	return domain.ExternalResource{}, store.ErrNotFound
}
func (f *fakeOnboardIdentities) SetExternalStatus(_ context.Context, _, _, _ string) error { return nil }

// fakeMailStore is an in-memory MailStore for the onboard-user tests.
type fakeMailStore struct {
	mailDomains     map[string]domain.MailDomain // domain id -> mail domain
	identities      map[string]domain.MailIdentity
	byAddress       map[string]string
	credentials     []string
	policies        int
	aliasesByDomain map[string][]domain.MailAlias
}

func newFakeMailStore() *fakeMailStore {
	return &fakeMailStore{
		mailDomains: map[string]domain.MailDomain{},
		identities:  map[string]domain.MailIdentity{},
		byAddress:   map[string]string{},
	}
}

func (f *fakeMailStore) CreateMailDomain(_ context.Context, domainID string) (domain.MailDomain, error) {
	md := domain.MailDomain{ID: "md-" + domainID, DomainID: domainID, Status: domain.MailDomainProvisioning}
	f.mailDomains[domainID] = md
	return md, nil
}
func (f *fakeMailStore) GetMailDomainByDomainID(_ context.Context, domainID string) (domain.MailDomain, error) {
	if md, ok := f.mailDomains[domainID]; ok {
		return md, nil
	}
	return domain.MailDomain{}, store.ErrNotFound
}
func (f *fakeMailStore) SetMailDomainStatus(_ context.Context, id string, status domain.MailDomainStatus) error {
	for did, md := range f.mailDomains {
		if md.ID == id {
			md.Status = status
			f.mailDomains[did] = md
		}
	}
	return nil
}
func (f *fakeMailStore) SetMailDomainDKIM(_ context.Context, _, _, _ string) error { return nil }

func (f *fakeMailStore) CreateMailIdentity(_ context.Context, m domain.MailIdentity) (domain.MailIdentity, error) {
	if _, taken := f.byAddress[m.Address]; taken {
		return domain.MailIdentity{}, store.ErrConflict
	}
	m.ID = "mi-" + m.Address
	f.identities[m.ID] = m
	f.byAddress[m.Address] = m.ID
	return m, nil
}
func (f *fakeMailStore) GetMailIdentity(_ context.Context, id string) (domain.MailIdentity, error) {
	if m, ok := f.identities[id]; ok {
		return m, nil
	}
	return domain.MailIdentity{}, store.ErrNotFound
}
func (f *fakeMailStore) GetMailIdentityByAddress(_ context.Context, address string) (domain.MailIdentity, error) {
	if id, ok := f.byAddress[address]; ok {
		return f.identities[id], nil
	}
	return domain.MailIdentity{}, store.ErrNotFound
}
func (f *fakeMailStore) ListMailIdentitiesByDomain(_ context.Context, domainID string) ([]domain.MailIdentity, error) {
	var out []domain.MailIdentity
	for _, m := range f.identities {
		if m.DomainID == domainID {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMailStore) SetMailIdentityStatus(_ context.Context, id, status string) error {
	m := f.identities[id]
	m.Status = status
	f.identities[id] = m
	return nil
}
func (f *fakeMailStore) CreateMailCredential(_ context.Context, c domain.MailCredential) (domain.MailCredential, error) {
	c.ID = "cred-" + string(rune('0'+len(f.credentials)))
	c.Status = "active"
	f.credentials = append(f.credentials, c.ID)
	return c, nil
}
func (f *fakeMailStore) RevokeCredentialsByIdentity(_ context.Context, _ string) error { return nil }

func (f *fakeMailStore) CreateMailAlias(_ context.Context, a domain.MailAlias) (domain.MailAlias, error) {
	return a, nil
}
func (f *fakeMailStore) GetMailAliasByAddress(_ context.Context, _ string) (domain.MailAlias, error) {
	return domain.MailAlias{}, store.ErrNotFound
}
func (f *fakeMailStore) ListMailAliasesByDomain(_ context.Context, domainID string) ([]domain.MailAlias, error) {
	return f.aliasesByDomain[domainID], nil
}
func (f *fakeMailStore) UpdateMailAliasDestinations(_ context.Context, _ string, _ []string) error {
	return nil
}
func (f *fakeMailStore) ListMailIdentitiesByUsers(_ context.Context, _ string, _ []string) ([]domain.MailIdentity, error) {
	return nil, nil
}
func (f *fakeMailStore) DeleteMailAlias(_ context.Context, _ string) error { return nil }
func (f *fakeMailStore) CreateMailSubmissionPolicy(_ context.Context, _ domain.MailSubmissionPolicy) error {
	f.policies++
	return nil
}
func (f *fakeMailStore) ValidateAliasDestinations(_ context.Context, _ string, _ []string) error {
	return nil
}

// fakeMTA records chasquid users added through the provision seam.
type fakeMTA struct {
	added []string
}

func (f *fakeMTA) AddUser(_ context.Context, address string, _ chasquid.Secret) error {
	f.added = append(f.added, address)
	return nil
}
func (f *fakeMTA) EnsureSenderPolicy(_ context.Context, _ string, _ []string) error { return nil }
func (f *fakeMTA) ChangePassword(_ context.Context, _ string, _ chasquid.Secret) error {
	return nil
}

// onboardFixture wires a handler with admin actor, one org-scoped verified
// domain and (optionally) its active mail domain.
type onboardFixture struct {
	h          *Handler
	sessions   interface{ CookieName() string }
	token      string
	idStore    *fakeOnboardIdentities
	mailStore  *fakeMailStore
	mta        *fakeMTA
	audit      *fakeAudit
}

func newOnboardFixture(t *testing.T, withMail bool) *onboardFixture {
	t.Helper()
	admin := domain.User{ID: "user-admin", Email: "a@x.test", Status: domain.UserStatusActive, IsAdmin: true}
	users := &fakeUsers{byID: map[string]domain.User{admin.ID: admin}}
	h, audit, sessions, _ := newHandler(t, users)

	idStore := newFakeOnboardIdentities()
	idStore.members["org-1|"+admin.ID] = domain.RoleOwner
	domains := &fakeDomainStore{domains: map[string]domain.Domain{
		"dom-1": {ID: "dom-1", OrganizationID: "org-1", FQDN: "example.com", Status: domain.DomainVerified},
	}}
	mailStore := newFakeMailStore()
	if withMail {
		mailStore.mailDomains["dom-1"] = domain.MailDomain{ID: "md-dom-1", DomainID: "dom-1", Status: domain.MailDomainActive}
	}
	mta := &fakeMTA{}
	h.d.IdentityStore = idStore
	h.d.DomainStore = domains
	h.d.MailStore = mailStore
	h.d.MailProvision = mta

	tok, err := sessions.Issue(admin.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return &onboardFixture{h: h, sessions: sessions, token: tok, idStore: idStore, mailStore: mailStore, mta: mta, audit: audit}
}

func postOnboard(t *testing.T, f *onboardFixture, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/org-1/onboard-user",
		strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: f.sessions.CookieName(), Value: f.token})
	w := httptest.NewRecorder()
	router(t, f.h).ServeHTTP(w, req)
	return w
}

type onboardRespBody struct {
	User         domain.User                   `json:"user"`
	Membership   domain.OrganizationMembership `json:"membership"`
	Group        *domain.Group                 `json:"group"`
	MailIdentity *domain.MailIdentity          `json:"mail_identity"`
	Credential   *struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"credential"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeOnboard(t *testing.T, w *httptest.ResponseRecorder) onboardRespBody {
	t.Helper()
	var body onboardRespBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (%s)", err, w.Body.String())
	}
	return body
}

// --- tests ----------------------------------------------------------------

func TestOnboardUserHappyPath(t *testing.T) {
	f := newOnboardFixture(t, true)
	f.idStore.groups["g-1"] = domain.Group{ID: "g-1", OrganizationID: "org-1", Name: "Eng"}

	w := postOnboard(t, f, `{"email":"dana@acme.test","display_name":"Dana","group_id":"g-1","provision_mailbox":true,"local_part":"dana"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("onboard status = %d body=%s, want 200", w.Code, w.Body.String())
	}
	body := decodeOnboard(t, w)

	if body.User.Email != "dana@acme.test" || body.User.ID == "" {
		t.Errorf("user = %+v, want created dana@acme.test with id", body.User)
	}
	if body.Membership.Role != domain.RoleMember {
		t.Errorf("membership role = %q, want member", body.Membership.Role)
	}
	if body.Group == nil || body.Group.ID != "g-1" {
		t.Errorf("group = %+v, want g-1", body.Group)
	}
	if body.MailIdentity == nil || body.MailIdentity.Address != "dana@example.com" {
		t.Errorf("mail identity = %+v, want dana@example.com", body.MailIdentity)
	}
	if body.Credential == nil || body.Credential.Secret == "" {
		t.Errorf("credential secret must be present on first onboarding: %+v", body.Credential)
	}
	if len(f.mta.added) != 1 || f.mta.added[0] != "dana@example.com" {
		t.Errorf("mta added = %v, want [dana@example.com]", f.mta.added)
	}
	if got := f.idStore.members["org-1|"+body.User.ID]; got != domain.RoleMember {
		t.Errorf("stored membership role = %q, want member", got)
	}
	if !f.idStore.groupMemb["g-1"][body.User.ID] {
		t.Error("user not added to group g-1")
	}
	foundAudit := false
	for _, e := range f.audit.events {
		if e.Action == "user.onboarded" && e.ResourceID == "org-1" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Errorf("audit events %v, want user.onboarded", f.audit.events)
	}
}

func TestOnboardUserIdempotentRerun(t *testing.T) {
	f := newOnboardFixture(t, true)
	payload := `{"email":"dana@acme.test","display_name":"Dana","provision_mailbox":true}`

	first := decodeOnboard(t, postOnboard(t, f, payload))
	second := decodeOnboard(t, postOnboard(t, f, payload))

	if second.User.ID != first.User.ID {
		t.Errorf("rerun created duplicate user %s, want %s", second.User.ID, first.User.ID)
	}
	if len(f.idStore.users) != 1 {
		t.Errorf("users = %d, want 1", len(f.idStore.users))
	}
	if len(f.mailStore.identities) != 1 {
		t.Errorf("mail identities = %d, want 1", len(f.mailStore.identities))
	}
	if len(f.mailStore.credentials) != 1 {
		t.Errorf("credentials minted = %d, want 1 (no fresh secret on rerun)", len(f.mailStore.credentials))
	}
	if second.MailIdentity == nil || second.MailIdentity.Address != "dana@example.com" {
		t.Errorf("rerun mail identity = %+v, want existing dana@example.com", second.MailIdentity)
	}
	if second.Credential != nil {
		t.Errorf("rerun credential = %+v, want omitted", second.Credential)
	}
	if len(f.mta.added) != 1 {
		t.Errorf("mta AddUser calls = %d, want 1", len(f.mta.added))
	}
}

func TestOnboardUserMissingVerifiedMailDomain(t *testing.T) {
	f := newOnboardFixture(t, false)

	w := postOnboard(t, f, `{"email":"dana@acme.test","provision_mailbox":true}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s, want 422", w.Code, w.Body.String())
	}
	body := decodeOnboard(t, w)
	if body.Error == nil || body.Error.Code != "no_mail_domain" {
		t.Errorf("error = %+v, want no_mail_domain", body.Error)
	}
	// No partial state: nothing was created before the clean failure.
	if len(f.idStore.users) != 0 {
		t.Errorf("users created = %d, want 0", len(f.idStore.users))
	}
}

func TestOnboardUserMemberForbidden(t *testing.T) {
	admin := domain.User{ID: "user-admin", Email: "a@x.test", Status: domain.UserStatusActive, IsAdmin: true}
	member := domain.User{ID: "user-member", Email: "m@x.test", Status: domain.UserStatusActive, IsAdmin: false}
	users := &fakeUsers{byID: map[string]domain.User{admin.ID: admin, member.ID: member}}
	h, _, sessions, _ := newHandler(t, users)
	h.d.IdentityStore = func() *fakeOnboardIdentities {
		fs := newFakeOnboardIdentities()
		fs.members["org-1|"+member.ID] = domain.RoleMember
		return fs
	}()

	tok, err := sessions.Issue(member.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/org-1/onboard-user",
		strings.NewReader(`{"email":"dana@acme.test"}`))
	req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member onboard status = %d, want 403", w.Code)
	}
}
