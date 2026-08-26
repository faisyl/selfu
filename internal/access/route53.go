package access

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"selfu/internal/dns"
)

// route53API is the injected AWS Route 53 seam. Production uses the SigV4
// REST client below; tests supply a fake so no live AWS calls ever happen.
// Zone ids are bare ("Z123ABC"), without the /hostedzone/ prefix.
type route53API interface {
	// ChangeRRSet submits a change-batch against the hosted zone.
	ChangeRRSet(ctx context.Context, hostedZoneID string, batch Route53ChangeBatch) error
	// GetHostedZone returns the zone name (trailing dot included) or an
	// error when the zone is not reachable with the configured credentials.
	GetHostedZone(ctx context.Context, hostedZoneID string) (string, error)
	// FindHostedZoneID resolves the hosted-zone id whose name matches the
	// domain (case-insensitive, trailing dot ignored).
	FindHostedZoneID(ctx context.Context, domain string) (string, error)
}

// Route53 is the AWS Route 53 external-access provider: it publishes DNS
// records (TXT verification + A records) as Route 53 change-batches and
// emits a Traefik DNS-01 ACME resolver using lego's route53 provider.
//
// Credentials come from access.Config (aws_* fields) and fall back to the
// standard AWS environment variables AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN and AWS_REGION (default
// us-east-1). The hosted zone id reuses Config.ZoneID.
type Route53 struct {
	dns  *Route53DNS
	cfg  Config
	api  route53API
	acme string
}

// NewRoute53 builds the Route 53 access provider. Tests inject a fake AWS
// seam via WithRoute53Client.
func NewRoute53(cfg Config, opts ...Option) *Route53 {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	api := o.route53
	if api == nil {
		api = newAWSRoute53Client(cfg)
	}
	return &Route53{
		dns:  &Route53DNS{api: api, zoneID: cfg.ZoneID},
		cfg:  cfg,
		api:  api,
		acme: ACMEChallengeFor("route53", cfg),
	}
}

// Name matches the "route53" provider identifier.
func (r *Route53) Name() string { return "route53" }

// DNS is the Route 53 DNS surface.
func (r *Route53) DNS() dns.Provider { return r.dns }

// ACME is the DNS-01 resolver configuration for Traefik.
func (r *Route53) ACME() string { return r.acme }

// Automated reports that this provider writes DNS records itself.
func (r *Route53) Automated() bool { return true }

// Validate checks the configured hosted zone is reachable with the
// configured credentials.
func (r *Route53) Validate(ctx context.Context) error {
	if _, err := r.api.GetHostedZone(ctx, r.cfg.ZoneID); err != nil {
		return err
	}
	return nil
}

// ResolveZone looks up the Route 53 hosted-zone id for the domain using
// the configured credentials.
func (r *Route53) ResolveZone(ctx context.Context, domain string) (string, error) {
	return r.api.FindHostedZoneID(ctx, domain)
}

// Route53DNS provisions records in a fixed hosted zone through the
// injected AWS seam. It satisfies dns.Provider.
type Route53DNS struct {
	api    route53API
	zoneID string
}

// Name matches the "route53" provider identifier.
func (d *Route53DNS) Name() string { return "route53" }

// SetTXT ensures a TXT record holds value at fqdn (UPSERT).
func (d *Route53DNS) SetTXT(ctx context.Context, fqdn, value string) error {
	return d.change(ctx, "UPSERT", fqdn, "TXT", value)
}

// RemoveTXT deletes the TXT record holding value at fqdn.
func (d *Route53DNS) RemoveTXT(ctx context.Context, fqdn, value string) error {
	return d.change(ctx, "DELETE", fqdn, "TXT", value)
}

// SetAddr ensures an A record points fqdn at ip (UPSERT).
func (d *Route53DNS) SetAddr(ctx context.Context, fqdn, ip string) error {
	return d.change(ctx, "UPSERT", fqdn, "A", ip)
}

// RemoveAddr removes the A record pointing fqdn at ip.
func (d *Route53DNS) RemoveAddr(ctx context.Context, fqdn, ip string) error {
	return d.change(ctx, "DELETE", fqdn, "A", ip)
}

func (d *Route53DNS) change(ctx context.Context, action, fqdn, rrtype, value string) error {
	batch := Route53ChangeBatch{
		Comment: "managed by selfu",
		Changes: []Route53Change{newRoute53Change(action, fqdn, rrtype, value)},
	}
	return d.api.ChangeRRSet(ctx, d.zoneID, batch)
}

const route53TTL = 300

// newRoute53Change builds one change-batch entry. TXT values are quoted
// per the Route 53 wire format; names are FQDN-normalized with a trailing
// dot.
func newRoute53Change(action, name, rrtype, value string) Route53Change {
	v := value
	if rrtype == "TXT" {
		v = `"` + value + `"`
	}
	return Route53Change{
		Action: action,
		ResourceRecordSet: Route53ResourceRecordSet{
			Name:            ensureTrailingDot(name),
			Type:            rrtype,
			TTL:             route53TTL,
			ResourceRecords: []Route53ResourceRecord{{Value: v}},
		},
	}
}

func ensureTrailingDot(name string) string {
	return strings.TrimSuffix(name, ".") + "."
}

// Route53ChangeBatch mirrors the Route 53 ChangeResourceRecordSets
// request shape (JSON form used by the injected seam; the REST client
// serializes the same structure to XML).
type Route53ChangeBatch struct {
	Comment string          `json:"comment,omitempty"`
	Changes []Route53Change `json:"changes"`
}

// Route53Change is a single UPSERT/DELETE of one resource record set.
type Route53Change struct {
	Action            string                   `json:"action"`
	ResourceRecordSet Route53ResourceRecordSet `json:"resource_record_set"`
}

// Route53ResourceRecordSet is the RRSet touched by a change.
type Route53ResourceRecordSet struct {
	Name            string                  `json:"name"`
	Type            string                  `json:"type"`
	TTL             int64                   `json:"ttl"`
	ResourceRecords []Route53ResourceRecord `json:"resource_records,omitempty"`
}

// Route53ResourceRecord is one record value inside an RRSet.
type Route53ResourceRecord struct {
	Value string `json:"value"`
}

// --- production AWS client (SigV4-signed REST, SDK-free) ------------------

type awsRoute53Client struct {
	accessKey    string
	secretKey    string
	sessionToken string
	region       string
	http         *http.Client
}

// newAWSRoute53Client builds the real AWS seam from access.Config with
// fallback to the standard AWS_* environment variables.
func newAWSRoute53Client(cfg Config) *awsRoute53Client {
	ak, sk, st := cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSSessionToken
	if ak == "" {
		ak = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if sk == "" {
		sk = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if st == "" {
		st = os.Getenv("AWS_SESSION_TOKEN")
	}
	region := cfg.AWSRegion
	if region == "" {
		if region = os.Getenv("AWS_REGION"); region == "" {
			region = "us-east-1" // Route 53 is a global service
		}
	}
	return &awsRoute53Client{
		accessKey: ak, secretKey: sk, sessionToken: st, region: region,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *awsRoute53Client) ChangeRRSet(ctx context.Context, hostedZoneID string, batch Route53ChangeBatch) error {
	body, err := xml.Marshal(route53XMLChangeBatch(batch))
	if err != nil {
		return err
	}
	endpoint := "https://route53.amazonaws.com/2013-04-01/hostedzone/" +
		url.PathEscape(bareZoneID(hostedZoneID)) + "/rrset"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml")
	c.sign(req, body)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("route53 change-batch: %w", decodeXMLError(resp.Body, resp.StatusCode))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *awsRoute53Client) GetHostedZone(ctx context.Context, hostedZoneID string) (string, error) {
	endpoint := "https://route53.amazonaws.com/2013-04-01/hostedzone/" +
		url.PathEscape(bareZoneID(hostedZoneID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	c.sign(req, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("route53 get-hosted-zone %s: %w",
			hostedZoneID, decodeXMLError(resp.Body, resp.StatusCode))
	}
	var out struct {
		HostedZone struct {
			Name string `xml:"Name"`
		} `xml:"HostedZone"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.HostedZone.Name, nil
}

func (c *awsRoute53Client) FindHostedZoneID(ctx context.Context, domain string) (string, error) {
	q := url.Values{}
	q.Set("dnsname", strings.TrimSuffix(domain, "."))
	q.Set("maxitems", "100")
	endpoint := "https://route53.amazonaws.com/2013-04-01/hostedzonesbyname?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	c.sign(req, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("route53 list-hosted-zones-by-name: %w",
			decodeXMLError(resp.Body, resp.StatusCode))
	}
	var out struct {
		Zones []struct {
			ID   string `xml:"Id"`
			Name string `xml:"Name"`
		} `xml:"HostedZones>HostedZone"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	want := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, z := range out.Zones {
		if strings.ToLower(strings.TrimSuffix(z.Name, ".")) == want {
			return bareZoneID(z.ID), nil
		}
	}
	return "", fmt.Errorf("no route53 hosted zone found for %s", domain)
}

// sign applies AWS Signature Version 4 to the request (service "route53").
func (c *awsRoute53Client) sign(req *http.Request, payload []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(payload)

	req.Header.Set("X-Amz-Date", amzDate)
	if c.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.sessionToken)
	}

	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/xml"
	}
	signedHeaders := "content-type;host;x-amz-date"
	canonicalHeaders := "content-type:" + contentType +
		"\nhost:" + req.URL.Host + "\nx-amz-date:" + amzDate + "\n"
	if c.sessionToken != "" {
		signedHeaders += ";x-amz-security-token"
		canonicalHeaders += "x-amz-security-token:" + c.sessionToken + "\n"
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + c.region + "/route53/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+c.secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte("route53"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, scope, signedHeaders, signature))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// decodeXMLError extracts the Route 53 error message from an error
// response body, falling back to the status code.
func decodeXMLError(r io.Reader, status int) error {
	var out struct {
		Error struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		} `xml:"Error"`
	}
	if err := xml.NewDecoder(r).Decode(&out); err == nil && out.Error.Message != "" {
		return errors.New(out.Error.Message)
	}
	return fmt.Errorf("status %d", status)
}

// Route 53 XML wire types.

type xmlChangeRequest struct {
	XMLName     xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	XMLNS       string   `xml:"xmlns,attr"`
	ChangeBatch struct {
		Comment string      `xml:"Comment"`
		Changes []xmlChange `xml:"Changes>Change"`
	} `xml:"ChangeBatch"`
}

type xmlChange struct {
	Action            string   `xml:"Action"`
	ResourceRecordSet xmlRRSet `xml:"ResourceRecordSet"`
}

type xmlRRSet struct {
	Name    string      `xml:"Name"`
	Type    string      `xml:"Type"`
	TTL     int64       `xml:"TTL"`
	Records []xmlRecord `xml:"ResourceRecords>ResourceRecord"`
}

type xmlRecord struct {
	Value string `xml:"Value"`
}

// route53XMLChangeBatch renders a change-batch as the Route 53 XML wire
// format.
func route53XMLChangeBatch(batch Route53ChangeBatch) xmlChangeRequest {
	var out xmlChangeRequest
	out.XMLNS = "https://route53.amazonaws.com/doc/2013-04-01/"
	out.ChangeBatch.Comment = batch.Comment
	for _, ch := range batch.Changes {
		change := xmlChange{Action: ch.Action}
		change.ResourceRecordSet.Name = ch.ResourceRecordSet.Name
		change.ResourceRecordSet.Type = ch.ResourceRecordSet.Type
		change.ResourceRecordSet.TTL = ch.ResourceRecordSet.TTL
		for _, rr := range ch.ResourceRecordSet.ResourceRecords {
			change.ResourceRecordSet.Records = append(change.ResourceRecordSet.Records, xmlRecord{Value: rr.Value})
		}
		out.ChangeBatch.Changes = append(out.ChangeBatch.Changes, change)
	}
	return out
}

func bareZoneID(id string) string {
	return strings.TrimPrefix(strings.TrimPrefix(id, "/hostedzone/"), "/")
}

// Compile-time assertions.
var (
	_ Provider     = (*Route53)(nil)
	_ dns.Provider = (*Route53DNS)(nil)
)
