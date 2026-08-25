// Command doctor is the preflight check for a selfu operator host
// (`make doctor`). It verifies everything `make bootstrap` needs before it
// starts, with actionable messages. Hard failures exit nonzero; soft issues
// (DNS not pointed yet, optional integrations) are warnings.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// requiredEnv lists every variable compose marks mandatory (`:?set in .env`).
var requiredEnv = []string{
	"POSTGRES_USER", "POSTGRES_PASSWORD",
	"AUTHENTIK_SECRET_KEY", "AUTHENTIK_BOOTSTRAP_EMAIL",
	"AUTHENTIK_BOOTSTRAP_PASSWORD", "AUTHENTIK_BOOTSTRAP_TOKEN",
	"SELFU_SESSION_SECRET", "SELFU_OIDC_CLIENT_ID", "SELFU_OIDC_CLIENT_SECRET",
	"CHASQUID_AGENT_TOKEN",
	"PLATFORM_HOST", "AUTH_HOST", "ACME_EMAIL",
}

type result struct {
	name string
	ok   bool   // false -> hard failure
	warn bool   // true  -> report but don't fail
	msg  string // actionable detail
}

func main() {
	env := loadDotEnv(".env")
	httpPort := portEnv(env, "SELFU_HTTP_PORT", "18080")
	authPort := portEnv(env, "AUTHENTIK_PORT", "9000")

	var results []result
	results = append(results, checkDocker())
	results = append(results, checkPorts(httpPort, authPort)...)
	results = append(results, checkDotEnv(env)...)
	results = append(results, checkDNS(env)...)
	if tok := env["CLOUDFLARE_API_TOKEN"]; tok != "" {
		results = append(results, checkCloudflareToken(tok))
	}

	hard := 0
	for _, r := range results {
		switch {
		case r.ok:
			fmt.Printf("  ok    %s\n", r.msg)
		case r.warn:
			fmt.Printf("  warn  %s\n", r.msg)
		default:
			fmt.Printf("  FAIL  %s\n", r.msg)
			hard++
		}
	}
	if hard > 0 {
		fmt.Printf("\ndoctor: %d hard failure(s) — fix the FAIL lines above before bootstrapping.\n", hard)
		os.Exit(1)
	}
	fmt.Println("\ndoctor: all preflight checks passed (warnings are non-blocking).")
}

func checkDocker() result {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	if err != nil {
		return result{name: "docker", msg: "docker daemon unreachable — start Docker (systemctl start docker / open Docker Desktop)"}
	}
	return result{ok: true, msg: fmt.Sprintf("docker daemon reachable (server %s)", strings.TrimSpace(string(out)))}
}

func checkPorts(ports ...string) []result {
	var out []result
	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", p), time.Second)
		if err == nil {
			conn.Close()
			// A busy port only blocks the FIRST run; if our own stack is
			// already serving it, re-running bootstrap must stay safe.
			if holders := selfuContainersOnPort(p); len(holders) > 0 {
				out = append(out, result{ok: true, msg: fmt.Sprintf("port :%s served by existing selfu container(s) %s — compose up will reconcile them", p, strings.Join(holders, ", "))})
				continue
			}
			out = append(out, result{msg: fmt.Sprintf("port :%s in use by another process — free it or stop the conflicting service before compose up", p)})
			continue
		}
		out = append(out, result{ok: true, msg: fmt.Sprintf("port :%s free", p)})
	}
	return out
}

func checkDotEnv(env map[string]string) []result {
	if _, err := os.Stat(".env"); err != nil {
		return []result{{msg: ".env missing — run `make gen-env` (bootstrap does this for you) and fill in hosts/secrets"}}
	}
	var out []result
	var missing []string
	for _, k := range requiredEnv {
		if strings.TrimSpace(env[k]) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return []result{{msg: fmt.Sprintf(".env missing required variables: %s — add them to .env", strings.Join(missing, ", "))}}
	}
	out = append(out, result{ok: true, msg: fmt.Sprintf(".env present with all %d required variables", len(requiredEnv))})

	if env["SELFU_ACCESS_PROVIDER"] == "cloudflare" && strings.TrimSpace(env["CLOUDFLARE_API_TOKEN"]) == "" {
		out = append(out, result{msg: "SELFU_ACCESS_PROVIDER=cloudflare but CLOUDFLARE_API_TOKEN unset — set it in .env or switch to manual"})
	} else if env["SELFU_ACCESS_PROVIDER"] == "cloudflare" && strings.TrimSpace(env["CLOUDFLARE_ZONE_ID"]) == "" {
		out = append(out, result{warn: true, msg: "CLOUDFLARE_ZONE_ID unset — automatic DNS records will need the zone ID set in .env"})
	}
	return out
}

func checkDNS(env map[string]string) []result {
	var out []result
	for _, key := range []string{"PLATFORM_HOST", "AUTH_HOST", "MAIL_HOST"} {
		host := strings.TrimSpace(env[key])
		if host == "" || key == "MAIL_HOST" && !hasMXIntent(env) {
			continue // MAIL_HOST is optional; only checked when configured
		}
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			pub := strings.TrimSpace(env["PUBLIC_IP"])
			hint := ""
			if pub != "" {
				hint = fmt.Sprintf(" — should point at %s (see scripts/dns-records.sh)", pub)
			}
			out = append(out, result{warn: true, msg: fmt.Sprintf("DNS does not resolve for %s (%s)%s", key, host, hint)})
			continue
		}
		out = append(out, result{ok: true, msg: fmt.Sprintf("%s resolves (%s)", host, ips[0])})
	}
	return out
}

func hasMXIntent(env map[string]string) bool { return strings.TrimSpace(env["MAIL_HOST"]) != "" }

// selfuContainersOnPort lists running compose containers publishing the given
// host port, so a re-run against an existing stack is not mistaken for a
// foreign conflict.
func selfuContainersOnPort(port string) []string {
	out, err := exec.Command("docker", "ps", "--filter", "publish="+port,
		"--format", "{{.Names}}").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, n := range strings.Fields(string(out)) {
		names = append(names, n)
	}
	return names
}

func checkCloudflareToken(token string) result {
	req, _ := http.NewRequest(http.MethodGet, "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result{warn: true, msg: fmt.Sprintf("could not reach Cloudflare API to verify token: %v", err)}
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK || !body.Success {
		return result{msg: "CLOUDFLARE_API_TOKEN rejected by Cloudflare — generate a new token with Zone:DNS:Edit permission"}
	}
	return result{ok: true, msg: "CLOUDFLARE_API_TOKEN valid"}
}

func portEnv(env map[string]string, key, def string) string {
	if v := strings.TrimSpace(env[key]); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			return v
		}
	}
	return def
}

// loadDotEnv parses a simple KEY=VALUE file (comments with #, optional
// quotes). It never overrides variables already set in the process
// environment, mirroring compose behavior.
func loadDotEnv(path string) map[string]string {
	env := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return env
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); exists {
			v = os.Getenv(k)
		}
		env[k] = v
	}
	return env
}
