// Command chasquid-agent is the admin sidecar inside the chasquid container
// (spec §59: sidecar controller). It runs chasquid-util locally and manages
// generated domain configuration (spec §28, §33, §60) behind a token-guarded
// loopback HTTP API — the only component that may invoke chasquid-util.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	port := getenv("CHASQUID_AGENT_LISTEN", ":8530")
	token := os.Getenv("CHASQUID_AGENT_TOKEN")
	if token == "" {
		log.Fatal("CHASQUID_AGENT_TOKEN is required")
	}

	a := &agent{
		token:  token,
		conf:   getenv("CHASQUID_CONFIG_DIR", "/etc/chasquid"),
		util:   getenv("CHASQUID_UTIL_BIN", "chasquid-util"),
		daemon: getenv("CHASQUID_BIN", "chasquid"),
	}
	if err := a.ensureHook(); err != nil {
		log.Printf("chasquid-agent: hook install failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("POST /api/v1/domain", a.handleEnsureDomain)
	mux.HandleFunc("DELETE /api/v1/domain", a.handleRemoveDomain)
	mux.HandleFunc("POST /api/v1/user", a.handleAddUser)
	mux.HandleFunc("DELETE /api/v1/user", a.handleRemoveUser)
	mux.HandleFunc("POST /api/v1/user/password", a.handleChangePassword)
	mux.HandleFunc("POST /api/v1/alias", a.handleEnsureAlias)
	mux.HandleFunc("DELETE /api/v1/alias", a.handleRemoveAlias)
	mux.HandleFunc("POST /api/v1/policy", a.handleEnsurePolicy)
	mux.HandleFunc("POST /api/v1/dkim", a.handleEnsureDKIM)
	mux.HandleFunc("POST /api/v1/domain/check", a.handleCheckDomain)
	mux.HandleFunc("POST /api/v1/user/exists", a.handleUserExists)
	mux.HandleFunc("POST /api/v1/reload", a.handleReload)
	mux.HandleFunc("POST /api/v1/restart", a.handleRestart)

	srv := &http.Server{
		Addr:              port,
		Handler:           a.auth(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("chasquid-agent listening on %s", port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

type agent struct {
	token  string
	conf   string // /etc/chasquid
	util   string
	daemon string
}

func (a *agent) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Token") != a.token {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type req struct {
	Domain       string   `json:"domain"`
	Address      string   `json:"address"`
	Password     string   `json:"password"`
	Local        string   `json:"local"`
	Destinations []string `json:"destinations"`
	AllowedFrom  []string `json:"allowed_from_addresses"`
}

func (a *agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Config must parse, and the daemon must be running.
	if _, err := a.utilCmd(r.Context(), "print-config").Output(); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "config invalid: "+trunc(err.Error(), 200))
		return
	}
	if !a.daemonRunning(r.Context()) {
		writeErr(w, http.StatusServiceUnavailable, "daemon not running")
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (a *agent) daemonRunning(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", daemonPattern)
	out, err := cmd.Output()
	return err == nil && len(out) > 0
}

func (a *agent) handleEnsureDomain(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Domain == "" {
		return
	}
	dir := filepath.Join(a.conf, "domains", in.Domain)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true, "domain_dir": dir})
}

func (a *agent) handleRemoveDomain(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Domain == "" {
		return
	}
	// Removal is explicit; the default lifecycle disables and retains.
	if err := os.RemoveAll(filepath.Join(a.conf, "domains", in.Domain)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (a *agent) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Address == "" {
		return
	}
	out, err := a.utilCmd(r.Context(), "user-add", in.Address, "--password="+in.Password).CombinedOutput()
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, trunc(string(out)+" "+err.Error(), 300))
		return
	}
	_ = a.signalDaemon(r.Context(), syscall_SIGHUP) // apply to running userdb
	writeOK(w, map[string]any{"ok": true})
}

func (a *agent) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Address == "" {
		return
	}
	if out, err := a.utilCmd(r.Context(), "user-remove", in.Address).CombinedOutput(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, trunc(string(out)+" "+err.Error(), 300))
		return
	}
	_ = a.signalDaemon(r.Context(), syscall_SIGHUP)
	writeOK(w, map[string]any{"ok": true})
}

func (a *agent) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Address == "" {
		return
	}
	// chasquid-util user-add refuses existing users; rotate = remove+add.
	_, _ = a.utilCmd(r.Context(), "user-remove", in.Address).CombinedOutput()
	out, err := a.utilCmd(r.Context(), "user-add", in.Address, "--password="+in.Password).CombinedOutput()
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, trunc(string(out)+" "+err.Error(), 300))
		return
	}
	_ = a.signalDaemon(r.Context(), syscall_SIGHUP)
	writeOK(w, map[string]any{"ok": true})
}

func (a *agent) handleEnsureAlias(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Domain == "" {
		return
	}
	if err := a.setAlias(in.Domain, in.Local, in.Destinations); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.signalDaemon(r.Context(), syscall_SIGHUP); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (a *agent) handleRemoveAlias(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Domain == "" {
		return
	}
	a.removeAliasLine(in.Domain, in.Local)
	_ = a.signalDaemon(r.Context(), syscall_SIGHUP)
	writeOK(w, map[string]any{"ok": true})
}

// handleEnsurePolicy installs the sender-authorization policy file for an
// authenticated address (spec §46, §50): one allowed MAIL FROM per line.
func (a *agent) handleEnsurePolicy(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Address == "" {
		return
	}
	dir := filepath.Join(a.conf, "policies")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var b strings.Builder
	for _, addr := range in.AllowedFrom {
		b.WriteString(addr + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, in.Address), []byte(b.String()), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

// handleCheckDomain reports the observed chasquid state for a domain
// (spec §66, §92): users/aliases counts parsed from chasquid's own tools.
func (a *agent) handleCheckDomain(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Domain == "" {
		return
	}
	users := 0
	if out, err := a.utilCmd(r.Context(), "check-userdb", in.Domain).Output(); err == nil {
		if _, err := fmt.Sscanf(string(out), "Database loaded (%d users)", &users); err != nil {
			users = 0
		}
	}
	aliases := 0
	if b, err := os.ReadFile(filepath.Join(a.conf, "domains", in.Domain, "aliases")); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(ln) != "" {
				aliases++
			}
		}
	}
	exists := false
	if _, err := os.Stat(filepath.Join(a.conf, "domains", in.Domain)); err == nil {
		exists = true
	}
	writeOK(w, map[string]any{"exists": exists, "users": users, "aliases": aliases})
}

// handleUserExists reports whether a local user exists in the domain's
// userdb (by the documented `key: "<local>"` entries chasquid-util writes).
func (a *agent) handleUserExists(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Address == "" {
		return
	}
	local, _, ok := strings.Cut(in.Address, "@")
	if !ok {
		writeErr(w, http.StatusBadRequest, "address must be user@domain")
		return
	}
	b, err := os.ReadFile(filepath.Join(a.conf, "domains", strings.Split(in.Address, "@")[1], "users"))
	if err != nil {
		writeOK(w, map[string]any{"exists": false})
		return
	}
	exists := false
	for _, ln := range strings.Split(string(b), "\n") {
		key, rest, ok := strings.Cut(ln, ":")
		if ok && strings.TrimSpace(key) == "key" && strings.Contains(rest, `"`+local+`"`) {
			exists = true
			break
		}
	}
	writeOK(w, map[string]any{"exists": exists})
}

// handleEnsureDKIM generates (once) the domain's DKIM signing key and
// returns its selector and the DNS TXT record to publish (spec §28, §68).
func (a *agent) handleEnsureDKIM(w http.ResponseWriter, r *http.Request) {
	var in req
	if !readReq(w, r, &in) || in.Domain == "" {
		return
	}
	pattern := filepath.Join(a.conf, "domains", in.Domain, "dkim:*.pem")
	record := ""
	if matches, _ := filepath.Glob(pattern); len(matches) == 0 {
		out, err := a.utilCmd(r.Context(), "dkim-keygen", in.Domain).CombinedOutput()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "dkim-keygen: "+trunc(string(out)+" "+err.Error(), 300))
			return
		}
		record = dkimRecord(out)
	}
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		writeErr(w, http.StatusInternalServerError, "no DKIM key after keygen")
		return
	}
	base := filepath.Base(matches[0]) // dkim:<selector>.pem
	selector := strings.TrimSuffix(strings.TrimPrefix(base, "dkim:"), ".pem")
	if record == "" {
		record = "(key already present; re-run keygen output not available)"
	}
	writeOK(w, map[string]any{"selector": selector, "record": record})
}

// dkimRecord extracts the DNS TXT record from dkim-keygen output.
func dkimRecord(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "v=DKIM1") {
			return line
		}
	}
	return strings.TrimSpace(string(out))
}

// postDataHookScript enforces sender authorization after DATA (spec §47–50).
const postDataHookScript = `#!/bin/sh
# Generated by the selfu platform. Sender authorization (spec §47-50):
# an authenticated user may only send as addresses granted in its policy.
[ -n "$AUTH_AS" ] || exit 0
policy="/etc/chasquid/policies/$AUTH_AS"
if [ -f "$policy" ]; then
  if grep -Fxq "$MAIL_FROM" "$policy"; then
    exit 0
  fi
  domain="${MAIL_FROM##*@}"
  if [ -n "$domain" ] && grep -Fxq "@$domain" "$policy"; then
    exit 0
  fi
fi
echo "5.7.1 Sender not authorized for this identity"
exit 20
`

// ensureHook installs the post-data hook into the (volume-mounted) config
// dir; chasquid auto-discovers $config_dir/hooks/post-data.
func (a *agent) ensureHook() error {
	hooksDir := filepath.Join(a.conf, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(hooksDir, "post-data")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(postDataHookScript), 0o755)
}

func (a *agent) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := a.signalDaemon(r.Context(), syscall_SIGHUP); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

// handleRestart asks the entrypoint supervisor to restart the MTA (TERM).
// Required when NEW domains are provisioned (chasquid registers domain
// userdbs at startup; SIGHUP only reloads registered domains, spec §91).
func (a *agent) handleRestart(w http.ResponseWriter, r *http.Request) {
	_ = exec.CommandContext(r.Context(), "pkill", "-TERM", "-f", daemonPattern).Run()
	writeOK(w, map[string]any{"ok": true})
}

// setAlias replaces the alias line for local in the domain's aliases file,
// preserving all other lines (conservative, spec §92).
func (a *agent) setAlias(domain, local string, destinations []string) error {
	path := filepath.Join(a.conf, "domains", domain, "aliases")
	lines := []string{}
	if b, err := os.ReadFile(path); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			trimmed := strings.TrimSpace(ln)
			if trimmed == "" {
				continue
			}
			key, _, ok := strings.Cut(trimmed, ":")
			key = strings.TrimSpace(key)
			if ok && strings.EqualFold(key, local) {
				continue // replaced below
			}
			lines = append(lines, trimmed)
		}
	}
	if len(destinations) == 0 {
		return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640)
	}
	lines = append(lines, local+": "+strings.Join(destinations, ", "))
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640)
}

func (a *agent) removeAliasLine(domain, local string) {
	_ = a.setAlias(domain, local, nil)
}

func (a *agent) utilCmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, a.util, args...)
	cmd.Env = append(os.Environ(), "CHASQUID_CONFIG_DIR="+a.conf)
	return cmd
}

// daemonPattern matches only the chasquid daemon process line (not the
// companion agent) so pgrep/pkill -f target the MTA precisely.
const daemonPattern = "chasquid -config_dir"

func (a *agent) signalDaemon(ctx context.Context, _ int) error {
	cmd := exec.CommandContext(ctx, "pkill", "-sighup", "-f", daemonPattern)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No matching processes") {
		return fmt.Errorf("signal %s: %w (%s)", a.daemon, err, trunc(string(out), 200))
	}
	return nil
}

func readReq(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return false
	}
	return true
}

func writeOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

const syscall_SIGHUP = 1
