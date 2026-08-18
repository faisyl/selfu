package traefik

import (
	"strings"
	"testing"
)

func TestRouteLabels(t *testing.T) {
	labels := RouteLabels("71b07bde-73cb-4590", "cloud.pruxi.in", 3000, true)
	byKey := map[string]string{}
	for _, l := range labels {
		byKey[l.Key] = l.Value
	}
	if !strings.Contains(byKey["traefik.http.routers.71b07bde-73cb-4590.rule"], "cloud.pruxi.in") {
		t.Errorf("router rule missing hostname: %v", byKey)
	}
	if byKey["traefik.enable"] != "true" {
		t.Error("traefik.enable missing")
	}
	if byKey["traefik.http.services.71b07bde-73cb-4590.loadbalancer.server.port"] != "3000" {
		t.Error("port label missing")
	}
	if !strings.Contains(byKey["traefik.http.routers.71b07bde-73cb-4590.middlewares"], "-auth") {
		t.Error("forward-auth middleware not wired")
	}
	if byKey["traefik.http.routers.71b07bde-73cb-4590.entrypoints"] != "websecure" ||
		byKey["traefik.http.routers.71b07bde-73cb-4590.tls"] != "true" {
		t.Error("tls/entrypoint labels wrong")
	}
}

// spec §18: the label set is closed — every emitted key is traefik.* and
// derived from platform inputs; there is no vector for arbitrary config.
func TestLabelsAreClosedTraefikSet(t *testing.T) {
	for _, mode := range []bool{false, true} {
		for _, l := range RouteLabels("abc123", "git.example.com", 8080, mode) {
			if !strings.HasPrefix(l.Key, "traefik.") {
				t.Errorf("non-traefik label leaked: %q (spec §18)", l.Key)
			}
		}
	}
}

func TestSanitizeName(t *testing.T) {
	if got := sanitize("ACME/Tool_1!b"); got != "acmetool1b" {
		t.Errorf("sanitize = %q", got)
	}
}
