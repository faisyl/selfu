// Package traefik generates Traefik discovery labels for application
// instances (spec §18). The catalog can never inject configuration here —
// labels are derived ONLY from platform-controlled inputs (instance id,
// verified hostname, container port, auth mode); there is no free-form field.
package traefik

import (
	"fmt"
	"sort"
	"strings"
)

// Label is one traefik.<...> label key/value.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RouteLabels builds the labels for one hostname. name is sanitized from the
// instance id (never user input, §20). When forwardAuth is true, an
// authentik forward-auth middleware is wired (spec §83).
func RouteLabels(instanceID, hostname string, port int, forwardAuth bool) []Label {
	name := sanitize(instanceID)
	out := []Label{
		{Key: "traefik.enable", Value: "true"},
		{Key: fmt.Sprintf("traefik.http.routers.%s.rule", name),
			Value: fmt.Sprintf("Host(`%s`)", hostname)},
		{Key: fmt.Sprintf("traefik.http.routers.%s.entrypoints", name), Value: "websecure"},
		{Key: fmt.Sprintf("traefik.http.routers.%s.tls", name), Value: "true"},
		{Key: fmt.Sprintf("traefik.http.services.%s.loadbalancer.server.port", name),
			Value: fmt.Sprintf("%d", port)},
	}
	if forwardAuth {
		mw := name + "-auth"
		out = append(out,
			Label{Key: fmt.Sprintf("traefik.http.middlewares.%s.forwardauth.address", mw),
				Value: "http://authentik:9000/outpost.goauthentik.io/auth/traefik"},
			Label{Key: fmt.Sprintf("traefik.http.middlewares.%s.forwardauth.authResponseHeaders", mw),
				Value: "X-authentik-*"},
			Label{Key: fmt.Sprintf("traefik.http.routers.%s.middlewares", name), Value: mw},
		)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// sanitize derives a safe, short router name from an id.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			b.WriteRune(r - 'A' + 'a')
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		name = "app"
	}
	if len(name) > 20 {
		name = name[:20]
	}
	return name
}
