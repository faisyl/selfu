package dns

import (
	"context"
	"net"
	"time"
)

// NewTXTLookup returns a TXTLookup that queries the given resolvers
// (host:port) directly, trying each in order. This avoids depending on the
// host's resolver, which may cache negative answers and hide records that
// public resolvers already serve (the API container inherits the host stub).
func NewTXTLookup(servers []string) TXTLookup {
	return func(ctx context.Context, fqdn string) ([]string, error) {
		var lastErr error
		for _, server := range servers {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, network, server)
				},
			}
			txts, err := r.LookupTXT(ctx, fqdn)
			if err == nil {
				return txts, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
