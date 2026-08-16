// Package version carries build metadata injected at link time.
package version

// Version is the semantic version. Overridable with
// -ldflags "-X selfu/internal/version.Version=v0.1.0".
var Version = "0.1.0-dev"
