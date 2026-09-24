// Package version exposes build metadata (version, commit, build date) that
// can be injected at build time via -ldflags. When not injected, it reports
// reasonable defaults for development builds.
package version

// Build variables. Overridden at build time using -ldflags, for example:
//
//	go build -ldflags "-X github.com/h1s97x/openidp/api/internal/version.Version=1.2.3"
var (
	// Version is the semantic version of the build.
	Version = "dev"
	// Commit is the git commit SHA the binary was built from.
	Commit = "none"
	// BuildDate is the RFC3339 timestamp of the build.
	BuildDate = "unknown"
)

// Info describes a single build's metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

// Get returns the current build metadata.
func Get() Info {
	return Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
}
