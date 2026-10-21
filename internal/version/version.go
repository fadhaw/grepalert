// Package version holds the release version of both binaries. Release
// builds set it with -ldflags "-X github.com/fadhaw/grepalert/internal/version.Version=0.1.0".
package version

// Version is "dev" for builds that did not set it.
var Version = "dev"
