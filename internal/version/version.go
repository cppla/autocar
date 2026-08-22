// Package version exposes build metadata injected with -ldflags.
package version

import "runtime/debug"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// ModuleVersion returns the injected version, or the Go module version when
// built without release ldflags.
func ModuleVersion() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return Version
}
