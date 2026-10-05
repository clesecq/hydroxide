package main

import (
	"runtime"
	runtimedebug "runtime/debug"
)

// version can be set at build time with:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/hydroxide
var version string

func getVersion() string {
	if version != "" {
		return version
	}

	info, ok := runtimedebug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	// Set when installed with "go install <module>@<version>"
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return "devel"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return "devel-" + revision
}

func versionString() string {
	return "hydroxide " + getVersion() + " (" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
