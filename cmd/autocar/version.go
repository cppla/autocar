package main

import (
	"fmt"
	"runtime"

	buildversion "github.com/cppla/autocar/internal/version"
)

func printVersion() {
	fmt.Printf("autocar %s (commit %s, built %s, %s/%s, %s)\n",
		buildversion.ModuleVersion(), buildversion.Commit, buildversion.Date,
		runtime.GOOS, runtime.GOARCH, runtime.Version())
}
