package main

import (
	"os"

	"github.com/Method-Security/methodtenable/cmd"
)

var version = "none"

func main() {
	methodtenable := cmd.NewMethodTenable(version)
	methodtenable.InitRootCommand()
	methodtenable.InitVMCommand()
	methodtenable.InitWASCommand()

	if err := methodtenable.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
