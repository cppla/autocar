package main

import (
	"flag"
	"fmt"
)

// None of the option-based commands accepts positional operands. Check them
// before reading credentials, creating output files, or starting network I/O.
// Do not echo the operands: an accidentally pasted value may be a secret.
func parseCommandFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments; use named options", fs.Name())
	}
	return nil
}
