package main

import "errors"

type commandError struct {
	code int
	err  error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }
func (e *commandError) ExitCode() int { return e.code }

func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &commandError{code: code, err: err}
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) && coded.ExitCode() > 0 {
		return coded.ExitCode()
	}
	return 1
}
