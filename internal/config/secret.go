// Package config contains small, dependency-free configuration helpers.
package config

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const maxSecretSize = 4096

// LoadSecret reads a secret from file when fileName is non-empty, otherwise
// from envName. Secret files must not be accessible by group or other users on
// Unix. Leading and trailing ASCII whitespace is removed.
func LoadSecret(fileName, envName string) (string, error) {
	var value string
	if fileName != "" {
		info, err := os.Stat(fileName)
		if err != nil {
			return "", fmt.Errorf("stat secret file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("secret file is not a regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("secret file %q permissions are %04o; want 0600 or stricter", fileName, info.Mode().Perm())
		}
		if info.Size() > maxSecretSize {
			return "", fmt.Errorf("secret file exceeds %d bytes", maxSecretSize)
		}
		contents, err := os.ReadFile(fileName)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		value = string(contents)
	} else if envName != "" {
		value = os.Getenv(envName)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		if fileName != "" {
			return "", errors.New("secret file is empty")
		}
		return "", fmt.Errorf("secret is required; set %s or provide a secret file", envName)
	}
	if len(value) > maxSecretSize {
		return "", fmt.Errorf("secret exceeds %d bytes", maxSecretSize)
	}
	return value, nil
}
