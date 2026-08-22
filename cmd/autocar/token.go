package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

func runToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	output := fs.String("out", "", "write to a new 0600 file instead of stdout")
	bytesCount := fs.Int("bytes", 32, "random byte count (16-128)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bytesCount < 16 || *bytesCount > 128 {
		return errors.New("--bytes must be between 16 and 128")
	}
	random := make([]byte, *bytesCount)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("read cryptographic randomness: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(random) + "\n"
	if *output == "" {
		fmt.Print(value)
		return nil
	}
	if strings.TrimSpace(*output) == "" {
		return errors.New("invalid --out path")
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create token file: %w", err)
	}
	if _, err := file.WriteString(value); err != nil {
		file.Close()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}
	return nil
}
