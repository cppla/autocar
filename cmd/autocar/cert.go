package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/security"
)

func runCert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	hosts := fs.String("hosts", "", "comma-separated DNS names/IP SANs (required)")
	certFile := fs.String("cert", "server.crt", "certificate output path")
	keyFile := fs.String("key", "server.key", "0600 private-key output path")
	days := fs.Int("days", 365, "certificate validity in days (1-1825)")
	organization := fs.String("organization", "AutoCAR", "certificate organization")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*hosts) == "" {
		return errors.New("--hosts is required")
	}
	if *days < 1 || *days > 1825 {
		return errors.New("--days must be between 1 and 1825")
	}
	if fileExists(*certFile) || fileExists(*keyFile) {
		return errors.New("refusing to overwrite an existing certificate or key")
	}
	var sans []string
	for _, host := range strings.Split(*hosts, ",") {
		if host = strings.TrimSpace(host); host != "" {
			sans = append(sans, host)
		}
	}
	if err := security.WriteSelfSignedCertificate(*certFile, *keyFile, security.CertificateOptions{
		Hosts:        sans,
		ValidFor:     time.Duration(*days) * 24 * time.Hour,
		Organization: *organization,
	}); err != nil {
		return err
	}
	fmt.Printf("wrote certificate %s and private key %s\n", *certFile, *keyFile)
	return nil
}
