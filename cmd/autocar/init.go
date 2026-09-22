package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cppla/autocar/internal/security"
)

func runInit(args []string) error {
	return runInitWith(args, os.Stdout)
}

// init creates a native deployment bundle only. It never contacts the relay,
// installs services, opens a firewall, or overwrites an existing output path.
func runInitWith(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	server := fs.String("server", "", "client-visible relay host:numeric-port (required; bracket IPv6)")
	serverName := fs.String("server-name", "", "certificate DNS name or IP; defaults to the relay host")
	directory := fs.String("out", "autocar-config", "new private output directory; must not already exist")
	days := fs.Int("days", 365, "self-signed certificate validity in days (1-1825)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("init does not accept positional arguments")
	}
	if strings.TrimSpace(*directory) == "" {
		return errors.New("--out must name a new directory")
	}
	if *days < 1 || *days > 1825 {
		return errors.New("--days must be between 1 and 1825")
	}
	host, port, err := validateInitServer(*server)
	if err != nil {
		return err
	}
	name := *serverName
	if name == "" {
		name = host
	}
	if err := validateInitHost(name); err != nil {
		return errors.New("--server-name must be a DNS name or IP without a port, wildcard, or zone")
	}
	cert, key, err := security.GenerateSelfSignedCertificate(security.CertificateOptions{
		Hosts: []string{name}, ValidFor: time.Duration(*days) * 24 * time.Hour,
		Organization: "AutoCAR",
	})
	if err != nil {
		return errors.New("could not generate a certificate; check the relay name and system randomness")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generate shared token: %w", err)
	}
	token := []byte(base64.RawURLEncoding.EncodeToString(random) + "\n")
	serverConfig, err := json.MarshalIndent(map[string]any{
		"protocol": "native", "listen": ":" + port,
		"cert": "server.crt", "key": "server.key", "token-file": "relay-token",
	}, "", "  ")
	if err != nil {
		return err
	}
	clientConfig, err := json.MarshalIndent(map[string]any{
		"server": net.JoinHostPort(host, port), "server-name": name,
		"ca": "server.crt", "token-file": "relay-token", "transport": "auto",
	}, "", "  ")
	if err != nil {
		return err
	}
	files := []initBundleFile{
		{".gitignore", []byte("*\n")},
		{"server/.gitignore", []byte("*\n")}, {"client/.gitignore", []byte("*\n")},
		{"server/server.crt", cert}, {"server/server.key", key}, {"server/relay-token", token},
		{"client/server.crt", cert}, {"client/relay-token", token},
		{"server/server.json", append(serverConfig, '\n')},
		{"client/client.json", append(clientConfig, '\n')},
		{"README.txt", []byte(initBundleInstructions)},
	}
	if err := writeInitBundle(*directory, files); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Created native configuration bundle in %q.\n"+
		"Copy only server/ to the relay and only client/ to the client over an authenticated channel.\n"+
		"The server private key is not included in client/. Both directories contain a secret token.\n"+
		"See README.txt for offline checks and startup. No service or network connection was started.\n", *directory)
	if err != nil {
		return errors.New("bundle was created, but writing the completion message failed; do not overwrite it")
	}
	return nil
}

func validateInitServer(server string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(server)
	if err != nil || validateInitHost(host) != nil || port == "" {
		return "", "", errors.New("--server must be host:numeric-port (use [IPv6-address]:port)")
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return "", "", errors.New("--server port must be an integer from 1 through 65535")
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return "", "", errors.New("--server port must be an integer from 1 through 65535")
	}
	return host, strconv.FormatUint(number, 10), nil
}

func validateInitHost(host string) error {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return errors.New("relay address must not contain a zone")
		}
		address = address.Unmap()
		if address.IsUnspecified() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return errors.New("relay address must be a specific unicast address without a zone")
		}
		return nil
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return errors.New("invalid DNS name length")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, letter := range label {
			if !(letter >= 'a' && letter <= 'z' || letter >= 'A' && letter <= 'Z' || letter >= '0' && letter <= '9' || letter == '-') {
				return errors.New("DNS labels must use ASCII letters, digits, and hyphens; use punycode for international names")
			}
		}
	}
	return nil
}

type initBundleFile struct {
	path string
	data []byte
}

func writeInitBundle(directory string, files []initBundleFile) error {
	// Mkdir, not MkdirAll, reserves a new destination atomically. Even an empty
	// existing directory or a dangling symlink must never be reused.
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create new --out directory (parent must exist; existing paths are never reused): %w", err)
	}
	if err := writeInitBundleContents(directory, files); err != nil {
		// Do not recursively remove a user-selected path on failure. An incomplete
		// bundle remains private and can be inspected before choosing a new path.
		return fmt.Errorf("incomplete bundle left in --out; do not deploy it: %w", err)
	}
	return nil
}

func writeInitBundleContents(directory string, files []initBundleFile) error {
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"server", "client"} {
		path := filepath.Join(directory, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	for _, file := range files {
		if err := writeNewInitFile(filepath.Join(directory, filepath.FromSlash(file.path)), file.data); err != nil {
			return fmt.Errorf("write bundle file %s: %w", file.path, err)
		}
	}
	return nil
}

func writeNewInitFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

const initBundleInstructions = `AutoCAR native deployment bundle

This is a private, self-signed-certificate deployment, not a publicly trusted
website certificate. Keep the private key only on the relay. The client directory
contains the trust anchor and shared token but never the private key.

1. Transfer server/ to the relay and client/ to your client using an authenticated
   channel. Never publish this bundle or commit it to Git. Generated .gitignore
   files reduce accidental Git adds, but do not replace secure storage. Preserve permissions
   and ensure each file is owned/readable by the service user. On Unix, directories
   are 0700 and files are 0600. On Windows, restrict access using filesystem ACLs;
   Unix mode bits do not secure the bundle there.
2. On the relay, from server/:
     autocar server --config server.json --check
     autocar server --config server.json
3. On your client, from client/:
     autocar client --config client.json --check
     autocar doctor --config client.json --target example.com:443
     autocar client --config client.json
   The doctor step contacts the relay and the target; choose a target you are
   authorized to test. A successful TCP open does not validate UDP or application
   traffic. --check only checks local configuration, not connectivity.

Use a build with init, --config and --check support on both hosts, not the old
v1.0.1 binary. Paths inside JSON are relative to the configuration file, so the
directories can be moved independently. Existing CLI flags override JSON.

Open the relay's configured TCP and UDP port in your firewall before real use.
No service installation, firewall changes, DNS lookup or network test was done
by init. Low ports may require a capability or external port mapping; do not run
the entire service as root merely for a low port. The local SOCKS5/HTTP proxies
remain loopback-only. Existing destination policy and native/auto defaults apply.

The generated certificate expires; plan renewal and transfer the replacement
trust anchor through an authenticated channel. init is for NEW deployments only,
not credential rotation. It refuses existing output directories. If initialization
fails, any incomplete private bundle is left in place; do not deploy it.
`
