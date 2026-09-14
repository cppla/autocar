package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

const maxCommandConfigSize = 64 << 10

// parseFlagsWithConfig preserves flag's CLI syntax and precedence. A config is
// a single, bounded JSON object whose keys are this command's long flag names.
// It contains file references, never inline credentials. Each command still
// performs its normal semantic and credential validation after parsing.
func parseFlagsWithConfig(fs *flag.FlagSet, args []string) error {
	configPath := fs.String("config", "", "JSON options file; CLI overrides it, file paths are relative to its directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("positional arguments are not supported; use named options")
	}
	if *configPath == "" {
		return nil
	}
	// Save explicit flags before Set marks config options as visited too.
	explicit := make(map[string]string)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = f.Value.String() })
	values, err := readCommandConfig(*configPath)
	if err != nil {
		return err
	}
	base, err := filepath.Abs(filepath.Dir(*configPath))
	if err != nil {
		return fmt.Errorf("resolve config directory: %w", err)
	}
	keys := make([]string, 0, len(values))
	for name := range values {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		f := fs.Lookup(name)
		if f == nil || name == "config" {
			return fmt.Errorf("unknown or unsupported config option %q for %s", name, fs.Name())
		}
		value, err := commandConfigValue(f, values[name])
		if err != nil {
			return fmt.Errorf("config option %q: %w", name, err)
		}
		if commandConfigFileOption(name) && value != "" && !filepath.IsAbs(value) {
			value = filepath.Join(base, value)
		}
		// Validate even overridden entries so stale/invalid config never goes
		// unnoticed. Do not include a possibly sensitive value in diagnostics.
		if err := fs.Set(name, value); err != nil {
			return fmt.Errorf("invalid config option %q; see command help for its type and format", name)
		}
		if cliValue, ok := explicit[name]; ok {
			if err := fs.Set(name, cliValue); err != nil {
				return fmt.Errorf("restore command-line option %q: %w", name, err)
			}
		}
	}
	return nil
}

func readCommandConfig(path string) (map[string]any, error) {
	// Check before opening so accidental directories/devices/FIFOs are not
	// treated as configuration streams. Check the opened file again below.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxCommandConfigSize {
		return nil, errors.New("config must be a regular JSON file no larger than 64 KiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened config file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxCommandConfigSize {
		return nil, errors.New("config must be a regular JSON file no larger than 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCommandConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	if len(data) > maxCommandConfigSize {
		return nil, errors.New("config exceeds 64 KiB")
	}
	return decodeCommandConfig(data)
}

func decodeCommandConfig(data []byte) (map[string]any, error) {
	// Token-by-token decoding detects duplicate keys that a normal map decode
	// would silently accept (including escaped spellings of the same key).
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("config must contain one JSON object")
	}
	values := make(map[string]any)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, errors.New("invalid config JSON")
		}
		name, ok := token.(string)
		if !ok || name == "" {
			return nil, errors.New("config option names must be nonempty strings")
		}
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("duplicate config option %q", name)
		}
		var value any
		if err := d.Decode(&value); err != nil {
			return nil, errors.New("invalid config JSON")
		}
		switch value.(type) {
		case string, bool, json.Number:
		default:
			return nil, fmt.Errorf("config option %q must be a string, boolean, or integer", name)
		}
		values[name] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid config JSON")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("config must contain exactly one JSON object")
	}
	return values, nil
}

func commandConfigValue(f *flag.Flag, value any) (string, error) {
	getter, ok := f.Value.(flag.Getter)
	if !ok {
		return "", errors.New("unsupported option type")
	}
	switch getter.Get().(type) {
	case string:
		if text, ok := value.(string); ok {
			return text, nil
		}
		return "", errors.New("must be a JSON string")
	case bool:
		if enabled, ok := value.(bool); ok {
			return strconv.FormatBool(enabled), nil
		}
		return "", errors.New("must be a JSON boolean")
	case time.Duration:
		if text, ok := value.(string); ok {
			return text, nil
		}
		return "", errors.New("must be a duration string such as 15s")
	default:
		// Numeric flags accept exact JSON integers or strings and retain
		// flag's own range/format validation.
		switch v := value.(type) {
		case string:
			return v, nil
		case json.Number:
			return v.String(), nil
		default:
			return "", errors.New("must be a number or numeric string")
		}
	}
}

func commandConfigFileOption(name string) bool {
	switch name {
	case "ca", "client-cert", "client-key", "token-file", "proxy-cert", "proxy-key",
		"proxy-password-file", "cert", "key", "client-ca", "cover-root":
		return true
	default:
		return false
	}
}
