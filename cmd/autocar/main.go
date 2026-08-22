package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Error("command failed", "error", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) (err error) {
	if len(args) == 0 {
		printUsage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "client":
		err = runClient(ctx, args[1:])
	case "server":
		err = runServer(ctx, args[1:])
	case "cert":
		err = runCert(args[1:])
	case "token":
		err = runToken(args[1:])
	case "bench-server":
		err = runBenchServer(ctx, args[1:])
	case "bench-client":
		err = runBenchClient(ctx, args[1:])
	case "version":
		printVersion()
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `AutoCAR - authenticated dual-ended TCP acceleration

Usage:
  autocar server [options]       run the remote QUIC/TLS relay
  autocar client [options]       run local SOCKS5 and HTTP(S) proxies
  autocar cert [options]         generate a self-signed TLS certificate
  autocar token [options]        generate a strong shared token
  autocar bench-server [options] run a benchmark source/sink target
  autocar bench-client [options] measure direct or tunneled goodput
  autocar version                print build information

Run "autocar <command> -h" for command-specific options.`)
}
