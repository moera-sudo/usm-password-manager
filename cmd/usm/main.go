package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/moera-sudo/usm-password-manager/internal/logging"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

const appName = "usm"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		vaultName   = flag.String("vault", "", "vault to open, empty means the last used one")
		logLevel    = flag.String("log-level", "", "log level: debug, info, warn, error")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s %s (commit %s, built %s)\n", appName, version, commit, buildDate)
		return nil
	}

	closer, err := logging.Setup(logging.Options{Component: appName, Level: *logLevel})
	if err != nil {
		return fmt.Errorf("setup logging: %w", err)
	}
	defer func() {
		if cerr := closer.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "%s: close log file: %v\n", appName, cerr)
		}
	}()

	slog.Info("client started", slog.String("version", version))

	slog.Debug("startup parameters", slog.String("vault", *vaultName))

	slog.Warn("no subcommands implemented yet")

	slog.Info("client finished")

	return nil
}
