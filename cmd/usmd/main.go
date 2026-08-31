package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/moera-sudo/usm-password-manager/internal/logging"
)

// IMPORTANT Server does not have master-key and never get it.
// IMPORTANT It stores only opaque blobs.

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

const appName = "usmd"

// IMPORTANT main does not contain defer: os.Exit does not run defer funcs, so all processes taken out in run()
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr        = flag.String("addr", "127.0.0.1:8787", "address to listen on")
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

	slog.Info("server started",
		slog.String("version", version),
		slog.String("addr", *addr),
	)

	slog.Warn("server is a stub, no endpoints served yet")

	slog.Info("server finished")

	return nil
}
