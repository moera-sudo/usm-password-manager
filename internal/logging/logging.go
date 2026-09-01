package logging

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	appDirName = "usm"
	logFileExt = ".log"

	logFileMode = 0o600
	logDirMode  = 0o700

	envLevel = "USM_LOG"
	envFile  = "USM_LOG_FILE"

	redacted = "[redacted]"
)

type Options struct {
	Component string
	Level     string
}

func Setup(opts Options) (io.Closer, error) {
	level, err := resolveLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	if opts.Component == "" {
		return nil, errors.New("logging: component name is required")
	}
	path, err := resolvePath(opts.Component)
	if err != nil {
		return nil, err
	}

	file, err := openLogFile(path)
	if err != nil {
		return nil, err
	}

	handler := slog.NewTextHandler(file, &slog.HandlerOptions{Level: level})

	slog.SetDefault(slog.New(handler).With(
		slog.String("component", opts.Component),
		slog.Int("pid", os.Getpid()),
	))

	slog.Info("logging initialised",
		slog.String("file", path),
		slog.String("level", level.String()),
	)

	return file, nil
}

func resolveLevel(flagValue string) (slog.Level, error) {
	raw := flagValue
	if raw == "" {
		raw = os.Getenv(envLevel)
	}
	if raw == "" {
		return slog.LevelInfo, nil
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(raw)); err != nil {
		return 0, fmt.Errorf("parse log level: %w", err)
	}

	return level, nil
}

func resolvePath(component string) (string, error) {
	if custom := os.Getenv(envFile); custom != "" {
		return custom, nil
	}

	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}

	return filepath.Join(stateHome, appDirName, component+logFileExt), nil
}

func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), logDirMode); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	// #nosec G304 -- the path is built from XDG variables, not from user input
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	if err := file.Chmod(logFileMode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("tighten log file permissions: %w", err)
	}

	return file, nil
}

type Secret[T any] struct {
	value T
}

func Wrap[T any](v T) Secret[T] {
	return Secret[T]{value: v}
}

func (s Secret[T]) Unwrap() T {
	return s.value
}

func (Secret[T]) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

func (Secret[T]) String() string {
	return redacted
}

func (Secret[T]) GoString() string {
	return redacted
}

func (Secret[T]) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
