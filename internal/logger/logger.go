package logger

import (
	"io"
	"log/slog"
	"os"
)

var defaultLogger *slog.Logger

func init() {
	lvlStr := os.Getenv("ENTROPIA_LOG_LEVEL")
	if lvlStr == "" {
		// silent by default – discard logs until enabled via flag or env var
		defaultLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
		return
	}

	lvl := ParseLevel(lvlStr)
	defaultLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// L returns the shared application logger.
func L() *slog.Logger {
	return defaultLogger
}

// Set replaces the global logger (useful in tests).
func Set(l *slog.Logger) {
	if l != nil {
		defaultLogger = l
	}
}

// SetLevel changes logging level at runtime.
func SetLevel(level slog.Level) {
	defaultLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// ParseLevel converts a textual level ("debug", "info", "warn", "error") to a slog.Level.
// Unknown strings fall back to slog.LevelInfo.
func ParseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info", "":
		return slog.LevelInfo
	default:
		return slog.LevelInfo
	}
}

// SetLevelFromString is a helper that calls ParseLevel and SetLevel.
func SetLevelFromString(s string) {
	SetLevel(ParseLevel(s))
}
