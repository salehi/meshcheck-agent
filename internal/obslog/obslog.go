// SPDX-License-Identifier: AGPL-3.0-only

// Package obslog provides the agent's structured logging. It is a small,
// self-contained slog setup so the public agent has no dependency on the
// platform's server-side observability package (which also carries Prometheus
// metrics the agent never uses).
package obslog

import (
	"log/slog"
	"os"
)

// NewLogger builds a JSON structured logger at the given level. Every log line
// is machine-parseable.
func NewLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}
