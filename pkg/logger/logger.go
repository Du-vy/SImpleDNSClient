package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	defaultLogger *slog.Logger
	logQueries    bool
	mu            sync.RWMutex
)

func init() {
	// Initialize with sensible text default
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// Config defines the options for logging setup.
type Config struct {
	Level      string `yaml:"level"`       // "debug", "info", "warn", "error"
	Format     string `yaml:"format"`      // "text" or "json"
	LogQueries bool   `yaml:"log_queries"` // Whether to log individual DNS queries (privacy sensitive)
}

// Setup initializes the global structured logger.
func Setup(cfg Config, w io.Writer) *slog.Logger {
	mu.Lock()
	defer mu.Unlock()

	if w == nil {
		w = os.Stdout
	}

	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(cfg.Level)) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.ToLower(strings.TrimSpace(cfg.Format)) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
	logQueries = cfg.LogQueries

	return defaultLogger
}

// L returns the current global logger.
func L() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLogger
}

// ShouldLogQueries returns true if DNS query details are permitted to be logged.
func ShouldLogQueries() bool {
	mu.RLock()
	defer mu.RUnlock()
	return logQueries
}

// LogQuery logs a DNS query if query logging is permitted.
// If query logging is disabled, this is a no-op to protect user privacy.
func LogQuery(ctx context.Context, clientIP string, qname string, qtype string, upstream string, latencyMs float64, err error) {
	if !ShouldLogQueries() {
		return
	}

	l := L()
	if err != nil {
		l.WarnContext(ctx, "dns query failed",
			slog.String("client", clientIP),
			slog.String("name", qname),
			slog.String("type", qtype),
			slog.String("upstream", upstream),
			slog.Float64("duration_ms", latencyMs),
			slog.String("error", err.Error()),
		)
	} else {
		l.DebugContext(ctx, "dns query handled",
			slog.String("client", clientIP),
			slog.String("name", qname),
			slog.String("type", qtype),
			slog.String("upstream", upstream),
			slog.Float64("duration_ms", latencyMs),
		)
	}
}
