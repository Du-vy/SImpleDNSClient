package logger

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLoggerSetupAndQueryPrivacy(t *testing.T) {
	var buf bytes.Buffer

	// Test 1: Query logging disabled by default (Privacy preservation)
	cfg := Config{
		Level:      "debug",
		Format:     "json",
		LogQueries: false,
	}
	Setup(cfg, &buf)

	LogQuery(context.Background(), "127.0.0.1", "secret-domain.com.", "A", "Cloudflare", 12.5, nil)
	if strings.Contains(buf.String(), "secret-domain.com") {
		t.Fatalf("expected query not to be logged when LogQueries is false, but found: %s", buf.String())
	}

	// Test 2: Query logging explicitly enabled
	buf.Reset()
	cfg.LogQueries = true
	Setup(cfg, &buf)

	LogQuery(context.Background(), "127.0.0.1", "example.com.", "A", "Cloudflare", 5.2, nil)
	if !strings.Contains(buf.String(), "example.com") {
		t.Fatalf("expected query to be logged when LogQueries is true, got: %s", buf.String())
	}

	// Test 3: LogQuery with error
	buf.Reset()
	LogQuery(context.Background(), "127.0.0.1", "fail.com.", "AAAA", "Google", 100.0, errors.New("timeout"))
	if !strings.Contains(buf.String(), "timeout") || !strings.Contains(buf.String(), "fail.com") {
		t.Fatalf("expected error query to be logged, got: %s", buf.String())
	}
}
