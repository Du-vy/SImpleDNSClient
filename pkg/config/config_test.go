package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got: %v", err)
	}
	if cfg.Routing.AllowPlaintextFallback {
		t.Fatalf("expected AllowPlaintextFallback to be false by default for privacy")
	}
	if cfg.Logging.LogQueries {
		t.Fatalf("expected LogQueries to be false by default for privacy")
	}
	if cfg.Interceptor.Mode != ModeWinDivert {
		t.Fatalf("expected default interceptor mode to be windivert (transparent), got %s", cfg.Interceptor.Mode)
	}
}

func TestLoadFromYAMLValid(t *testing.T) {
	yamlContent := `
logging:
  level: "debug"
  format: "json"
  log_queries: false

interceptor:
  mode: "windivert"
  windivert:
    workers: 8

bootstrap:
  servers:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  timeout: "1s"

routing:
  strategy: "round_robin"
  allow_plaintext_fallback: false

cache:
  enabled: true
  max_entries: 2048
  min_ttl: "5s"
  max_ttl: "3600s"

upstreams:
  - name: "Cloudflare DoT"
    transport: "dot"
    endpoint: "1.1.1.1"
    hostname: "cloudflare-dns.com"
    port: 853
    priority: 1
`
	cfg, err := LoadFromBytes([]byte(yamlContent))
	if err != nil {
		t.Fatalf("failed to load valid YAML config: %v", err)
	}

	if cfg.Logging.Level != "debug" {
		t.Errorf("expected level debug, got %s", cfg.Logging.Level)
	}
	if cfg.Routing.Strategy != StrategyRoundRobin {
		t.Errorf("expected strategy round_robin, got %s", cfg.Routing.Strategy)
	}
	if len(cfg.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].Transport != TransportDoT {
		t.Errorf("expected transport dot, got %s", cfg.Upstreams[0].Transport)
	}
	if cfg.Cache.MaxEntries != 2048 {
		t.Errorf("expected 2048 cache entries, got %d", cfg.Cache.MaxEntries)
	}
	if cfg.Cache.MinTTL != 5*time.Second {
		t.Errorf("expected 5s min TTL, got %v", cfg.Cache.MinTTL)
	}
}

func TestUnknownFieldStrictRejection(t *testing.T) {
	yamlContent := `
unknown_key_here: true
upstreams:
  - name: "Google"
    transport: "udp"
    endpoint: "8.8.8.8"
`
	_, err := LoadFromBytes([]byte(yamlContent))
	if err == nil {
		t.Fatalf("expected strict decoder to reject unknown field, but it succeeded")
	}
	if !strings.Contains(err.Error(), "unknown_key_here") && !strings.Contains(err.Error(), "field") {
		t.Logf("got error: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name          string
		modify        func(*Config)
		expectedError string
	}{
		{
			name: "invalid bootstrap server hostname",
			modify: func(c *Config) {
				c.Bootstrap.Servers = []string{"some.hostname.com:53"}
			},
			expectedError: "must be a raw IP address",
		},
		{
			name: "empty upstreams list",
			modify: func(c *Config) {
				c.Upstreams = nil
			},
			expectedError: "at least one upstream DNS provider",
		},
		{
			name: "unsupported transport",
			modify: func(c *Config) {
				c.Upstreams[0].Transport = "invalid-proto"
			},
			expectedError: "unsupported transport",
		},
		{
			name: "invalid doh url",
			modify: func(c *Config) {
				c.Upstreams[0].Transport = TransportDoH
				c.Upstreams[0].Endpoint = "not-a-valid-url"
			},
			expectedError: "valid https URL",
		},
		{
			name: "invalid cache min/max ttl",
			modify: func(c *Config) {
				c.Cache.MinTTL = 100 * time.Second
				c.Cache.MaxTTL = 10 * time.Second
			},
			expectedError: "cache min_ttl cannot be greater than max_ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing '%s', got nil", tt.expectedError)
			}
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Fatalf("expected error containing '%s', got '%v'", tt.expectedError, err)
			}
		})
	}
}
