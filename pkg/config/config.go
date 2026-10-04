package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Supported transports
const (
	TransportUDP  = "udp"
	TransportTCP  = "tcp"
	TransportDoT  = "dot"
	TransportDoH  = "doh"
	TransportDoH3 = "doh3"
	TransportDoQ  = "doq"
)

// Supported IP preferences
const (
	IPPreferenceDual       = "dual"
	IPPreferencePreferIPv4 = "prefer_ipv4"
	IPPreferencePreferIPv6 = "prefer_ipv6"
	IPPreferenceIPv4Only   = "ipv4_only"
	IPPreferenceIPv6Only   = "ipv6_only"
)

// Supported interception modes
const (
	ModeWinDivert = "windivert"
	ModeListener  = "listener"
	ModeAuto      = "auto"
)

// Supported selection strategies
const (
	StrategyPriority   = "priority"
	StrategyRoundRobin = "round_robin"
	StrategyFastest    = "fastest"
	StrategyParallel   = "parallel"
)

// Config represents the complete application configuration.
type Config struct {
	Logging     LoggingConfig     `yaml:"logging"`
	Interceptor InterceptorConfig `yaml:"interceptor"`
	Bootstrap   BootstrapConfig   `yaml:"bootstrap"`
	Routing     RoutingConfig     `yaml:"routing"`
	Cache       CacheConfig       `yaml:"cache"`
	Upstreams   []UpstreamConfig  `yaml:"upstreams"`
	Service     ServiceConfig     `yaml:"service"`
}

// LoggingConfig configures logging behavior.
type LoggingConfig struct {
	Level      string `yaml:"level"`       // "debug", "info", "warn", "error"
	Format     string `yaml:"format"`      // "text" or "json"
	LogQueries bool   `yaml:"log_queries"` // Whether to log query names (disabled by default for privacy)
}

// InterceptorConfig configures how DNS queries are intercepted on Windows.
type InterceptorConfig struct {
	Mode      string          `yaml:"mode"` // "windivert" (transparent default), "listener", or "auto"
	WinDivert WinDivertConfig `yaml:"windivert"`
	Listener  ListenerConfig  `yaml:"listener"`
}

// WinDivertConfig configures the transparent Windows Filtering Platform driver.
type WinDivertConfig struct {
	Priority       int16    `yaml:"priority"`         // Driver priority (default 0)
	Filter         string   `yaml:"filter"`           // Custom filter string; if empty, standard DNS filter is used
	TCPIntercept   bool     `yaml:"tcp_interception"` // Intercept outbound TCP port 53
	Workers        int      `yaml:"workers"`          // Packet processing worker goroutines
	ExemptIPs      []string `yaml:"exempt_ips"`       // Destination IPs exempt from interception (e.g. bootstrap DNS)
}

// ListenerConfig configures the optional fallback/testing local DNS listener.
type ListenerConfig struct {
	ListenAddr string `yaml:"listen_addr"` // e.g. "127.0.0.1:53" or "127.0.0.1:5354"
	Protocol   string `yaml:"protocol"`    // "both", "udp", or "tcp"
}

// BootstrapConfig configures resolution of upstream hostnames without circular dependencies.
type BootstrapConfig struct {
	Servers      []string      `yaml:"servers"`       // Configurable bootstrap DNS servers (must be raw IPs)
	Timeout      time.Duration `yaml:"timeout"`       // Timeout per bootstrap query
	Retries      int           `yaml:"retries"`       // Number of retries per server
	CacheTTL     time.Duration `yaml:"cache_ttl"`      // TTL for cached bootstrap resolutions
	IPPreference string        `yaml:"ip_preference"` // "dual", "prefer_ipv4", "prefer_ipv6", etc.
}

// RoutingConfig configures how queries are routed across upstreams.
type RoutingConfig struct {
	Strategy               string        `yaml:"strategy"`                 // "priority", "round_robin", "fastest"
	AllowPlaintextFallback bool          `yaml:"allow_plaintext_fallback"` // Disabled by default for privacy
	ProbeInterval          time.Duration `yaml:"probe_interval"`           // Health-check probe interval for degraded upstreams
	FailureThreshold       int           `yaml:"failure_threshold"`        // Consecutive failures before marking degraded
}

// CacheConfig configures the in-memory DNS query response cache.
type CacheConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MaxEntries  int           `yaml:"max_entries"`
	MinTTL      time.Duration `yaml:"min_ttl"`
	MaxTTL      time.Duration `yaml:"max_ttl"`
	NegativeTTL time.Duration `yaml:"negative_ttl"`
}

// UpstreamConfig defines a single DNS resolver endpoint.
type UpstreamConfig struct {
	Name             string        `yaml:"name"`               // Friendly name, e.g. "Cloudflare DoH"
	Transport        string        `yaml:"transport"`          // "udp", "tcp", "dot", "doh", "doh3", "doq"
	Endpoint         string        `yaml:"endpoint"`           // Hostname/IP or HTTPS URL
	Hostname         string        `yaml:"hostname"`           // Optional TLS SNI / certificate verification hostname
	Port             int           `yaml:"port"`               // Port (defaults based on transport)
	IPPreference     string        `yaml:"ip_preference"`     // "dual", "prefer_ipv4", "prefer_ipv6", etc.
	Timeout          time.Duration `yaml:"timeout"`           // Query timeout
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`   // Connection establishment timeout
	MaxRetries       int           `yaml:"max_retries"`       // Retries on transient errors
	Priority         int           `yaml:"priority"`          // Lower number = higher priority (1 is highest)
	Weight           int           `yaml:"weight"`            // For weighted round robin within same priority
	AllowTCPFallback bool          `yaml:"allow_tcp_fallback"`// Automatic fallback to TCP if UDP response is truncated
}

// ServiceConfig defines Windows Service properties.
type ServiceConfig struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"display_name"`
	Description string `yaml:"description"`
}

// DefaultConfig returns a fully configured, secure default configuration.
// By default, uses transparent WinDivert interception and well-known encrypted DNS providers
// (Cloudflare, Google, Quad9) with strict TLS validation and zero plaintext fallback.
func DefaultConfig() *Config {
	return &Config{
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			LogQueries: false, // Privacy default: do not log query domains
		},
		Interceptor: InterceptorConfig{
			Mode: ModeWinDivert, // Transparent interception by default (no 127.0.0.1 required)
			WinDivert: WinDivertConfig{
				Priority:     0,
				Filter:       "", // Default DNS filter constructed dynamically
				TCPIntercept: true,
				Workers:      4,
			},
			Listener: ListenerConfig{
				ListenAddr: "127.0.0.1:5354", // Alternative testing port
				Protocol:   "both",
			},
		},
		Bootstrap: BootstrapConfig{
			Servers: []string{
				"1.1.1.1:53",
				"8.8.8.8:53",
				"9.9.9.9:53",
			},
			Timeout:      2 * time.Second,
			Retries:      2,
			CacheTTL:     300 * time.Second,
			IPPreference: IPPreferencePreferIPv4,
		},
		Routing: RoutingConfig{
			Strategy:               StrategyPriority,
			AllowPlaintextFallback: false, // Strict privacy: do NOT leak queries to plaintext DNS on failure
			ProbeInterval:          30 * time.Second,
			FailureThreshold:       3,
		},
		Cache: CacheConfig{
			Enabled:     true,
			MaxEntries:  4096,
			MinTTL:      10 * time.Second,
			MaxTTL:      86400 * time.Second,
			NegativeTTL: 30 * time.Second,
		},
		Upstreams: []UpstreamConfig{
			{
				Name:           "Cloudflare DoH",
				Transport:      TransportDoH,
				Endpoint:       "https://cloudflare-dns.com/dns-query",
				Hostname:       "cloudflare-dns.com",
				Port:           443,
				IPPreference:   IPPreferenceDual,
				Timeout:        3 * time.Second,
				ConnectTimeout: 2 * time.Second,
				MaxRetries:     2,
				Priority:       1,
				Weight:         100,
			},
			{
				Name:           "Google DoH",
				Transport:      TransportDoH,
				Endpoint:       "https://dns.google/dns-query",
				Hostname:       "dns.google",
				Port:           443,
				IPPreference:   IPPreferenceDual,
				Timeout:        3 * time.Second,
				ConnectTimeout: 2 * time.Second,
				MaxRetries:     2,
				Priority:       1,
				Weight:         100,
			},
			{
				Name:           "Quad9 DoT",
				Transport:      TransportDoT,
				Endpoint:       "dns.quad9.net",
				Hostname:       "dns.quad9.net",
				Port:           853,
				IPPreference:   IPPreferenceDual,
				Timeout:        3 * time.Second,
				ConnectTimeout: 2 * time.Second,
				MaxRetries:     2,
				Priority:       2,
				Weight:         50,
			},
			{
				Name:           "Cloudflare DoH3",
				Transport:      TransportDoH3,
				Endpoint:       "https://cloudflare-dns.com/dns-query",
				Hostname:       "cloudflare-dns.com",
				Port:           443,
				IPPreference:   IPPreferenceDual,
				Timeout:        3 * time.Second,
				ConnectTimeout: 2 * time.Second,
				MaxRetries:     2,
				Priority:       2,
				Weight:         50,
			},
		},
		Service: ServiceConfig{
			Name:        "SimpleDNS",
			DisplayName: "SimpleDNS Secure Client",
			Description: "Transparent Windows DNS Client with DoH, DoT, DoQ, and DoH3 support",
		},
	}
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file '%s': %w", path, err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses configuration YAML bytes and validates the resulting Config.
func LoadFromBytes(data []byte) (*Config, error) {
	cfg := DefaultConfig()
	// Strict decoding: error on unknown fields to prevent silent misconfigurations
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("configuration syntax error: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation error: %w", err)
	}

	return cfg, nil
}

// Validate rigorously checks all fields of the Config.
func (c *Config) Validate() error {
	var errs []string

	// 1. Logging validation
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Sprintf("invalid logging level '%s' (expected debug, info, warn, error)", c.Logging.Level))
	}
	switch strings.ToLower(c.Logging.Format) {
	case "text", "json":
	default:
		errs = append(errs, fmt.Sprintf("invalid logging format '%s' (expected text or json)", c.Logging.Format))
	}

	// 2. Interceptor validation
	switch strings.ToLower(c.Interceptor.Mode) {
	case ModeWinDivert, ModeListener, ModeAuto:
	default:
		errs = append(errs, fmt.Sprintf("invalid interceptor mode '%s' (expected %s, %s, or %s)",
			c.Interceptor.Mode, ModeWinDivert, ModeListener, ModeAuto))
	}
	if c.Interceptor.WinDivert.Workers <= 0 {
		c.Interceptor.WinDivert.Workers = 4
	}
	if c.Interceptor.Mode == ModeListener || c.Interceptor.Mode == ModeAuto {
		if c.Interceptor.Listener.ListenAddr == "" {
			errs = append(errs, "listener listen_addr cannot be empty when listener mode is active")
		} else {
			if _, _, err := net.SplitHostPort(c.Interceptor.Listener.ListenAddr); err != nil {
				errs = append(errs, fmt.Sprintf("invalid listener listen_addr '%s': %v", c.Interceptor.Listener.ListenAddr, err))
			}
		}
	}

	// 3. Bootstrap validation
	if len(c.Bootstrap.Servers) == 0 {
		errs = append(errs, "bootstrap servers list cannot be empty")
	}
	for _, s := range c.Bootstrap.Servers {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			// Check if it's just an IP without port
			if ip := net.ParseIP(s); ip == nil {
				errs = append(errs, fmt.Sprintf("bootstrap server '%s' must be a raw IP address, not a hostname", s))
			}
		} else {
			if ip := net.ParseIP(host); ip == nil {
				errs = append(errs, fmt.Sprintf("bootstrap server host '%s' must be a raw IP address, not a hostname", host))
			}
		}
	}
	if c.Bootstrap.Timeout <= 0 {
		c.Bootstrap.Timeout = 2 * time.Second
	}
	if c.Bootstrap.Retries < 0 {
		c.Bootstrap.Retries = 2
	}
	if c.Bootstrap.CacheTTL <= 0 {
		c.Bootstrap.CacheTTL = 300 * time.Second
	}

	// 4. Routing strategy
	switch strings.ToLower(c.Routing.Strategy) {
	case StrategyPriority, StrategyRoundRobin, StrategyFastest, StrategyParallel:
	default:
		errs = append(errs, fmt.Sprintf("invalid routing strategy '%s' (expected %s, %s, %s, or %s)",
			c.Routing.Strategy, StrategyPriority, StrategyRoundRobin, StrategyFastest, StrategyParallel))
	}
	if c.Routing.ProbeInterval <= 0 {
		c.Routing.ProbeInterval = 30 * time.Second
	}
	if c.Routing.FailureThreshold <= 0 {
		c.Routing.FailureThreshold = 3
	}

	// 5. Cache validation
	if c.Cache.Enabled {
		if c.Cache.MaxEntries <= 0 {
			errs = append(errs, "cache max_entries must be greater than 0")
		}
		if c.Cache.MinTTL < 0 {
			c.Cache.MinTTL = 10 * time.Second
		}
		if c.Cache.MaxTTL <= 0 {
			c.Cache.MaxTTL = 86400 * time.Second
		}
		if c.Cache.MinTTL > c.Cache.MaxTTL {
			errs = append(errs, "cache min_ttl cannot be greater than max_ttl")
		}
	}

	// 6. Upstreams validation
	if len(c.Upstreams) == 0 {
		errs = append(errs, "at least one upstream DNS provider must be configured")
	}
	for i, u := range c.Upstreams {
		prefix := fmt.Sprintf("upstream[%d] ('%s')", i, u.Name)
		if u.Name == "" {
			errs = append(errs, fmt.Sprintf("%s name cannot be empty", prefix))
		}

		t := strings.ToLower(u.Transport)
		switch t {
		case TransportUDP, TransportTCP, TransportDoT, TransportDoH, TransportDoH3, TransportDoQ:
		default:
			errs = append(errs, fmt.Sprintf("%s unsupported transport '%s'", prefix, u.Transport))
		}

		if u.Endpoint == "" {
			errs = append(errs, fmt.Sprintf("%s endpoint cannot be empty", prefix))
		}

		// Validate URL format for DoH and DoH3
		if t == TransportDoH || t == TransportDoH3 {
			parsedURL, err := url.Parse(u.Endpoint)
			if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") {
				errs = append(errs, fmt.Sprintf("%s DoH endpoint must be a valid https URL, got '%s'", prefix, u.Endpoint))
			}
		}

		// Validate port
		if u.Port < 0 || u.Port > 65535 {
			errs = append(errs, fmt.Sprintf("%s invalid port %d (must be between 1 and 65535)", prefix, u.Port))
		}

		// Fill in default port if unspecified
		if c.Upstreams[i].Port == 0 {
			c.Upstreams[i].Port = defaultPortForTransport(t)
		}

		// Timeouts
		if c.Upstreams[i].Timeout <= 0 {
			c.Upstreams[i].Timeout = 3 * time.Second
		}
		if c.Upstreams[i].ConnectTimeout <= 0 {
			c.Upstreams[i].ConnectTimeout = 2 * time.Second
		}
		if c.Upstreams[i].MaxRetries < 0 {
			c.Upstreams[i].MaxRetries = 2
		}
		if c.Upstreams[i].Priority <= 0 {
			c.Upstreams[i].Priority = 1
		}
		if c.Upstreams[i].Weight <= 0 {
			c.Upstreams[i].Weight = 100
		}
	}

	// 7. Service config validation
	if c.Service.Name == "" {
		c.Service.Name = "SimpleDNS"
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func defaultPortForTransport(transport string) int {
	switch strings.ToLower(transport) {
	case TransportUDP, TransportTCP:
		return 53
	case TransportDoT, TransportDoQ:
		return 853
	case TransportDoH, TransportDoH3:
		return 443
	default:
		return 53
	}
}



// NormalizeServerAddr normalizes "ip:port" or "ip" string into host and port.
func NormalizeServerAddr(addr string, defaultPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified
		return addr, defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port '%s' in address '%s'", portStr, addr)
	}
	return host, port, nil
}
