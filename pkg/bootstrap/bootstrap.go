package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

var (
	ErrNoBootstrapServers = errors.New("no bootstrap servers configured")
	ErrResolutionFailed   = errors.New("bootstrap resolution failed on all servers")
	ErrRecursionDetected  = errors.New("circular dependency detected in bootstrap resolver")
)

type cachedResolution struct {
	ips      []net.IP
	expireAt time.Time
}

// Resolver resolves endpoint hostnames to IP addresses using configured bootstrap servers.
type Resolver struct {
	servers      []string
	timeout      time.Duration
	retries      int
	cacheTTL     time.Duration
	ipPreference string

	mu        sync.RWMutex
	cache     map[string]cachedResolution
	inFlight  map[string]chan struct{} // Singleflight deduplication
	dnsClient *dns.Client

	// Active ephemeral ports used by bootstrap client to allow WinDivert exemption
	portsMu sync.RWMutex
	ports   map[int]struct{}
}

// NewResolver creates a new bootstrap resolver from configuration.
func NewResolver(cfg config.BootstrapConfig) (*Resolver, error) {
	if len(cfg.Servers) == 0 {
		return nil, ErrNoBootstrapServers
	}

	// Normalize server addresses
	var servers []string
	for _, s := range cfg.Servers {
		host, port, err := config.NormalizeServerAddr(s, 53)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap server address '%s': %w", s, err)
		}
		servers = append(servers, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	retries := cfg.Retries
	if retries <= 0 {
		retries = 2
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 300 * time.Second
	}

	ipPref := cfg.IPPreference
	if ipPref == "" {
		ipPref = config.IPPreferencePreferIPv4
	}

	return &Resolver{
		servers:      servers,
		timeout:      timeout,
		retries:      retries,
		cacheTTL:     cacheTTL,
		ipPreference: ipPref,
		cache:        make(map[string]cachedResolution),
		inFlight:     make(map[string]chan struct{}),
		ports:        make(map[int]struct{}),
		dnsClient: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
	}, nil
}

// Resolve resolves a hostname to IP addresses.
// If host is already an IP address, it is parsed and returned immediately without network traffic.
func (r *Resolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	return r.ResolveWithPreference(ctx, host, r.ipPreference)
}

// ResolveWithPreference resolves a hostname with a specific IP preference.
func (r *Resolver) ResolveWithPreference(ctx context.Context, host string, preference string) ([]net.IP, error) {
	cleanHost := strings.TrimSpace(host)
	// Remove port if present
	if h, _, err := net.SplitHostPort(cleanHost); err == nil {
		cleanHost = h
	}

	// 1. If already an IP address, return immediately without network lookups
	if ip := net.ParseIP(cleanHost); ip != nil {
		return []net.IP{ip}, nil
	}

	key := strings.ToLower(cleanHost)

	// 2. Check cache
	r.mu.RLock()
	entry, found := r.cache[key]
	if found && time.Now().Before(entry.expireAt) {
		r.mu.RUnlock()
		return filterAndOrderIPs(entry.ips, preference), nil
	}
	r.mu.RUnlock()

	// 3. Singleflight deduplication to avoid thundering herd and accidental recursion
	r.mu.Lock()
	// Re-check after acquiring write lock
	if entry, found := r.cache[key]; found && time.Now().Before(entry.expireAt) {
		r.mu.Unlock()
		return filterAndOrderIPs(entry.ips, preference), nil
	}

	waitCh, inFlight := r.inFlight[key]
	if inFlight {
		r.mu.Unlock()
		select {
		case <-waitCh:
			// Completed by other goroutine, read from cache
			r.mu.RLock()
			entry, found := r.cache[key]
			r.mu.RUnlock()
			if found {
				return filterAndOrderIPs(entry.ips, preference), nil
			}
			return nil, ErrResolutionFailed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ch := make(chan struct{})
	r.inFlight[key] = ch
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.inFlight, key)
		close(ch)
		r.mu.Unlock()
	}()

	// 4. Perform actual DNS resolution against bootstrap servers
	ips, err := r.queryBootstrapServers(ctx, key, preference)
	if err != nil {
		// If resolution failed but we have stale cache, use stale cache as best-effort fallback
		r.mu.RLock()
		staleEntry, hasStale := r.cache[key]
		r.mu.RUnlock()
		if hasStale && len(staleEntry.ips) > 0 {
			return filterAndOrderIPs(staleEntry.ips, preference), nil
		}
		return nil, fmt.Errorf("bootstrap resolution error for '%s': %w", key, err)
	}

	// 5. Store in cache
	r.mu.Lock()
	r.cache[key] = cachedResolution{
		ips:      ips,
		expireAt: time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()

	return filterAndOrderIPs(ips, preference), nil
}

func (r *Resolver) queryBootstrapServers(ctx context.Context, hostname string, preference string) ([]net.IP, error) {
	var collectedIPs []net.IP
	var lastErr error

	typesToQuery := []uint16{dns.TypeA}
	switch preference {
	case config.IPPreferenceIPv6Only:
		typesToQuery = []uint16{dns.TypeAAAA}
	case config.IPPreferenceDual, config.IPPreferencePreferIPv6, config.IPPreferencePreferIPv4:
		typesToQuery = []uint16{dns.TypeA, dns.TypeAAAA}
	}

	// Try each bootstrap server until success
	for _, server := range r.servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		serverIPs := make([]net.IP, 0)
		serverSuccess := false

		for _, qtype := range typesToQuery {
			msg := dnsmsg.NewQuery(hostname, qtype)

			var resp *dns.Msg
			for attempt := 0; attempt <= r.retries; attempt++ {
				rResp, _, err := r.dnsClient.ExchangeContext(ctx, msg, server)
				if err == nil && rResp != nil && rResp.Rcode == dns.RcodeSuccess {
					resp = rResp
					break
				}
				lastErr = err
			}

			if resp != nil {
				serverSuccess = true
				for _, rr := range resp.Answer {
					switch record := rr.(type) {
					case *dns.A:
						serverIPs = append(serverIPs, record.A)
					case *dns.AAAA:
						serverIPs = append(serverIPs, record.AAAA)
					}
				}
			}
		}

		if serverSuccess && len(serverIPs) > 0 {
			collectedIPs = append(collectedIPs, serverIPs...)
			break // Successfully resolved via this bootstrap server
		}
	}

	if len(collectedIPs) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrResolutionFailed, lastErr)
		}
		return nil, ErrResolutionFailed
	}

	return collectedIPs, nil
}

func filterAndOrderIPs(ips []net.IP, preference string) []net.IP {
	var v4 []net.IP
	var v6 []net.IP

	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else if ip.To16() != nil {
			v6 = append(v6, ip)
		}
	}

	switch preference {
	case config.IPPreferenceIPv4Only:
		return v4
	case config.IPPreferenceIPv6Only:
		return v6
	case config.IPPreferencePreferIPv6:
		return append(v6, v4...)
	case config.IPPreferencePreferIPv4, config.IPPreferenceDual:
		fallthrough
	default:
		return append(v4, v6...)
	}
}

// Servers returns the list of configured bootstrap servers.
func (r *Resolver) Servers() []string {
	serversCopy := make([]string, len(r.servers))
	copy(serversCopy, r.servers)
	return serversCopy
}
