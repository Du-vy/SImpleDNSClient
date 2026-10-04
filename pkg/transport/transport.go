package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/miekg/dns"
)

var (
	ErrUnsupportedTransport = errors.New("unsupported dns transport protocol")
	ErrNoIPResolved         = errors.New("could not resolve IP for endpoint")
	ErrTransportClosed      = errors.New("dns transport is closed")
)

// Transport defines the common interface for all DNS transport protocols.
type Transport interface {
	// Exchange sends a DNS query and waits for the response.
	Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
	// Close terminates any active connections or background resources.
	Close() error
	// Protocol returns the protocol identifier (e.g. "udp", "tcp", "dot", "doh", "doh3", "doq").
	Protocol() string
	// Endpoint returns the human-readable upstream endpoint description.
	Endpoint() string
}

// Options contains parameters needed to initialize a transport.
type Options struct {
	Config          config.UpstreamConfig
	Bootstrap       *bootstrap.Resolver
	CustomRootCAs   *x509.CertPool
}

// NewTransport creates an initialized DNS transport based on configuration.
func NewTransport(opts Options) (Transport, error) {
	t := strings.ToLower(opts.Config.Transport)
	switch t {
	case config.TransportUDP:
		return NewUDP(opts)
	case config.TransportTCP:
		return NewTCP(opts)
	case config.TransportDoT:
		return NewDoT(opts)
	case config.TransportDoH:
		return NewDoH(opts)
	case config.TransportDoH3:
		return NewDoH3(opts)
	case config.TransportDoQ:
		return NewDoQ(opts)
	default:
		return nil, fmt.Errorf("%w: '%s'", ErrUnsupportedTransport, opts.Config.Transport)
	}
}

// buildTLSConfig creates a hardened crypto/tls.Config for encrypted transports.
// Strict certificate validation is enforced: InsecureSkipVerify is NEVER enabled.
func buildTLSConfig(serverName string, customCAs *x509.CertPool, nextProtos []string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            customCAs, // nil uses host system root CAs
		InsecureSkipVerify: false,     // Strict validation always enforced
		NextProtos:         nextProtos,
	}
}

// resolveTargetAddress resolves the host to an IP (if not already an IP) and formats host:port.
func resolveTargetAddress(ctx context.Context, endpointHost string, port int, b *bootstrap.Resolver, ipPref string) (string, error) {
	// If already an IP address
	if ip := net.ParseIP(endpointHost); ip != nil {
		if ip.To4() != nil {
			return fmt.Sprintf("%s:%d", ip.String(), port), nil
		}
		return fmt.Sprintf("[%s]:%d", ip.String(), port), nil
	}

	if b == nil {
		return "", fmt.Errorf("bootstrap resolver is required to resolve hostname '%s'", endpointHost)
	}

	ips, err := b.ResolveWithPreference(ctx, endpointHost, ipPref)
	if err != nil {
		return "", fmt.Errorf("failed to resolve endpoint hostname '%s': %w", endpointHost, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("%w for '%s'", ErrNoIPResolved, endpointHost)
	}

	// Pick first matching IP
	ip := ips[0]
	if ip.To4() != nil {
		return fmt.Sprintf("%s:%d", ip.String(), port), nil
	}
	return fmt.Sprintf("[%s]:%d", ip.String(), port), nil
}

// clampTimeout ensures a sensible timeout is used.
func clampTimeout(d, defaultVal time.Duration) time.Duration {
	if d <= 0 {
		return defaultVal
	}
	return d
}
