package transport

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/miekg/dns"
)

// UDPTransport implements classic DNS over UDP with optional TCP fallback.
type UDPTransport struct {
	cfg          config.UpstreamConfig
	bootstrap    *bootstrap.Resolver
	client       *dns.Client
	tcpClient    *dns.Client
	host         string
	port         int
	targetAddr   string // Cached or pre-resolved target address
}

// NewUDP creates a new UDP DNS transport.
func NewUDP(opts Options) (*UDPTransport, error) {
	host := opts.Config.Endpoint
	port := opts.Config.Port
	if port <= 0 {
		port = 53
	}

	// Remove port from endpoint if present
	if h, pStr, err := net.SplitHostPort(host); err == nil {
		host = h
		if p, err := net.LookupPort("udp", pStr); err == nil {
			port = p
		}
	}

	timeout := clampTimeout(opts.Config.Timeout, 3*time.Second)

	t := &UDPTransport{
		cfg:       opts.Config,
		bootstrap: opts.Bootstrap,
		host:      host,
		port:      port,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
	}

	// If host is already an IP, pre-format targetAddr
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			t.targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
		} else {
			t.targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
		}
	}

	return t, nil
}

func (t *UDPTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	addr := t.targetAddr
	if addr == "" {
		resolved, err := resolveTargetAddress(ctx, t.host, t.port, t.bootstrap, t.cfg.IPPreference)
		if err != nil {
			return nil, err
		}
		addr = resolved
	}

	resp, _, err := t.client.ExchangeContext(ctx, query, addr)
	if err != nil {
		return nil, fmt.Errorf("udp dns exchange error with %s: %w", addr, err)
	}

	// Handle truncation (TC=1) with TCP fallback
	if resp != nil && resp.Truncated && t.cfg.AllowTCPFallback {
		tcpResp, _, tcpErr := t.tcpClient.ExchangeContext(ctx, query, addr)
		if tcpErr == nil && tcpResp != nil {
			return tcpResp, nil
		}
	}

	return resp, nil
}

func (t *UDPTransport) Close() error {
	return nil
}

func (t *UDPTransport) Protocol() string {
	return config.TransportUDP
}

func (t *UDPTransport) Endpoint() string {
	return fmt.Sprintf("udp://%s:%d", t.host, t.port)
}

// TCPTransport implements classic DNS over TCP.
type TCPTransport struct {
	cfg        config.UpstreamConfig
	bootstrap  *bootstrap.Resolver
	client     *dns.Client
	host       string
	port       int
	targetAddr string
}

// NewTCP creates a new TCP DNS transport.
func NewTCP(opts Options) (*TCPTransport, error) {
	host := opts.Config.Endpoint
	port := opts.Config.Port
	if port <= 0 {
		port = 53
	}

	if h, pStr, err := net.SplitHostPort(host); err == nil {
		host = h
		if p, err := net.LookupPort("tcp", pStr); err == nil {
			port = p
		}
	}

	timeout := clampTimeout(opts.Config.Timeout, 3*time.Second)

	t := &TCPTransport{
		cfg:       opts.Config,
		bootstrap: opts.Bootstrap,
		host:      host,
		port:      port,
		client: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			t.targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
		} else {
			t.targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
		}
	}

	return t, nil
}

func (t *TCPTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	addr := t.targetAddr
	if addr == "" {
		resolved, err := resolveTargetAddress(ctx, t.host, t.port, t.bootstrap, t.cfg.IPPreference)
		if err != nil {
			return nil, err
		}
		addr = resolved
	}

	resp, _, err := t.client.ExchangeContext(ctx, query, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dns exchange error with %s: %w", addr, err)
	}
	return resp, nil
}

func (t *TCPTransport) Close() error {
	return nil
}

func (t *TCPTransport) Protocol() string {
	return config.TransportTCP
}

func (t *TCPTransport) Endpoint() string {
	return fmt.Sprintf("tcp://%s:%d", t.host, t.port)
}
