package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/miekg/dns"
)

// DoTTransport implements DNS-over-TLS (RFC 7858) with persistent connection reuse.
type DoTTransport struct {
	cfg        config.UpstreamConfig
	bootstrap  *bootstrap.Resolver
	host       string
	port       int
	serverName string
	tlsConfig  *tls.Config
	timeout    time.Duration

	mu     sync.Mutex
	conn   *dns.Conn
	lastOp time.Time
	closed bool
}

// NewDoT creates a new DNS-over-TLS transport.
func NewDoT(opts Options) (*DoTTransport, error) {
	host := opts.Config.Endpoint
	port := opts.Config.Port
	if port <= 0 {
		port = 853
	}

	if h, pStr, err := net.SplitHostPort(host); err == nil {
		host = h
		if p, err := net.LookupPort("tcp", pStr); err == nil {
			port = p
		}
	}

	serverName := opts.Config.Hostname
	if serverName == "" {
		if net.ParseIP(host) == nil {
			serverName = host
		}
	}

	if serverName == "" {
		return nil, fmt.Errorf("dot transport requires a hostname for TLS certificate verification")
	}

	tlsConfig := buildTLSConfig(serverName, opts.CustomRootCAs, []string{"dot"})
	timeout := clampTimeout(opts.Config.Timeout, 3*time.Second)

	return &DoTTransport{
		cfg:        opts.Config,
		bootstrap:  opts.Bootstrap,
		host:       host,
		port:       port,
		serverName: serverName,
		tlsConfig:  tlsConfig,
		timeout:    timeout,
	}, nil
}

func (t *DoTTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, ErrTransportClosed
	}

	// Try existing connection first if idle for less than 10 seconds
	if t.conn != nil && time.Since(t.lastOp) < 10*time.Second {
		_ = t.conn.SetDeadline(time.Now().Add(t.timeout))
		if err := t.conn.WriteMsg(query); err == nil {
			resp, err := t.conn.ReadMsg()
			if err == nil && resp != nil {
				t.lastOp = time.Now()
				return resp, nil
			}
		}
		// Connection failed or timed out, close and re-establish
		_ = t.conn.Close()
		t.conn = nil
	}

	// Establish new connection
	conn, err := t.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dot dial error to %s:%d: %w", t.host, t.port, err)
	}

	_ = conn.SetDeadline(time.Now().Add(t.timeout))
	if err := conn.WriteMsg(query); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dot write error: %w", err)
	}

	resp, err := conn.ReadMsg()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dot read error: %w", err)
	}

	t.conn = conn
	t.lastOp = time.Now()
	return resp, nil
}

func (t *DoTTransport) dial(ctx context.Context) (*dns.Conn, error) {
	addr, err := resolveTargetAddress(ctx, t.host, t.port, t.bootstrap, t.cfg.IPPreference)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout: clampTimeout(t.cfg.ConnectTimeout, 2*time.Second),
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, t.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tls handshake failed with %s: %w", t.serverName, err)
	}

	return &dns.Conn{Conn: tlsConn}, nil
}

func (t *DoTTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

func (t *DoTTransport) Protocol() string {
	return config.TransportDoT
}

func (t *DoTTransport) Endpoint() string {
	return fmt.Sprintf("tls://%s:%d (%s)", t.host, t.port, t.serverName)
}
