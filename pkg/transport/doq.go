package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// DoQTransport implements DNS-over-QUIC (RFC 9250).
type DoQTransport struct {
	cfg        config.UpstreamConfig
	bootstrap  *bootstrap.Resolver
	host       string
	port       int
	serverName string
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	timeout    time.Duration

	mu     sync.Mutex
	conn   *quic.Conn
	closed bool
}

// NewDoQ creates a new DNS-over-QUIC transport.
func NewDoQ(opts Options) (*DoQTransport, error) {
	host := opts.Config.Endpoint
	port := opts.Config.Port
	if port <= 0 {
		port = 853
	}

	if h, pStr, err := net.SplitHostPort(host); err == nil {
		host = h
		if p, err := net.LookupPort("udp", pStr); err == nil {
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
		return nil, fmt.Errorf("doq transport requires a hostname for TLS certificate verification")
	}

	tlsConfig := buildTLSConfig(serverName, opts.CustomRootCAs, []string{"doq"})

	quicConfig := &quic.Config{
		HandshakeIdleTimeout: clampTimeout(opts.Config.ConnectTimeout, 3*time.Second),
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}

	timeout := clampTimeout(opts.Config.Timeout, 3*time.Second)

	return &DoQTransport{
		cfg:        opts.Config,
		bootstrap:  opts.Bootstrap,
		host:       host,
		port:       port,
		serverName: serverName,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		timeout:    timeout,
	}, nil
}

func (t *DoQTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	conn, err := t.getOrCreateConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq connection error: %w", err)
	}

	resp, err := t.exchangeOnConn(ctx, conn, query)
	if err != nil {
		// Connection may have failed, invalidate connection and retry once
		t.mu.Lock()
		if t.conn == conn {
			_ = t.conn.CloseWithError(0, "exchange failed")
			t.conn = nil
		}
		t.mu.Unlock()

		// Retry with new connection
		newConn, retryErr := t.getOrCreateConn(ctx)
		if retryErr != nil {
			return nil, fmt.Errorf("doq reconnect error after initial failure (%v): %w", err, retryErr)
		}
		return t.exchangeOnConn(ctx, newConn, query)
	}

	return resp, nil
}

func (t *DoQTransport) getOrCreateConn(ctx context.Context) (*quic.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, ErrTransportClosed
	}

	if t.conn != nil {
		// Check if connection is still healthy
		select {
		case <-t.conn.Context().Done():
			t.conn = nil
		default:
			return t.conn, nil
		}
	}

	targetAddr, err := resolveTargetAddress(ctx, t.host, t.port, t.bootstrap, t.cfg.IPPreference)
	if err != nil {
		return nil, fmt.Errorf("doq address resolution error for '%s': %w", t.host, err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, clampTimeout(t.cfg.ConnectTimeout, 3*time.Second))
	defer cancel()

	conn, err := quic.DialAddr(dialCtx, targetAddr, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("doq dial error to %s: %w", targetAddr, err)
	}

	t.conn = conn
	return conn, nil
}

func (t *DoQTransport) exchangeOnConn(ctx context.Context, conn *quic.Conn, query *dns.Msg) (*dns.Msg, error) {
	wire, err := dnsmsg.PackWire(query)
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns wire query: %w", err)
	}

	streamCtx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to open doq stream: %w", err)
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(t.timeout))

	// Write 2-byte prefix length + wire query
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := stream.Write(lenBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to write doq query length: %w", err)
	}
	if _, err := stream.Write(wire); err != nil {
		return nil, fmt.Errorf("failed to write doq query body: %w", err)
	}

	// RFC 9250 section 5.2: half-close stream to signal end of query
	_ = stream.Close()

	// Read 2-byte prefix length response
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read doq response length: %w", err)
	}

	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 || respLen > 65535 {
		return nil, fmt.Errorf("invalid doq response length %d", respLen)
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read doq response body: %w", err)
	}

	respMsg, err := dnsmsg.ParseWire(respBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse doq dns response: %w", err)
	}

	return respMsg, nil
}

func (t *DoQTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.conn != nil {
		err := t.conn.CloseWithError(0, "transport closed")
		t.conn = nil
		return err
	}
	return nil
}

func (t *DoQTransport) Protocol() string {
	return config.TransportDoQ
}

func (t *DoQTransport) Endpoint() string {
	return fmt.Sprintf("doq://%s:%d (%s)", t.host, t.port, t.serverName)
}
