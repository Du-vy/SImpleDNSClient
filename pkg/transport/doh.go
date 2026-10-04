package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// DoHTransport implements DNS-over-HTTPS (RFC 8484) over HTTP/2.
type DoHTransport struct {
	cfg        config.UpstreamConfig
	bootstrap  *bootstrap.Resolver
	endpointURL *url.URL
	httpClient *http.Client
	host       string
	port       int
	serverName string
}

// NewDoH creates a new DNS-over-HTTPS transport with HTTP/2 connection pooling.
func NewDoH(opts Options) (*DoHTransport, error) {
	endpointStr := opts.Config.Endpoint
	if !strings.HasPrefix(endpointStr, "http://") && !strings.HasPrefix(endpointStr, "https://") {
		endpointStr = "https://" + endpointStr
	}

	u, err := url.Parse(endpointStr)
	if err != nil {
		return nil, fmt.Errorf("invalid doh endpoint url '%s': %w", endpointStr, err)
	}

	host := u.Hostname()
	port := opts.Config.Port
	if port <= 0 {
		if u.Port() != "" {
			if p, err := net.LookupPort("tcp", u.Port()); err == nil {
				port = p
			}
		}
		if port <= 0 {
			port = 443
		}
	}

	serverName := opts.Config.Hostname
	if serverName == "" {
		if net.ParseIP(host) == nil {
			serverName = host
		}
	}

	tlsConfig := buildTLSConfig(serverName, opts.CustomRootCAs, []string{"h2", "http/1.1"})

	// Custom DialContext: Resolves target host via Bootstrap resolver to eliminate circular dependency
	baseDialer := &net.Dialer{
		Timeout:   clampTimeout(opts.Config.ConnectTimeout, 2*time.Second),
		KeepAlive: 30 * time.Second,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, pStr, err := net.SplitHostPort(addr)
		if err != nil {
			h = addr
			pStr = fmt.Sprintf("%d", port)
		}
		p, err := net.LookupPort(network, pStr)
		if err != nil {
			p = port
		}

		targetAddr, err := resolveTargetAddress(ctx, h, p, opts.Bootstrap, opts.Config.IPPreference)
		if err != nil {
			return nil, fmt.Errorf("doh dial resolution error for '%s': %w", h, err)
		}

		return baseDialer.DialContext(ctx, network, targetAddr)
	}

	httpTransport := &http.Transport{
		DialContext:           dialContext,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   clampTimeout(opts.Config.ConnectTimeout, 2*time.Second),
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Ensure HTTP/2 is configured on transport
	if err := http2.ConfigureTransport(httpTransport); err != nil {
		// Non-fatal, http.Transport supports HTTP/2 natively as well
	}

	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   clampTimeout(opts.Config.Timeout, 3*time.Second),
	}

	return &DoHTransport{
		cfg:         opts.Config,
		bootstrap:   opts.Bootstrap,
		endpointURL: u,
		httpClient:  httpClient,
		host:        host,
		port:        port,
		serverName:  serverName,
	}, nil
}

func (t *DoHTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	wire, err := dnsmsg.PackWire(query)
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns wire query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpointURL.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create doh http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "SimpleDNS/1.0")

	if t.serverName != "" {
		req.Host = t.serverName
	}

	httpResp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh http post error to %s: %w", t.endpointURL.String(), err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("doh server returned HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("failed to read doh response body: %w", err)
	}

	respMsg, err := dnsmsg.ParseWire(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse doh dns response: %w", err)
	}

	return respMsg, nil
}

func (t *DoHTransport) Close() error {
	t.httpClient.CloseIdleConnections()
	return nil
}

func (t *DoHTransport) Protocol() string {
	return config.TransportDoH
}

func (t *DoHTransport) Endpoint() string {
	return t.endpointURL.String()
}
