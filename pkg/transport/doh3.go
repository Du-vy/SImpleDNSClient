package transport

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// DoH3Transport implements DNS-over-HTTPS over HTTP/3 (RFC 9114 / RFC 8484).
type DoH3Transport struct {
	cfg         config.UpstreamConfig
	bootstrap   *bootstrap.Resolver
	endpointURL *url.URL
	httpClient  *http.Client
	h3Transport *http3.Transport
	host        string
	port        int
	serverName  string
}

// NewDoH3 creates a new HTTP/3 DNS transport.
func NewDoH3(opts Options) (*DoH3Transport, error) {
	endpointStr := opts.Config.Endpoint
	if !strings.HasPrefix(endpointStr, "http://") && !strings.HasPrefix(endpointStr, "https://") {
		endpointStr = "https://" + endpointStr
	}

	u, err := url.Parse(endpointStr)
	if err != nil {
		return nil, fmt.Errorf("invalid doh3 endpoint url '%s': %w", endpointStr, err)
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

	tlsConfig := buildTLSConfig(serverName, opts.CustomRootCAs, []string{"h3"})

	quicConf := &quic.Config{
		HandshakeIdleTimeout: clampTimeout(opts.Config.ConnectTimeout, 3*time.Second),
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}

	h3Transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConf,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			h, pStr, err := net.SplitHostPort(addr)
			if err != nil {
				h = addr
				pStr = fmt.Sprintf("%d", port)
			}
			p, err := net.LookupPort("udp", pStr)
			if err != nil {
				p = port
			}

			targetAddr, err := resolveTargetAddress(ctx, h, p, opts.Bootstrap, opts.Config.IPPreference)
			if err != nil {
				return nil, fmt.Errorf("doh3 bootstrap dial error for '%s': %w", h, err)
			}

			return quic.DialAddr(ctx, targetAddr, tlsCfg, cfg)
		},
	}

	httpClient := &http.Client{
		Transport: h3Transport,
		Timeout:   clampTimeout(opts.Config.Timeout, 3*time.Second),
	}

	return &DoH3Transport{
		cfg:         opts.Config,
		bootstrap:   opts.Bootstrap,
		endpointURL: u,
		httpClient:  httpClient,
		h3Transport: h3Transport,
		host:        host,
		port:        port,
		serverName:  serverName,
	}, nil
}

func (t *DoH3Transport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	wire, err := dnsmsg.PackWire(query)
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns wire query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpointURL.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("failed to create doh3 http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "SimpleDNS/1.0 (HTTP3)")

	if t.serverName != "" {
		req.Host = t.serverName
	}

	httpResp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh3 http post error to %s: %w", t.endpointURL.String(), err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("doh3 server returned HTTP %d: %s", httpResp.StatusCode, string(body))
	}

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("failed to read doh3 response body: %w", err)
	}

	respMsg, err := dnsmsg.ParseWire(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse doh3 dns response: %w", err)
	}

	return respMsg, nil
}

func (t *DoH3Transport) Close() error {
	return t.h3Transport.Close()
}

func (t *DoH3Transport) Protocol() string {
	return config.TransportDoH3
}

func (t *DoH3Transport) Endpoint() string {
	return fmt.Sprintf("h3://%s", t.endpointURL.String())
}
