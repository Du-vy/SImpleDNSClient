package upstream

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

// mockTransport is a test double for transport.Transport.
type mockTransport struct {
	protocol string
	endpoint string
	fail     bool
	answerIP string
}

func (m *mockTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if m.fail {
		return nil, errors.New("upstream connection reset")
	}
	resp := dnsmsg.CreateResponse(query, dns.RcodeSuccess)
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(m.answerIP).To4(),
	}
	resp.Answer = append(resp.Answer, rr)
	return resp, nil
}

func (m *mockTransport) Close() error {
	return nil
}

func (m *mockTransport) Protocol() string {
	return m.protocol
}

func (m *mockTransport) Endpoint() string {
	return m.endpoint
}

func TestPoolPriorityFailover(t *testing.T) {
	u1 := &Upstream{
		Config: config.UpstreamConfig{
			Name:       "Primary-Failing",
			Transport:  config.TransportDoH,
			Priority:   1,
			MaxRetries: 1,
		},
		Transport: &mockTransport{fail: true, endpoint: "https://fail.com"},
		state:     StateHealthy,
	}

	u2 := &Upstream{
		Config: config.UpstreamConfig{
			Name:       "Secondary-Working",
			Transport:  config.TransportDoT,
			Priority:   2,
			MaxRetries: 1,
		},
		Transport: &mockTransport{fail: false, answerIP: "1.1.1.1", endpoint: "1.1.1.1:853"},
		state:     StateHealthy,
	}

	p := &Pool{
		cfg: config.RoutingConfig{
			Strategy:               config.StrategyPriority,
			AllowPlaintextFallback: false,
		},
		upstreams: []*Upstream{u1, u2},
		stopCh:    make(chan struct{}),
	}

	query := dnsmsg.NewQuery("example.com", dns.TypeA)
	resp, name, err := p.Resolve(context.Background(), query)
	if err != nil {
		t.Fatalf("expected failover to succeed, got error: %v", err)
	}
	if name != "Secondary-Working" {
		t.Errorf("expected resolution by Secondary-Working, got %s", name)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("unexpected answer: %v", resp)
	}

	// Verify Primary was marked with a failure
	u1.mu.RLock()
	if u1.failedQueries != 1 {
		t.Errorf("expected 1 failed query on primary, got %d", u1.failedQueries)
	}
	u1.mu.RUnlock()
}

func TestPoolAllUpstreamsFailPrivacy(t *testing.T) {
	u1 := &Upstream{
		Config: config.UpstreamConfig{
			Name:       "Upstream-1",
			Transport:  config.TransportDoH,
			Priority:   1,
			MaxRetries: 0,
		},
		Transport: &mockTransport{fail: true, endpoint: "https://fail1.com"},
		state:     StateHealthy,
	}

	p := &Pool{
		cfg: config.RoutingConfig{
			Strategy:               config.StrategyPriority,
			AllowPlaintextFallback: false, // Privacy: no plaintext fallback
		},
		upstreams: []*Upstream{u1},
		stopCh:    make(chan struct{}),
	}

	query := dnsmsg.NewQuery("secret.internal", dns.TypeA)
	_, _, err := p.Resolve(context.Background(), query)
	if err == nil {
		t.Fatalf("expected error when all upstreams fail and fallback is disabled")
	}
	if !errors.Is(err, ErrAllUpstreamsFailed) {
		t.Errorf("expected ErrAllUpstreamsFailed, got: %v", err)
	}
}

func TestPoolRoundRobin(t *testing.T) {
	u1 := &Upstream{
		Config:    config.UpstreamConfig{Name: "U1", Transport: "doh", Priority: 1},
		Transport: &mockTransport{fail: false, answerIP: "1.1.1.1"},
		state:     StateHealthy,
	}
	u2 := &Upstream{
		Config:    config.UpstreamConfig{Name: "U2", Transport: "dot", Priority: 1},
		Transport: &mockTransport{fail: false, answerIP: "2.2.2.2"},
		state:     StateHealthy,
	}

	p := &Pool{
		cfg: config.RoutingConfig{
			Strategy: config.StrategyRoundRobin,
		},
		upstreams: []*Upstream{u1, u2},
		stopCh:    make(chan struct{}),
	}

	query := dnsmsg.NewQuery("rr.test", dns.TypeA)

	_, name1, _ := p.Resolve(context.Background(), query)
	_, name2, _ := p.Resolve(context.Background(), query)

	if name1 == name2 {
		t.Errorf("expected round robin to alternate, got %s then %s", name1, name2)
	}
}

func TestPoolNewFromConfig(t *testing.T) {
	b, _ := bootstrap.NewResolver(config.BootstrapConfig{
		Servers: []string{"1.1.1.1:53"},
	})

	cfg := config.RoutingConfig{
		Strategy:      config.StrategyPriority,
		ProbeInterval: 1 * time.Minute,
	}
	upstreams := []config.UpstreamConfig{
		{
			Name:      "Cloudflare UDP",
			Transport: config.TransportUDP,
			Endpoint:  "1.1.1.1",
			Port:      53,
		},
	}

	pool, err := NewPool(cfg, upstreams, b)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	stats := pool.Stats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 upstream in stats, got %d", len(stats))
	}
	if stats[0].Name != "Cloudflare UDP" {
		t.Errorf("unexpected name in stats: %s", stats[0].Name)
	}
}

type delayedTransport struct {
	delay    time.Duration
	answerIP string
	fail     bool
}

func (d *delayedTransport) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if d.fail {
		return nil, errors.New("upstream failed")
	}

	resp := dnsmsg.CreateResponse(query, dns.RcodeSuccess)
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(d.answerIP).To4(),
	}
	resp.Answer = append(resp.Answer, rr)
	return resp, nil
}

func (d *delayedTransport) Close() error   { return nil }
func (d *delayedTransport) Protocol() string { return "test" }
func (d *delayedTransport) Endpoint() string { return "test" }

func TestPoolParallelQueries(t *testing.T) {
	slowUpstream := &Upstream{
		Config:    config.UpstreamConfig{Name: "Slow", Transport: "doh", Priority: 1},
		Transport: &delayedTransport{delay: 60 * time.Millisecond, answerIP: "1.1.1.1"},
		state:     StateHealthy,
	}

	fastUpstream := &Upstream{
		Config:    config.UpstreamConfig{Name: "Fast", Transport: "dot", Priority: 1},
		Transport: &delayedTransport{delay: 5 * time.Millisecond, answerIP: "2.2.2.2"},
		state:     StateHealthy,
	}

	p := &Pool{
		cfg: config.RoutingConfig{
			Strategy: config.StrategyParallel,
		},
		upstreams: []*Upstream{slowUpstream, fastUpstream},
		stopCh:    make(chan struct{}),
	}

	query := dnsmsg.NewQuery("parallel.test", dns.TypeA)
	resp, name, err := p.Resolve(context.Background(), query)
	if err != nil {
		t.Fatalf("expected parallel query to succeed, got: %v", err)
	}

	// Fast upstream must win the race
	if name != "Fast" {
		t.Errorf("expected Fast upstream to win race, got: %s", name)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatalf("unexpected answer: %v", resp)
	}
}
