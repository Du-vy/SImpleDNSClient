package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

func TestEngineEndToEndWithListener(t *testing.T) {
	// 1. Start mock upstream DNS server on an ephemeral port
	upstreamPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	defer upstreamPC.Close()
	upstreamAddr := upstreamPC.LocalAddr().String()

	upstreamServer := &dns.Server{
		PacketConn: upstreamPC,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			resp := dnsmsg.CreateResponse(r, dns.RcodeSuccess)
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("198.51.100.99").To4(),
			}
			resp.Answer = append(resp.Answer, rr)
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = upstreamServer.ActivateAndServe() }()
	defer upstreamServer.Shutdown()

	// 2. Pick an ephemeral port for engine listener
	listenerPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get listener port: %v", err)
	}
	listenerAddr := listenerPC.LocalAddr().String()
	listenerPC.Close()

	// 3. Configure Engine with listener mode
	cfg := &config.Config{
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Interceptor: config.InterceptorConfig{
			Mode: config.ModeListener,
			Listener: config.ListenerConfig{
				ListenAddr: listenerAddr,
				Protocol:   "udp",
			},
		},
		Bootstrap: config.BootstrapConfig{
			Servers: []string{"127.0.0.1:53"},
		},
		Routing: config.RoutingConfig{
			Strategy:      config.StrategyPriority,
			ProbeInterval: 1 * time.Minute,
		},
		Cache: config.CacheConfig{
			Enabled:    true,
			MaxEntries: 100,
			MinTTL:     10 * time.Second,
			MaxTTL:     300 * time.Second,
		},
		Upstreams: []config.UpstreamConfig{
			{
				Name:      "MockUpstream",
				Transport: config.TransportUDP,
				Endpoint:  upstreamAddr,
			},
		},
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer eng.Stop()

	// Allow listener time to bind
	time.Sleep(30 * time.Millisecond)

	// 4. Send query 1 to engine listener
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	q := dnsmsg.NewQuery("e2e-test.org", dns.TypeA)
	resp1, _, err := c.Exchange(q, listenerAddr)
	if err != nil {
		t.Fatalf("first query failed: %v", err)
	}
	if len(resp1.Answer) != 1 || resp1.Answer[0].(*dns.A).A.String() != "198.51.100.99" {
		t.Fatalf("unexpected answer: %v", resp1)
	}

	// 5. Send query 2 (should be answered from cache)
	resp2, _, err := c.Exchange(q, listenerAddr)
	if err != nil {
		t.Fatalf("second query failed: %v", err)
	}
	if len(resp2.Answer) != 1 || resp2.Answer[0].(*dns.A).A.String() != "198.51.100.99" {
		t.Fatalf("unexpected cached answer: %v", resp2)
	}

	// 6. Check stats
	stats := eng.Stats()
	if stats.Interceptor.QueriesHandled != 2 {
		t.Errorf("expected 2 queries handled by interceptor, got %d", stats.Interceptor.QueriesHandled)
	}
	if stats.Cache.Hits != 1 {
		t.Errorf("expected 1 cache hit, got %d", stats.Cache.Hits)
	}
}
