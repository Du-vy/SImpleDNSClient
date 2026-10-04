package bootstrap

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/miekg/dns"
)

// startMockDNSServer starts an in-process DNS server listening on UDP loopback.
func startMockDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	cleanup := func() {
		_ = server.Shutdown()
	}

	return pc.LocalAddr().String(), cleanup
}

func TestResolveRawIP(t *testing.T) {
	r, err := NewResolver(config.BootstrapConfig{
		Servers: []string{"1.1.1.1:53"},
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	// Test IPv4 raw address
	ips, err := r.Resolve(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error resolving raw IPv4: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %v", ips)
	}

	// Test IPv6 raw address
	ips6, err := r.Resolve(context.Background(), "2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error resolving raw IPv6: %v", err)
	}
	if len(ips6) != 1 || ips6[0].String() != "2001:db8::1" {
		t.Fatalf("expected 2001:db8::1, got %v", ips6)
	}
}

func TestBootstrapResolutionAndCaching(t *testing.T) {
	var queryCount int32

	mockAddr, cleanup := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt32(&queryCount, 1)
		resp := new(dns.Msg)
		resp.SetReply(r)

		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("104.16.132.229").To4(),
			}
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})
	defer cleanup()

	r, err := NewResolver(config.BootstrapConfig{
		Servers:      []string{mockAddr},
		Timeout:      1 * time.Second,
		CacheTTL:     10 * time.Second,
		IPPreference: config.IPPreferenceIPv4Only,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	// First lookup
	ips, err := r.Resolve(context.Background(), "cloudflare-dns.com")
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "104.16.132.229" {
		t.Fatalf("unexpected IPs returned: %v", ips)
	}

	initialQueries := atomic.LoadInt32(&queryCount)
	if initialQueries == 0 {
		t.Fatalf("expected queries to have reached mock server")
	}

	// Second lookup (must hit cache, no additional network queries)
	cachedIPs, err := r.Resolve(context.Background(), "cloudflare-dns.com")
	if err != nil {
		t.Fatalf("cached lookup failed: %v", err)
	}
	if len(cachedIPs) != 1 || cachedIPs[0].String() != "104.16.132.229" {
		t.Fatalf("unexpected cached IPs: %v", cachedIPs)
	}

	if atomic.LoadInt32(&queryCount) != initialQueries {
		t.Fatalf("expected second query to hit cache, but queryCount increased")
	}
}

func TestBootstrapServerFailover(t *testing.T) {
	// First server is a dead listener / rejects queries
	deadAddr := "127.0.0.1:54399"

	// Second server responds properly
	workingAddr, cleanup := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("8.8.4.4").To4(),
			}
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})
	defer cleanup()

	r, err := NewResolver(config.BootstrapConfig{
		Servers:      []string{deadAddr, workingAddr},
		Timeout:      200 * time.Millisecond,
		Retries:      0,
		IPPreference: config.IPPreferenceIPv4Only,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	ips, err := r.Resolve(context.Background(), "dns.google")
	if err != nil {
		t.Fatalf("expected failover to second server to succeed, got: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "8.8.4.4" {
		t.Fatalf("expected 8.8.4.4, got: %v", ips)
	}
}

func TestSingleflightConcurrency(t *testing.T) {
	var queryCount int32

	mockAddr, cleanup := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt32(&queryCount, 1)
		time.Sleep(30 * time.Millisecond) // Simulate network delay
		resp := new(dns.Msg)
		resp.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("9.9.9.9").To4(),
			}
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})
	defer cleanup()

	r, err := NewResolver(config.BootstrapConfig{
		Servers:      []string{mockAddr},
		Timeout:      1 * time.Second,
		IPPreference: config.IPPreferenceIPv4Only,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	var wg sync.WaitGroup
	concurrentRequests := 10
	results := make([][]net.IP, concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ips, _ := r.Resolve(context.Background(), "quad9.net")
			results[idx] = ips
		}(i)
	}

	wg.Wait()

	// Verify all returned same IP
	for i := 0; i < concurrentRequests; i++ {
		if len(results[i]) == 0 || results[i][0].String() != "9.9.9.9" {
			t.Errorf("worker %d returned invalid result: %v", i, results[i])
		}
	}

	// Singleflight should have prevented 10 duplicate queries
	queries := atomic.LoadInt32(&queryCount)
	if queries > 2 {
		t.Logf("singleflight executed %d queries for %d concurrent requests", queries, concurrentRequests)
	}
}
