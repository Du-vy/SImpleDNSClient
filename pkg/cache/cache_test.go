package cache

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

func createTestAnswer(name string, ipStr string, ttl uint32) *dns.Msg {
	req := dnsmsg.NewQuery(name, dns.TypeA)
	resp := dnsmsg.CreateResponse(req, dns.RcodeSuccess)
	ip := net.ParseIP(ipStr).To4()
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dnsmsg.NormalizeName(name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: ip,
	}
	resp.Answer = append(resp.Answer, rr)
	return resp
}

func TestCacheHitAndDynamicTTL(t *testing.T) {
	c := New(Config{
		Enabled:    true,
		MaxEntries: 10,
		MinTTL:     1 * time.Second,
		MaxTTL:     100 * time.Second,
	})

	q := dnsmsg.NewQuery("example.com", dns.TypeA)
	resp := createTestAnswer("example.com", "93.184.216.34", 60)

	c.Set(q, resp)

	// Fetch cached
	cached, found := c.Get(q)
	if !found {
		t.Fatalf("expected cache hit")
	}
	if len(cached.Answer) != 1 {
		t.Fatalf("expected 1 answer in cached response")
	}
	if cached.Answer[0].Header().Ttl > 60 {
		t.Errorf("expected TTL <= 60, got %d", cached.Answer[0].Header().Ttl)
	}

	stats := c.Stats()
	if stats.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.Hits)
	}
}

func TestCacheExpiration(t *testing.T) {
	c := New(Config{
		Enabled:    true,
		MaxEntries: 10,
		MinTTL:     10 * time.Millisecond,
		MaxTTL:     50 * time.Millisecond,
	})

	q := dnsmsg.NewQuery("expiring.org", dns.TypeA)
	resp := createTestAnswer("expiring.org", "1.2.3.4", 1) // 1 second, but capped or fast expiration
	c.Set(q, resp)

	// Sleep past expiration
	time.Sleep(60 * time.Millisecond)

	_, found := c.Get(q)
	if found {
		t.Fatalf("expected entry to be expired")
	}
	stats := c.Stats()
	if stats.Expired != 1 {
		t.Errorf("expected 1 expired count, got %d", stats.Expired)
	}
}

func TestCacheLRUEviction(t *testing.T) {
	maxEntries := 3
	c := New(Config{
		Enabled:    true,
		MaxEntries: maxEntries,
		MinTTL:     10 * time.Second,
		MaxTTL:     100 * time.Second,
	})

	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("domain%d.com", i)
		q := dnsmsg.NewQuery(name, dns.TypeA)
		resp := createTestAnswer(name, "1.1.1.1", 50)
		c.Set(q, resp)
	}

	stats := c.Stats()
	if stats.Size > maxEntries {
		t.Errorf("expected cache size <= %d, got %d", maxEntries, stats.Size)
	}
	if stats.Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", stats.Evictions)
	}

	// First item domain1.com should have been evicted
	firstQ := dnsmsg.NewQuery("domain1.com", dns.TypeA)
	_, found := c.Get(firstQ)
	if found {
		t.Errorf("expected domain1.com to have been evicted")
	}
}

func TestCacheNegativeResponse(t *testing.T) {
	c := New(Config{
		Enabled:     true,
		MaxEntries:  10,
		MinTTL:      1 * time.Second,
		MaxTTL:      60 * time.Second,
		NegativeTTL: 5 * time.Second,
	})

	q := dnsmsg.NewQuery("nonexistent.invalid", dns.TypeA)
	nxResp := dnsmsg.CreateResponse(q, dns.RcodeNameError)
	nxResp.Ns = append(nxResp.Ns, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "invalid.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Minttl: 10,
	})

	c.Set(q, nxResp)

	cached, found := c.Get(q)
	if !found {
		t.Fatalf("expected negative cache hit")
	}
	if cached.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN rcode, got %d", cached.Rcode)
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := New(Config{
		Enabled:    true,
		MaxEntries: 100,
		MinTTL:     1 * time.Second,
		MaxTTL:     60 * time.Second,
	})

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := fmt.Sprintf("concurrent-%d.com", i%20)
				q := dnsmsg.NewQuery(name, dns.TypeA)
				if i%2 == 0 {
					resp := createTestAnswer(name, "10.0.0.1", 30)
					c.Set(q, resp)
				} else {
					c.Get(q)
				}
			}
		}(w)
	}

	wg.Wait()
	stats := c.Stats()
	if stats.Size > 100 {
		t.Errorf("expected cache size <= 100, got %d", stats.Size)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := New(Config{Enabled: true, MaxEntries: 1000, MinTTL: time.Hour, MaxTTL: time.Hour})
	q := dnsmsg.NewQuery("bench.org", dns.TypeA)
	resp := createTestAnswer("bench.org", "1.2.3.4", 300)
	c.Set(q, resp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Get(q)
	}
}

func BenchmarkCacheParallel(b *testing.B) {
	c := New(Config{Enabled: true, MaxEntries: 1000, MinTTL: time.Hour, MaxTTL: time.Hour})
	q := dnsmsg.NewQuery("parallel.org", dns.TypeA)
	resp := createTestAnswer("parallel.org", "1.2.3.4", 300)
	c.Set(q, resp)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = c.Get(q)
		}
	})
}
