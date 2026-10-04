package listener

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

func TestLocalListenerInterceptor(t *testing.T) {
	// Pick an ephemeral port for testing
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get ephemeral port: %v", err)
	}
	testAddr := pc.LocalAddr().String()
	pc.Close()

	l, err := NewListener(config.ListenerConfig{
		ListenAddr: testAddr,
		Protocol:   "udp",
	})
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	handlerInvoked := false
	handler := func(ctx context.Context, clientAddr net.Addr, query *dns.Msg) (*dns.Msg, error) {
		handlerInvoked = true
		resp := dnsmsg.CreateResponse(query, dns.RcodeSuccess)
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   query.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: net.ParseIP("192.0.2.123").To4(),
		}
		resp.Answer = append(resp.Answer, rr)
		return resp, nil
	}

	if err := l.Start(context.Background(), handler); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer l.Stop()

	// Wait briefly for server startup
	time.Sleep(30 * time.Millisecond)

	// Send test query via standard dns.Client
	c := &dns.Client{Net: "udp", Timeout: 1 * time.Second}
	q := dnsmsg.NewQuery("listener.test", dns.TypeA)
	resp, _, err := c.Exchange(q, testAddr)
	if err != nil {
		t.Fatalf("failed to query listener: %v", err)
	}

	if !handlerInvoked {
		t.Errorf("expected handler to have been invoked")
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.123" {
		t.Fatalf("unexpected answer: %v", resp)
	}

	stats := l.Stats()
	if stats.QueriesHandled != 1 {
		t.Errorf("expected 1 handled query, got %d", stats.QueriesHandled)
	}
	if !stats.IsRunning {
		t.Errorf("expected IsRunning to be true")
	}
}
