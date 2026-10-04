package dnsmsg

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNewQueryAndEDNS(t *testing.T) {
	q := NewQuery("example.com", dns.TypeA)
	if q.Id == 0 {
		t.Errorf("expected non-zero query ID")
	}
	if !q.RecursionDesired {
		t.Errorf("expected recursion desired to be set")
	}
	if len(q.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(q.Question))
	}
	if q.Question[0].Name != "example.com." {
		t.Errorf("expected normalized name 'example.com.', got %s", q.Question[0].Name)
	}
	if q.Question[0].Qtype != dns.TypeA {
		t.Errorf("expected type A, got %d", q.Question[0].Qtype)
	}

	opt := q.IsEdns0()
	if opt == nil {
		t.Fatalf("expected EDNS0 OPT record to be present")
	}
	if opt.UDPSize() != DefaultEDNSBufferSize {
		t.Errorf("expected EDNS UDP size %d, got %d", DefaultEDNSBufferSize, opt.UDPSize())
	}
}

func TestExtractQuestion(t *testing.T) {
	q := NewQuery("google.com.", dns.TypeAAAA)
	name, qtype, qclass, err := ExtractQuestion(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "google.com." || qtype != dns.TypeAAAA || qclass != dns.ClassINET {
		t.Errorf("extracted unexpected question fields: %s, %d, %d", name, qtype, qclass)
	}

	// Test empty message
	emptyMsg := new(dns.Msg)
	_, _, _, err = ExtractQuestion(emptyMsg)
	if err != ErrEmptyMessage {
		t.Errorf("expected ErrEmptyMessage, got %v", err)
	}

	// Test nil message
	_, _, _, err = ExtractQuestion(nil)
	if err != ErrNilMessage {
		t.Errorf("expected ErrNilMessage, got %v", err)
	}
}

func TestPackAndParseWire(t *testing.T) {
	q := NewQuery("cloudflare.com", dns.TypeHTTPS)
	packed, err := PackWire(q)
	if err != nil {
		t.Fatalf("failed to pack wire: %v", err)
	}

	parsed, err := ParseWire(packed)
	if err != nil {
		t.Fatalf("failed to parse wire: %v", err)
	}
	if parsed.Id != q.Id {
		t.Errorf("ID mismatch: %d vs %d", parsed.Id, q.Id)
	}
	if len(parsed.Question) != 1 || parsed.Question[0].Name != "cloudflare.com." {
		t.Errorf("question mismatch")
	}

	// Test malformed packet (< 12 bytes)
	_, err = ParseWire([]byte{1, 2, 3})
	if err == nil {
		t.Errorf("expected error parsing short packet, got nil")
	}
}

func TestCreateResponses(t *testing.T) {
	req := NewQuery("test.org", dns.TypeMX)

	// SERVFAIL
	servfail := CreateErrorResponse(req, dns.RcodeServerFailure)
	if servfail.Id != req.Id || servfail.Rcode != dns.RcodeServerFailure || !servfail.Response {
		t.Errorf("invalid SERVFAIL response created")
	}

	// Truncated (TC=1)
	truncated := CreateTruncatedResponse(req)
	if !truncated.Truncated || truncated.Id != req.Id {
		t.Errorf("invalid truncated response")
	}
}

func BenchmarkPackWire(b *testing.B) {
	q := NewQuery("benchmark.example.com", dns.TypeA)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = PackWire(q)
	}
}

func BenchmarkParseWire(b *testing.B) {
	q := NewQuery("benchmark.example.com", dns.TypeA)
	wire, _ := PackWire(q)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseWire(wire)
	}
}
