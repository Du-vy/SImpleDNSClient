package dnsmsg

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DefaultEDNSBufferSize is the recommended DNS Flag Day 2020 buffer size
// to prevent fragmentation over IPv4/IPv6 networks while accommodating larger payloads.
const DefaultEDNSBufferSize = 1232

var (
	ErrEmptyMessage     = errors.New("dns message has no questions")
	ErrNilMessage       = errors.New("dns message is nil")
	ErrMalformedMessage = errors.New("malformed dns wire format")
)

// GenerateID produces a cryptographically secure random 16-bit DNS query ID.
func GenerateID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based pseudo-random if crypto/rand fails
		return uint16(binary.LittleEndian.Uint16(b[:]))
	}
	return binary.BigEndian.Uint16(b[:])
}

// NormalizeName ensures domain names are lowercase and end with a trailing dot.
func NormalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// NewQuery creates a standard DNS query message with EDNS0 enabled.
func NewQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Id = GenerateID()
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{
			Name:   NormalizeName(name),
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		},
	}
	EnsureEDNS(m, DefaultEDNSBufferSize, false)
	return m
}

// EnsureEDNS ensures an EDNS0 OPT record is present in the message.
// If already present, updates UDP buffer size if needed and preserves or sets DO (DNSSEC OK) bit.
func EnsureEDNS(msg *dns.Msg, bufSize uint16, doBit bool) {
	if msg == nil {
		return
	}
	if bufSize == 0 {
		bufSize = DefaultEDNSBufferSize
	}

	opt := msg.IsEdns0()
	if opt != nil {
		if opt.UDPSize() < bufSize {
			opt.SetUDPSize(bufSize)
		}
		if doBit {
			opt.SetDo()
		}
		return
	}

	msg.SetEdns0(bufSize, doBit)
}

// ExtractQuestion retrieves the primary question from a DNS message.
func ExtractQuestion(msg *dns.Msg) (name string, qtype uint16, qclass uint16, err error) {
	if msg == nil {
		return "", 0, 0, ErrNilMessage
	}
	if len(msg.Question) == 0 {
		return "", 0, 0, ErrEmptyMessage
	}
	q := msg.Question[0]
	return NormalizeName(q.Name), q.Qtype, q.Qclass, nil
}

// FormatQuestion returns a human-readable representation of the first question.
func FormatQuestion(msg *dns.Msg) string {
	if msg == nil || len(msg.Question) == 0 {
		return "<empty>"
	}
	q := msg.Question[0]
	return fmt.Sprintf("%s %s %s", q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
}

// CreateResponse creates a reply skeleton from a request, preserving query ID and question.
func CreateResponse(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	if req != nil {
		resp.SetReply(req)
	} else {
		resp.Id = GenerateID()
		resp.Response = true
	}
	resp.Rcode = rcode
	return resp
}

// CreateErrorResponse creates a standard error response (e.g. SERVFAIL, REFUSED).
func CreateErrorResponse(req *dns.Msg, rcode int) *dns.Msg {
	return CreateResponse(req, rcode)
}

// CreateTruncatedResponse creates a response with the TC (Truncated) bit set.
// This indicates to the client that it should retry over TCP.
func CreateTruncatedResponse(req *dns.Msg) *dns.Msg {
	resp := CreateResponse(req, dns.RcodeSuccess)
	resp.Truncated = true
	return resp
}

// ParseWire decodes wire-format bytes into a dns.Msg.
func ParseWire(data []byte) (*dns.Msg, error) {
	if len(data) < 12 { // Standard DNS header is 12 bytes
		return nil, ErrMalformedMessage
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
	}
	return msg, nil
}

// PackWire encodes a dns.Msg into wire-format bytes.
func PackWire(msg *dns.Msg) ([]byte, error) {
	if msg == nil {
		return nil, ErrNilMessage
	}
	data, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns message: %w", err)
	}
	return data, nil
}

// HasDNSSEC returns true if the message has DNSSEC DO bit set.
func HasDNSSEC(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	opt := msg.IsEdns0()
	return opt != nil && opt.Do()
}
