package interceptor

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

// DNSHandler is the callback invoked when a DNS query is intercepted.
// It receives the client's network address and parsed DNS query, and returns the response.
type DNSHandler func(ctx context.Context, clientAddr net.Addr, query *dns.Msg) (*dns.Msg, error)

// Stats holds operational metrics for an interceptor.
type Stats struct {
	Name            string
	PacketsCaptured uint64
	PacketsInjected uint64
	QueriesHandled  uint64
	QueriesFailed   uint64
	DroppedPackets  uint64
	ActiveWorkers   int
	IsRunning       bool
}

// Interceptor defines the common interface for traffic interception backends.
type Interceptor interface {
	// Start begins intercepting DNS queries and passes them to the handler.
	Start(ctx context.Context, handler DNSHandler) error
	// Stop halts interception and releases all kernel/network resources cleanly.
	Stop() error
	// Name returns the interceptor type ("windivert" or "listener").
	Name() string
	// Stats returns operational metrics.
	Stats() Stats
}
