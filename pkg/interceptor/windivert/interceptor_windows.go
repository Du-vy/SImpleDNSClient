//go:build windows
// +build windows

package windivert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/Du-vy/SImpleDNSClient/pkg/interceptor"
	"github.com/Du-vy/SImpleDNSClient/pkg/logger"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
)

var (
	ErrElevationRequired = errors.New("administrative privileges required for transparent DNS interception")
)

// WinDivertInterceptor intercepts system-wide outbound DNS packets without modifying Windows adapter settings.
type WinDivertInterceptor struct {
	cfg       config.WinDivertConfig
	handle    windows.Handle
	handler   interceptor.DNSHandler
	workers   int
	stopCh    chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	isRunning bool

	// Metrics
	captured uint64
	injected uint64
	handled  uint64
	failed   uint64
	dropped  uint64
}

// NewInterceptor creates a new WinDivert transparent DNS interceptor.
func NewInterceptor(cfg config.WinDivertConfig) (*WinDivertInterceptor, error) {
	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers < 2 {
			workers = 2
		}
	}

	return &WinDivertInterceptor{
		cfg:     cfg,
		workers: workers,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start opens the WinDivert device and spawns worker goroutines to handle captured packets.
func (wi *WinDivertInterceptor) Start(ctx context.Context, handler interceptor.DNSHandler) error {
	wi.mu.Lock()
	defer wi.mu.Unlock()

	if wi.isRunning {
		return errors.New("windivert interceptor is already running")
	}

	// 1. Verify elevation
	if !IsElevated() {
		return fmt.Errorf("%w: please run as Administrator or install as a Windows Service", ErrElevationRequired)
	}

	// 2. Build filter string
	filter := wi.cfg.Filter
	if filter == "" {
		if wi.cfg.TCPIntercept {
			filter = "outbound and !impostor and !loopback and (udp.DstPort == 53 or tcp.DstPort == 53)"
		} else {
			filter = "outbound and !impostor and !loopback and udp.DstPort == 53"
		}

		// Exclude bootstrap / exempt IPs to prevent circular interception loops
		if len(wi.cfg.ExemptIPs) > 0 {
			var v4Exempts []string
			var v6Exempts []string
			for _, s := range wi.cfg.ExemptIPs {
				host, _, err := net.SplitHostPort(s)
				if err != nil {
					host = s
				}
				ip := net.ParseIP(strings.TrimSpace(host))
				if ip != nil {
					if ip.To4() != nil {
						v4Exempts = append(v4Exempts, fmt.Sprintf("ip.DstAddr != %s", ip.String()))
					} else if ip.To16() != nil {
						v6Exempts = append(v6Exempts, fmt.Sprintf("ipv6.DstAddr != %s", ip.String()))
					}
				}
			}

			if len(v4Exempts) > 0 {
				filter += fmt.Sprintf(" and (!ip or (%s))", strings.Join(v4Exempts, " and "))
			}
			if len(v6Exempts) > 0 {
				filter += fmt.Sprintf(" and (!ipv6 or (%s))", strings.Join(v6Exempts, " and "))
			}
		}
	}

	logger.L().Info("opening WinDivert transparent capture handle",
		"filter", filter,
		"priority", wi.cfg.Priority,
		"workers", wi.workers,
	)

	// 3. Open WinDivert handle
	handle, err := Open(filter, LayerNetwork, wi.cfg.Priority, 0)
	if err != nil {
		return fmt.Errorf("failed to open WinDivert handle: %w (ensure WinDivert.dll and WinDivert64.sys are present)", err)
	}

	wi.handle = handle
	wi.handler = handler
	wi.isRunning = true
	wi.stopCh = make(chan struct{})

	// 4. Launch worker goroutines
	for i := 0; i < wi.workers; i++ {
		wi.wg.Add(1)
		go wi.worker(i)
	}

	logger.L().Info("WinDivert transparent DNS interception active",
		"mode", "system-wide kernel diversion",
		"adapters_modified", false,
	)

	return nil
}

func (wi *WinDivertInterceptor) worker(workerID int) {
	defer wi.wg.Done()

	// WinDivert maximum packet buffer size (64KB is sufficient for jumbo frames)
	packetBuf := make([]byte, 65535)
	var addr Address

	for {
		select {
		case <-wi.stopCh:
			return
		default:
		}

		recvLen, err := Recv(wi.handle, packetBuf, &addr)
		if err != nil {
			// Handle closure or error during shutdown
			select {
			case <-wi.stopCh:
				return
			default:
				// If not stopping, log and briefly yield
				time.Sleep(1 * time.Millisecond)
				continue
			}
		}

		atomic.AddUint64(&wi.captured, 1)

		rawPacket := packetBuf[:recvLen]
		parsed, err := ParsePacket(rawPacket)
		if err != nil {
			atomic.AddUint64(&wi.dropped, 1)
			continue
		}

		// Handle UDP DNS queries
		if parsed.Protocol == ProtocolUDP {
			go wi.handleUDPQuery(parsed, addr)
		} else {
			// Non-UDP or pass-through
			atomic.AddUint64(&wi.dropped, 1)
		}
	}
}

func (wi *WinDivertInterceptor) handleUDPQuery(parsed *ParsedPacket, origAddr Address) {
	queryMsg, err := dnsmsg.ParseWire(parsed.Payload)
	if err != nil {
		atomic.AddUint64(&wi.dropped, 1)
		return
	}

	clientAddr := &net.UDPAddr{
		IP:   parsed.SrcIP,
		Port: int(parsed.SrcPort),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	respMsg, err := wi.handler(ctx, clientAddr, queryMsg)
	if err != nil || respMsg == nil {
		atomic.AddUint64(&wi.failed, 1)
		// On resolution error, generate a SERVFAIL response matching client's query ID
		respMsg = dnsmsg.CreateErrorResponse(queryMsg, dns.RcodeServerFailure)
	}

	// Pack DNS response wire bytes
	respWire, err := dnsmsg.PackWire(respMsg)
	if err != nil {
		atomic.AddUint64(&wi.failed, 1)
		return
	}

	// Build spoofed inbound packet: swap IPs and ports, calculate RFC checksums
	respPacket, err := BuildUDPResponsePacket(parsed, respWire)
	if err != nil {
		atomic.AddUint64(&wi.failed, 1)
		return
	}

	// Prepare address structure for inbound injection
	injectAddr := origAddr
	injectAddr.SetOutbound(false) // Inbound towards client application
	injectAddr.SetImpostor(true)  // Mark as impostor so filter ignores it

	// Recalculate checksums using WinDivert helper or fallback
	HelperCalcChecksums(respPacket, &injectAddr, 0)

	// Send packet into the Windows network stack
	_, err = Send(wi.handle, respPacket, &injectAddr)
	if err != nil {
		atomic.AddUint64(&wi.failed, 1)
		logger.L().Debug("WinDivertSend error", "error", err)
		return
	}

	atomic.AddUint64(&wi.injected, 1)
	atomic.AddUint64(&wi.handled, 1)
}

// Stop cleanly terminates WinDivert packet diversion and unregisters WFP filters.
func (wi *WinDivertInterceptor) Stop() error {
	wi.mu.Lock()
	defer wi.mu.Unlock()

	if !wi.isRunning {
		return nil
	}

	wi.isRunning = false
	close(wi.stopCh)

	// Closing handle causes blocking WinDivertRecv calls to unblock immediately
	err := Close(wi.handle)
	wi.handle = InvalidHandle

	wi.wg.Wait()
	logger.L().Info("WinDivert transparent DNS interception stopped cleanly")
	return err
}

func (wi *WinDivertInterceptor) Name() string {
	return "windivert"
}

func (wi *WinDivertInterceptor) Stats() interceptor.Stats {
	wi.mu.Lock()
	running := wi.isRunning
	wi.mu.Unlock()

	return interceptor.Stats{
		Name:            wi.Name(),
		PacketsCaptured: atomic.LoadUint64(&wi.captured),
		PacketsInjected: atomic.LoadUint64(&wi.injected),
		QueriesHandled:  atomic.LoadUint64(&wi.handled),
		QueriesFailed:   atomic.LoadUint64(&wi.failed),
		DroppedPackets:  atomic.LoadUint64(&wi.dropped),
		ActiveWorkers:   wi.workers,
		IsRunning:       running,
	}
}
