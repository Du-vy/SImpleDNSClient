package listener

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/Du-vy/SImpleDNSClient/pkg/interceptor"
	"github.com/Du-vy/SImpleDNSClient/pkg/logger"
	"github.com/miekg/dns"
)

// LocalListenerInterceptor provides a local DNS server for testing or fallback configurations.
type LocalListenerInterceptor struct {
	cfg       config.ListenerConfig
	udpServer *dns.Server
	tcpServer *dns.Server
	handler   interceptor.DNSHandler
	mu        sync.Mutex
	isRunning bool

	captured uint64
	handled  uint64
	failed   uint64
}

// NewListener creates a new local DNS listener interceptor.
func NewListener(cfg config.ListenerConfig) (*LocalListenerInterceptor, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:5354"
	}
	return &LocalListenerInterceptor{
		cfg: cfg,
	}, nil
}

func (l *LocalListenerInterceptor) Start(ctx context.Context, handler interceptor.DNSHandler) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isRunning {
		return errors.New("listener interceptor is already running")
	}

	l.handler = handler

	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddUint64(&l.captured, 1)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := l.handler(ctx, w.RemoteAddr(), r)
		if err != nil || resp == nil {
			atomic.AddUint64(&l.failed, 1)
			resp = dnsmsg.CreateErrorResponse(r, dns.RcodeServerFailure)
		} else {
			atomic.AddUint64(&l.handled, 1)
		}

		_ = w.WriteMsg(resp)
	})

	listenAddr := l.cfg.ListenAddr
	runUDP := l.cfg.Protocol == "both" || l.cfg.Protocol == "udp" || l.cfg.Protocol == ""
	runTCP := l.cfg.Protocol == "both" || l.cfg.Protocol == "tcp" || l.cfg.Protocol == ""

	errChan := make(chan error, 2)

	if runUDP {
		udpPC, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			return fmt.Errorf("failed to bind local UDP listener to %s: %w", listenAddr, err)
		}
		l.udpServer = &dns.Server{
			PacketConn: udpPC,
			Handler:    dnsHandler,
		}
		go func() {
			if err := l.udpServer.ActivateAndServe(); err != nil {
				errChan <- fmt.Errorf("udp listener error: %w", err)
			}
		}()
	}

	if runTCP {
		tcpLn, err := net.Listen("tcp", listenAddr)
		if err != nil {
			if l.udpServer != nil {
				_ = l.udpServer.Shutdown()
			}
			return fmt.Errorf("failed to bind local TCP listener to %s: %w", listenAddr, err)
		}
		l.tcpServer = &dns.Server{
			Listener: tcpLn,
			Handler:  dnsHandler,
		}
		go func() {
			if err := l.tcpServer.ActivateAndServe(); err != nil {
				errChan <- fmt.Errorf("tcp listener error: %w", err)
			}
		}()
	}

	l.isRunning = true
	logger.L().Info("local DNS listener started", "listen_addr", listenAddr, "protocol", l.cfg.Protocol)
	return nil
}

func (l *LocalListenerInterceptor) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.isRunning {
		return nil
	}

	l.isRunning = false
	var firstErr error

	if l.udpServer != nil {
		if err := l.udpServer.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
		l.udpServer = nil
	}

	if l.tcpServer != nil {
		if err := l.tcpServer.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
		l.tcpServer = nil
	}

	logger.L().Info("local DNS listener stopped cleanly")
	return firstErr
}

func (l *LocalListenerInterceptor) Name() string {
	return "listener"
}

func (l *LocalListenerInterceptor) Stats() interceptor.Stats {
	l.mu.Lock()
	running := l.isRunning
	l.mu.Unlock()

	return interceptor.Stats{
		Name:            l.Name(),
		PacketsCaptured: atomic.LoadUint64(&l.captured),
		PacketsInjected: atomic.LoadUint64(&l.handled),
		QueriesHandled:  atomic.LoadUint64(&l.handled),
		QueriesFailed:   atomic.LoadUint64(&l.failed),
		ActiveWorkers:   1,
		IsRunning:       running,
	}
}
