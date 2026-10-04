package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/cache"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/Du-vy/SImpleDNSClient/pkg/interceptor"
	"github.com/Du-vy/SImpleDNSClient/pkg/interceptor/listener"
	"github.com/Du-vy/SImpleDNSClient/pkg/interceptor/windivert"
	"github.com/Du-vy/SImpleDNSClient/pkg/logger"
	"github.com/Du-vy/SImpleDNSClient/pkg/upstream"
	"github.com/miekg/dns"
)

// Engine is the central orchestrator coordinating interceptors, cache, and upstream routing.
type Engine struct {
	cfg         *config.Config
	cache       *cache.Cache
	bootstrap   *bootstrap.Resolver
	pool        *upstream.Pool
	interceptor interceptor.Interceptor

	mu        sync.RWMutex
	isRunning bool
	stopCh    chan struct{}
}

// EngineStats aggregates metrics from all subsystems.
type EngineStats struct {
	Interceptor interceptor.Stats
	Cache       cache.Stats
	Upstreams   []upstream.UpstreamStats
}

// New creates an initialized Engine from configuration.
func New(cfg *config.Config) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("configuration cannot be nil")
	}

	// 1. Initialize Cache
	c := cache.New(cache.Config{
		Enabled:     cfg.Cache.Enabled,
		MaxEntries:  cfg.Cache.MaxEntries,
		MinTTL:      cfg.Cache.MinTTL,
		MaxTTL:      cfg.Cache.MaxTTL,
		NegativeTTL: cfg.Cache.NegativeTTL,
	})

	// 2. Initialize Bootstrap Resolver
	b, err := bootstrap.NewResolver(cfg.Bootstrap)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bootstrap resolver: %w", err)
	}

	// 3. Initialize Upstream Pool
	p, err := upstream.NewPool(cfg.Routing, cfg.Upstreams, b)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize upstream pool: %w", err)
	}

	// 4. Select and Initialize Interceptor
	ic, err := selectInterceptor(cfg)
	if err != nil {
		_ = p.Close()
		return nil, err
	}

	return &Engine{
		cfg:         cfg,
		cache:       c,
		bootstrap:   b,
		pool:        p,
		interceptor: ic,
		stopCh:      make(chan struct{}),
	}, nil
}

func selectInterceptor(cfg *config.Config) (interceptor.Interceptor, error) {
	mode := cfg.Interceptor.Mode

	switch mode {
	case config.ModeWinDivert:
		if !windivert.IsElevated() {
			return nil, fmt.Errorf(
				"transparent DNS interception requires administrative privileges.\n" +
					"  - To run transparently: right-click simpledns.exe and select 'Run as administrator'\n" +
					"  - Or install as a Windows Service: 'simpledns service install'\n" +
					"  - Or run in local listener mode for testing: 'simpledns run --mode listener'",
			)
		}
		winCfg := cfg.Interceptor.WinDivert
		if len(winCfg.ExemptIPs) == 0 {
			winCfg.ExemptIPs = cfg.Bootstrap.Servers
		}
		return windivert.NewInterceptor(winCfg)

	case config.ModeListener:
		return listener.NewListener(cfg.Interceptor.Listener)

	case config.ModeAuto:
		if windivert.IsElevated() {
			winCfg := cfg.Interceptor.WinDivert
			if len(winCfg.ExemptIPs) == 0 {
				winCfg.ExemptIPs = cfg.Bootstrap.Servers
			}
			ic, err := windivert.NewInterceptor(winCfg)
			if err == nil {
				return ic, nil
			}
			logger.L().Warn("failed to initialize WinDivert in auto mode, falling back to local listener", "error", err)
		} else {
			logger.L().Warn("administrative privileges not detected, falling back to local listener (mode: auto)")
		}
		return listener.NewListener(cfg.Interceptor.Listener)

	default:
		return nil, fmt.Errorf("unknown interceptor mode '%s'", mode)
	}
}

// Start begins intercepting and handling queries.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isRunning {
		return errors.New("engine is already running")
	}

	logger.L().Info("starting SimpleDNS engine",
		"interceptor", e.interceptor.Name(),
		"upstreams", len(e.cfg.Upstreams),
		"cache_enabled", e.cfg.Cache.Enabled,
	)

	handler := func(qCtx context.Context, clientAddr net.Addr, query *dns.Msg) (*dns.Msg, error) {
		return e.handleDNSQuery(qCtx, clientAddr, query)
	}

	if err := e.interceptor.Start(ctx, handler); err != nil {
		return fmt.Errorf("failed to start interceptor: %w", err)
	}

	e.isRunning = true
	return nil
}

func (e *Engine) handleDNSQuery(ctx context.Context, clientAddr net.Addr, query *dns.Msg) (*dns.Msg, error) {
	if query == nil || len(query.Question) == 0 {
		return dnsmsg.CreateErrorResponse(query, dns.RcodeFormatError), nil
	}

	qName, qType, _, _ := dnsmsg.ExtractQuestion(query)
	qTypeStr := dns.TypeToString[qType]
	start := time.Now()

	// 1. Check in-memory DNS Cache
	if cachedResp, found := e.cache.Get(query); found {
		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
		logger.LogQuery(ctx, clientAddr.String(), qName, qTypeStr, "CACHE", latencyMs, nil)
		return cachedResp, nil
	}

	// 2. Resolve via Upstream Pool
	resp, upstreamName, err := e.pool.Resolve(ctx, query)
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		logger.LogQuery(ctx, clientAddr.String(), qName, qTypeStr, "FAILED", latencyMs, err)
		return nil, err
	}

	// 3. Store valid response in Cache
	if resp != nil {
		e.cache.Set(query, resp)
		logger.LogQuery(ctx, clientAddr.String(), qName, qTypeStr, upstreamName, latencyMs, nil)
	}

	return resp, nil
}

// Stop terminates the engine, interceptor, and background workers cleanly.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isRunning {
		return nil
	}

	e.isRunning = false

	var firstErr error
	if err := e.interceptor.Stop(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := e.pool.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	logger.L().Info("SimpleDNS engine stopped cleanly")
	return firstErr
}

// Stats returns a snapshot of current operational metrics across all subsystems.
func (e *Engine) Stats() EngineStats {
	return EngineStats{
		Interceptor: e.interceptor.Stats(),
		Cache:       e.cache.Stats(),
		Upstreams:   e.pool.Stats(),
	}
}
