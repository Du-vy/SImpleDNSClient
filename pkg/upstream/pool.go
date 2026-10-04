package upstream

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/Du-vy/SImpleDNSClient/pkg/logger"
	"github.com/Du-vy/SImpleDNSClient/pkg/transport"
	"github.com/miekg/dns"
)

var (
	ErrNoUpstreamsAvailable = errors.New("no upstream resolvers available")
	ErrAllUpstreamsFailed   = errors.New("all upstream resolvers failed to answer")
)

// State represents the health state of an upstream provider.
type State int

const (
	StateHealthy State = iota
	StateDegraded
	StateDown
)

func (s State) String() string {
	switch s {
	case StateHealthy:
		return "healthy"
	case StateDegraded:
		return "degraded"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// Upstream wraps a Transport with operational statistics and health tracking.
type Upstream struct {
	Config    config.UpstreamConfig
	Transport transport.Transport

	mu                  sync.RWMutex
	state               State
	consecutiveFailures int
	totalQueries        uint64
	successfulQueries   uint64
	failedQueries       uint64
	lastLatencyMs       float64
	movingAvgLatencyMs  float64
	lastUsed            time.Time
	lastError           error
}

// Stats returns a snapshot of the upstream's operational metrics.
type UpstreamStats struct {
	Name                string
	Transport           string
	Endpoint            string
	Priority            int
	Weight              int
	State               string
	ConsecutiveFailures int
	TotalQueries        uint64
	SuccessfulQueries   uint64
	FailedQueries       uint64
	LastLatencyMs       float64
	AvgLatencyMs        float64
	LastError           string
}

// Pool coordinates query routing, failover, health probing, and upstream selection.
type Pool struct {
	cfg       config.RoutingConfig
	upstreams []*Upstream
	fallback  transport.Transport // Plaintext fallback transport (only if explicitly enabled)
	rrIndex   uint32
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewPool initializes the upstream pool and creates transports for each provider.
func NewPool(cfg config.RoutingConfig, upstreamConfigs []config.UpstreamConfig, b *bootstrap.Resolver) (*Pool, error) {
	if len(upstreamConfigs) == 0 {
		return nil, errors.New("cannot create pool with zero upstreams")
	}

	var upstreams []*Upstream
	for _, uCfg := range upstreamConfigs {
		tr, err := transport.NewTransport(transport.Options{
			Config:    uCfg,
			Bootstrap: b,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize transport for '%s': %w", uCfg.Name, err)
		}

		u := &Upstream{
			Config:             uCfg,
			Transport:          tr,
			state:              StateHealthy,
			movingAvgLatencyMs: 20.0, // Initial estimate
		}
		upstreams = append(upstreams, u)
	}

	var fallbackTr transport.Transport
	if cfg.AllowPlaintextFallback {
		// Initialize plaintext fallback using the first bootstrap server
		servers := b.Servers()
		if len(servers) > 0 {
			var err error
			fallbackTr, err = transport.NewUDP(transport.Options{
				Config: config.UpstreamConfig{
					Name:             "Plaintext Fallback",
					Transport:        config.TransportUDP,
					Endpoint:         servers[0],
					AllowTCPFallback: true,
					Timeout:          2 * time.Second,
				},
				Bootstrap: b,
			})
			if err != nil {
				logger.L().Warn("failed to initialize plaintext fallback transport", "error", err)
			}
		}
	}

	p := &Pool{
		cfg:       cfg,
		upstreams: upstreams,
		fallback:  fallbackTr,
		stopCh:    make(chan struct{}),
	}

	// Start background health-check probe
	p.wg.Add(1)
	go p.probeWorker()

	return p, nil
}

// Resolve sends a DNS query to the selected upstream and handles retries and failover.
func (p *Pool) Resolve(ctx context.Context, query *dns.Msg) (*dns.Msg, string, error) {
	candidates := p.selectCandidates()
	if len(candidates) == 0 {
		if p.cfg.AllowPlaintextFallback && p.fallback != nil {
			logger.L().Warn("all upstreams degraded, falling back to plaintext DNS as permitted by config")
			resp, err := p.fallback.Exchange(ctx, query)
			return resp, "Plaintext-Fallback", err
		}
		return nil, "", ErrNoUpstreamsAvailable
	}

	// Parallel queries strategy: race all candidates simultaneously
	if p.cfg.Strategy == config.StrategyParallel {
		return p.resolveParallel(ctx, query, candidates)
	}

	var lastErr error
	for _, u := range candidates {
		start := time.Now()
		resp, err := p.executeWithRetries(ctx, u, query)
		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

		if err == nil && resp != nil {
			u.recordSuccess(latencyMs)
			return resp, u.Config.Name, nil
		}

		u.recordFailure(err)
		lastErr = err
		logger.L().Debug("upstream query failed, attempting failover",
			"upstream", u.Config.Name,
			"error", err,
		)
	}

	// If all configured upstreams fail
	if p.cfg.AllowPlaintextFallback && p.fallback != nil {
		logger.L().Warn("all configured upstreams failed, attempting plaintext fallback")
		resp, err := p.fallback.Exchange(ctx, query)
		return resp, "Plaintext-Fallback", err
	}

	return nil, "", fmt.Errorf("%w: %v", ErrAllUpstreamsFailed, lastErr)
}

// resolveParallel fires queries to all candidate upstreams simultaneously and takes the fastest successful reply.
func (p *Pool) resolveParallel(ctx context.Context, query *dns.Msg, candidates []*Upstream) (*dns.Msg, string, error) {
	type queryResult struct {
		upstream  *Upstream
		resp      *dns.Msg
		err       error
		latencyMs float64
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan queryResult, len(candidates))

	for _, u := range candidates {
		go func(target *Upstream) {
			start := time.Now()
			resp, err := p.executeWithRetries(childCtx, target, query)
			latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
			resultCh <- queryResult{
				upstream:  target,
				resp:      resp,
				err:       err,
				latencyMs: latencyMs,
			}
		}(u)
	}

	var lastErr error

	for i := 0; i < len(candidates); i++ {
		select {
		case res := <-resultCh:
			if res.err == nil && res.resp != nil {
				cancel() // Abort remaining in-flight queries
				res.upstream.recordSuccess(res.latencyMs)
				return res.resp, res.upstream.Config.Name, nil
			}
			res.upstream.recordFailure(res.err)
			lastErr = res.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}

	if p.cfg.AllowPlaintextFallback && p.fallback != nil {
		logger.L().Warn("all parallel upstreams failed, attempting plaintext fallback")
		resp, err := p.fallback.Exchange(ctx, query)
		return resp, "Plaintext-Fallback", err
	}

	return nil, "", fmt.Errorf("%w: %v", ErrAllUpstreamsFailed, lastErr)
}

func (p *Pool) executeWithRetries(ctx context.Context, u *Upstream, query *dns.Msg) (*dns.Msg, error) {
	retries := u.Config.MaxRetries
	if retries < 0 {
		retries = 1
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		queryCopy := query.Copy()
		resp, err := u.Transport.Exchange(ctx, queryCopy)
		if err == nil && resp != nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// selectCandidates returns ordered list of upstreams according to routing strategy.
func (p *Pool) selectCandidates() []*Upstream {
	// Filter out completely dead upstreams, prioritize healthy, include degraded as secondary
	var healthy []*Upstream
	var degraded []*Upstream

	for _, u := range p.upstreams {
		u.mu.RLock()
		st := u.state
		u.mu.RUnlock()

		switch st {
		case StateHealthy:
			healthy = append(healthy, u)
		case StateDegraded:
			degraded = append(degraded, u)
		}
	}

	var orderedHealthy []*Upstream
	switch p.cfg.Strategy {
	case config.StrategyRoundRobin:
		if len(healthy) > 0 {
			idx := int(atomic.AddUint32(&p.rrIndex, 1)) % len(healthy)
			for i := 0; i < len(healthy); i++ {
				orderedHealthy = append(orderedHealthy, healthy[(idx+i)%len(healthy)])
			}
		}
	case config.StrategyFastest:
		orderedHealthy = append([]*Upstream(nil), healthy...)
		sort.Slice(orderedHealthy, func(i, j int) bool {
			orderedHealthy[i].mu.RLock()
			latI := orderedHealthy[i].movingAvgLatencyMs
			orderedHealthy[i].mu.RUnlock()

			orderedHealthy[j].mu.RLock()
			latJ := orderedHealthy[j].movingAvgLatencyMs
			orderedHealthy[j].mu.RUnlock()

			return latI < latJ
		})
	case config.StrategyPriority:
		fallthrough
	default:
		orderedHealthy = append([]*Upstream(nil), healthy...)
		sort.Slice(orderedHealthy, func(i, j int) bool {
			return orderedHealthy[i].Config.Priority < orderedHealthy[j].Config.Priority
		})
	}

	// Always append degraded upstreams at the end for failover
	return append(orderedHealthy, degraded...)
}

func (u *Upstream) recordSuccess(latencyMs float64) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.totalQueries++
	u.successfulQueries++
	u.consecutiveFailures = 0
	u.lastLatencyMs = latencyMs
	u.lastUsed = time.Now()
	u.lastError = nil

	// Exponential moving average (alpha = 0.2)
	const alpha = 0.2
	u.movingAvgLatencyMs = (alpha * latencyMs) + ((1.0 - alpha) * u.movingAvgLatencyMs)

	if u.state != StateHealthy {
		u.state = StateHealthy
	}
}

func (u *Upstream) recordFailure(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.totalQueries++
	u.failedQueries++
	u.consecutiveFailures++
	u.lastError = err

	// If failures exceed threshold, mark as degraded or down
	if u.consecutiveFailures >= 5 {
		u.state = StateDown
	} else if u.consecutiveFailures >= 2 {
		u.state = StateDegraded
	}
}

func (p *Pool) probeWorker() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.cfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.probeDegradedUpstreams()
		}
	}
}

func (p *Pool) probeDegradedUpstreams() {
	probeQuery := dnsmsg.NewQuery("cloudflare.com", dns.TypeA)

	for _, u := range p.upstreams {
		u.mu.RLock()
		needsProbe := u.state != StateHealthy
		u.mu.RUnlock()

		if !needsProbe {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		start := time.Now()
		resp, err := u.Transport.Exchange(ctx, probeQuery)
		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
		cancel()

		if err == nil && resp != nil {
			logger.L().Info("upstream recovered through health check probe",
				"upstream", u.Config.Name,
				"latency_ms", latencyMs,
			)
			u.recordSuccess(latencyMs)
		}
	}
}

// Stats returns the operational statistics for all upstreams in the pool.
func (p *Pool) Stats() []UpstreamStats {
	var result []UpstreamStats
	for _, u := range p.upstreams {
		u.mu.RLock()
		lastErrStr := ""
		if u.lastError != nil {
			lastErrStr = u.lastError.Error()
		}
		st := UpstreamStats{
			Name:                u.Config.Name,
			Transport:           u.Config.Transport,
			Endpoint:            u.Transport.Endpoint(),
			Priority:            u.Config.Priority,
			Weight:              u.Config.Weight,
			State:               u.state.String(),
			ConsecutiveFailures: u.consecutiveFailures,
			TotalQueries:        u.totalQueries,
			SuccessfulQueries:   u.successfulQueries,
			FailedQueries:       u.failedQueries,
			LastLatencyMs:       math.Round(u.lastLatencyMs*100) / 100,
			AvgLatencyMs:        math.Round(u.movingAvgLatencyMs*100) / 100,
			LastError:           lastErrStr,
		}
		u.mu.RUnlock()
		result = append(result, st)
	}
	return result
}

// Close closes all upstreams and stops background probing.
func (p *Pool) Close() error {
	close(p.stopCh)
	p.wg.Wait()

	var firstErr error
	for _, u := range p.upstreams {
		if err := u.Transport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if p.fallback != nil {
		if err := p.fallback.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
