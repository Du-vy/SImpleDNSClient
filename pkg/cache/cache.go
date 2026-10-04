package cache

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/miekg/dns"
)

// Config defines cache behavior.
type Config struct {
	Enabled     bool
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	NegativeTTL time.Duration
}

// Stats holds cache operational metrics.
type Stats struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Expired   uint64
	Size      int
}

type cacheEntry struct {
	key       string
	msg       *dns.Msg
	cachedAt  time.Time
	expireAt  time.Time
	isNegative bool
}

// Cache provides a thread-safe LRU DNS response cache with dynamic TTL adjustment.
type Cache struct {
	cfg     Config
	mu      sync.RWMutex
	items   map[string]*list.Element
	evict   *list.List
	stats   Stats
}

// New creates a new DNS cache.
func New(cfg Config) *Cache {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 4096
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = 10 * time.Second
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 86400 * time.Second
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 30 * time.Second
	}

	return &Cache{
		cfg:   cfg,
		items: make(map[string]*list.Element),
		evict: list.New(),
	}
}

// makeKey generates a unique cache key from a DNS question.
func makeKey(name string, qtype, qclass uint16) string {
	return fmt.Sprintf("%s|%d|%d", dnsmsg.NormalizeName(name), qtype, qclass)
}

// Get retrieves a cached DNS response for the given request, if present and not expired.
// Returned response has its query ID updated to match the request and TTLs adjusted to remaining time.
func (c *Cache) Get(req *dns.Msg) (*dns.Msg, bool) {
	if !c.cfg.Enabled || req == nil || len(req.Question) == 0 {
		return nil, false
	}

	name, qtype, qclass, err := dnsmsg.ExtractQuestion(req)
	if err != nil {
		return nil, false
	}

	key := makeKey(name, qtype, qclass)

	c.mu.Lock()
	elem, found := c.items[key]
	if !found {
		c.stats.Misses++
		c.mu.Unlock()
		return nil, false
	}

	entry := elem.Value.(*cacheEntry)
	now := time.Now()

	// Check expiration
	if now.After(entry.expireAt) {
		c.stats.Expired++
		c.stats.Misses++
		c.removeElement(elem)
		c.mu.Unlock()
		return nil, false
	}

	// Move to front (MRU)
	c.evict.MoveToFront(elem)
	c.stats.Hits++

	// Clone message to avoid race conditions with callers
	resp := entry.msg.Copy()
	c.mu.Unlock()

	// Adjust TTLs to reflect remaining time
	remainingSecs := uint32(entry.expireAt.Sub(now).Seconds())
	if remainingSecs == 0 {
		remainingSecs = 1
	}

	adjustTTL(resp, remainingSecs)
	resp.Id = req.Id

	return resp, true
}

// Set inserts a DNS response into the cache.
func (c *Cache) Set(req *dns.Msg, resp *dns.Msg) {
	if !c.cfg.Enabled || req == nil || resp == nil || len(req.Question) == 0 {
		return
	}

	// Do not cache truncated responses (client needs to retry over TCP)
	if resp.Truncated {
		return
	}

	name, qtype, qclass, err := dnsmsg.ExtractQuestion(req)
	if err != nil {
		return
	}

	key := makeKey(name, qtype, qclass)
	now := time.Now()

	ttl, isNegative, cacheable := c.determineTTL(resp)
	if !cacheable || ttl <= 0 {
		return
	}

	// Apply min / max TTL constraints
	if ttl < c.cfg.MinTTL {
		ttl = c.cfg.MinTTL
	}
	if ttl > c.cfg.MaxTTL {
		ttl = c.cfg.MaxTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If entry already exists, update it
	if elem, found := c.items[key]; found {
		c.evict.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		entry.msg = resp.Copy()
		entry.cachedAt = now
		entry.expireAt = now.Add(ttl)
		entry.isNegative = isNegative
		return
	}

	// Evict oldest if capacity exceeded
	for c.evict.Len() >= c.cfg.MaxEntries {
		c.stats.Evictions++
		c.removeOldest()
	}

	entry := &cacheEntry{
		key:       key,
		msg:       resp.Copy(),
		cachedAt:  now,
		expireAt:  now.Add(ttl),
		isNegative: isNegative,
	}
	elem := c.evict.PushFront(entry)
	c.items[key] = elem
}

// determineTTL inspects response RRsets to determine the appropriate cache TTL.
func (c *Cache) determineTTL(resp *dns.Msg) (time.Duration, bool, bool) {
	// Negative response: NXDOMAIN or NODATA (NOERROR with 0 answers)
	if resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
		// Look for SOA record in Ns section to determine negative TTL
		for _, rr := range resp.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				soaTTL := time.Duration(soa.Minttl) * time.Second
				if soaTTL > 0 {
					return min(soaTTL, c.cfg.NegativeTTL), true, true
				}
			}
		}
		return c.cfg.NegativeTTL, true, true
	}

	// Only cache NOERROR responses with answers
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return 0, false, false
	}

	// Find the minimum positive TTL among all answer records
	var minTTL uint32 = 0xFFFFFFFF
	for _, rr := range resp.Answer {
		header := rr.Header()
		if header.Ttl < minTTL {
			minTTL = header.Ttl
		}
	}

	if minTTL == 0xFFFFFFFF || minTTL == 0 {
		return 0, false, false
	}

	return time.Duration(minTTL) * time.Second, false, true
}

func adjustTTL(msg *dns.Msg, newTTL uint32) {
	for _, rr := range msg.Answer {
		if rr.Header().Ttl > newTTL {
			rr.Header().Ttl = newTTL
		}
	}
	for _, rr := range msg.Ns {
		if rr.Header().Ttl > newTTL {
			rr.Header().Ttl = newTTL
		}
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			if rr.Header().Ttl > newTTL {
				rr.Header().Ttl = newTTL
			}
		}
	}
}

func (c *Cache) removeElement(elem *list.Element) {
	c.evict.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
}

func (c *Cache) removeOldest() {
	elem := c.evict.Back()
	if elem != nil {
		c.removeElement(elem)
	}
}

// Stats returns a snapshot of cache metrics.
func (c *Cache) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.stats
	s.Size = len(c.items)
	return s
}

// Clear flushes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.evict.Init()
}
