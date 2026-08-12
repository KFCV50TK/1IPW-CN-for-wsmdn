package main

import (
	"crypto/x509"
	"sync"
	"time"
)

const cacheMaxEntries = 512

type ttlEntry[V any] struct {
	value V
	at    time.Time
}

// ttlCache is a bounded TTL cache. Entries expire after ttl and the map never
// grows beyond max entries (oldest entries are evicted when full).
type ttlCache[V any] struct {
	mu  sync.Mutex
	m   map[string]ttlEntry[V]
	max int
	ttl time.Duration
}

func newTTLCache[V any](max int, ttl time.Duration) *ttlCache[V] {
	c := &ttlCache[V]{m: make(map[string]ttlEntry[V]), max: max, ttl: ttl}
	go c.janitor()
	return c
}

func (c *ttlCache[V]) Get(key string) (V, bool) {
	var zero V
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.m[key]
	if !ok {
		return zero, false
	}
	if time.Since(entry.at) >= c.ttl {
		delete(c.m, key)
		return zero, false
	}
	return entry.value, true
}

func (c *ttlCache[V]) Set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		c.sweepLocked()
	}
	if len(c.m) >= c.max {
		var oldestKey string
		var oldest time.Time
		first := true
		for k, e := range c.m {
			if first || e.at.Before(oldest) {
				oldestKey, oldest, first = k, e.at, false
			}
		}
		if oldestKey != "" {
			delete(c.m, oldestKey)
		}
	}
	c.m[key] = ttlEntry[V]{value: value, at: time.Now()}
}

func (c *ttlCache[V]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func (c *ttlCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

func (c *ttlCache[V]) sweepLocked() {
	for k, e := range c.m {
		if time.Since(e.at) >= c.ttl {
			delete(c.m, k)
		}
	}
}

func (c *ttlCache[V]) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		c.sweepLocked()
		c.mu.Unlock()
	}
}

// Bounded caches for public endpoints. Replaces the previous unbounded
// sync.Map caches that could grow without limit.
var (
	websiteCache = newTTLCache[*WebsiteCheckResult](cacheMaxEntries, 5*time.Minute)
	sslCache     = newTTLCache[*SSLCheckResult](cacheMaxEntries, 5*time.Minute)
	pingCache    = newTTLCache[*TCPingResult](cacheMaxEntries, 1*time.Minute)
	speedCache   = newTTLCache[*WebsiteSpeedTestResult](cacheMaxEntries, 1*time.Minute)
)

// tcping rate limiting and global concurrency guard.
type tcpingRateEntry struct {
	window time.Time
	count  int
}

const tcpingRateMax = 12

var (
	pingSem       = make(chan struct{}, 16)
	tcpingRates   = make(map[string]tcpingRateEntry)
	tcpingRatesMu sync.Mutex
)

func allowTcping(identity string) bool {
	now := time.Now()
	window := now.Truncate(time.Minute)
	tcpingRatesMu.Lock()
	defer tcpingRatesMu.Unlock()
	entry := tcpingRates[identity]
	if !entry.window.Equal(window) {
		entry = tcpingRateEntry{window: window}
	}
	if entry.count >= tcpingRateMax {
		return false
	}
	entry.count++
	tcpingRates[identity] = entry
	if len(tcpingRates) > 4096 {
		for key, value := range tcpingRates {
			if value.window.Before(window) {
				delete(tcpingRates, key)
			}
		}
	}
	return true
}

// maxUpstreamBody caps how much of an upstream response the public detection
// endpoints may buffer (memory-DoS guard).
const maxUpstreamBody = 8 << 20 // 8 MiB

// systemCertPool returns the system root CA pool, falling back to an empty
// pool when the OS pool cannot be loaded.
func systemCertPool() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return x509.NewCertPool()
	}
	return pool
}
