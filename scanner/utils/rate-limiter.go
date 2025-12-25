package utils

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	rate       float64 // tokens per second
	burst      int     // max burst size
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(ratePerSecond float64, burst int) *RateLimiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 10
	}
	if burst <= 0 {
		burst = int(ratePerSecond)
	}

	return &RateLimiter{
		rate:       ratePerSecond,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Wait blocks until a token is available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if rl.Allow() {
			return nil
		}

		// Calculate wait time
		rl.mu.Lock()
		waitTime := time.Duration((1.0 / rl.rate) * float64(time.Second))
		rl.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()

	// Add tokens based on elapsed time
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}
	rl.lastUpdate = now

	// Check if we have a token
	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}

	return false
}

// AllowN checks if n requests are allowed
func (rl *RateLimiter) AllowN(n int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()

	// Add tokens
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}
	rl.lastUpdate = now

	// Check if we have enough tokens
	if rl.tokens >= float64(n) {
		rl.tokens -= float64(n)
		return true
	}

	return false
}

// Reserve reserves a token and returns wait duration
func (rl *RateLimiter) Reserve() time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()

	// Add tokens
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}
	rl.lastUpdate = now

	// If we have a token, no wait needed
	if rl.tokens >= 1 {
		rl.tokens--
		return 0
	}

	// Calculate wait time for next token
	waitTime := time.Duration((1.0 - rl.tokens) / rl.rate * float64(time.Second))
	rl.tokens = 0
	return waitTime
}

// SetRate updates the rate limit
func (rl *RateLimiter) SetRate(ratePerSecond float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rate = ratePerSecond
}

// SetBurst updates the burst limit
func (rl *RateLimiter) SetBurst(burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.burst = burst
	if rl.tokens > float64(burst) {
		rl.tokens = float64(burst)
	}
}

// AdaptiveRateLimiter adjusts rate based on response times
type AdaptiveRateLimiter struct {
	limiter       *RateLimiter
	minRate       float64
	maxRate       float64
	targetLatency time.Duration
	samples       []time.Duration
	samplesMu     sync.Mutex
	maxSamples    int
}

// NewAdaptiveRateLimiter creates an adaptive rate limiter
func NewAdaptiveRateLimiter(initialRate, minRate, maxRate float64, targetLatency time.Duration) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		limiter:       NewRateLimiter(initialRate, int(initialRate)),
		minRate:       minRate,
		maxRate:       maxRate,
		targetLatency: targetLatency,
		maxSamples:    100,
	}
}

// Wait blocks until allowed
func (arl *AdaptiveRateLimiter) Wait(ctx context.Context) error {
	return arl.limiter.Wait(ctx)
}

// RecordLatency records a response latency for adaptation
func (arl *AdaptiveRateLimiter) RecordLatency(latency time.Duration) {
	arl.samplesMu.Lock()
	defer arl.samplesMu.Unlock()

	arl.samples = append(arl.samples, latency)
	if len(arl.samples) > arl.maxSamples {
		arl.samples = arl.samples[1:]
	}

	// Adjust rate based on average latency
	if len(arl.samples) >= 10 {
		avgLatency := arl.averageLatency()
		arl.adjustRate(avgLatency)
	}
}

// averageLatency calculates average of recent samples
func (arl *AdaptiveRateLimiter) averageLatency() time.Duration {
	if len(arl.samples) == 0 {
		return 0
	}

	var total time.Duration
	for _, s := range arl.samples {
		total += s
	}
	return total / time.Duration(len(arl.samples))
}

// adjustRate adjusts rate based on latency
func (arl *AdaptiveRateLimiter) adjustRate(avgLatency time.Duration) {
	currentRate := arl.limiter.rate

	if avgLatency > arl.targetLatency*2 {
		// High latency - slow down significantly
		newRate := currentRate * 0.5
		if newRate < arl.minRate {
			newRate = arl.minRate
		}
		arl.limiter.SetRate(newRate)
	} else if avgLatency > arl.targetLatency {
		// Above target - slow down slightly
		newRate := currentRate * 0.8
		if newRate < arl.minRate {
			newRate = arl.minRate
		}
		arl.limiter.SetRate(newRate)
	} else if avgLatency < arl.targetLatency/2 {
		// Very low latency - speed up
		newRate := currentRate * 1.2
		if newRate > arl.maxRate {
			newRate = arl.maxRate
		}
		arl.limiter.SetRate(newRate)
	}
}

// PerHostRateLimiter manages rate limits per host
type PerHostRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.RWMutex
	rate     float64
	burst    int
}

// NewPerHostRateLimiter creates a per-host rate limiter
func NewPerHostRateLimiter(ratePerHost float64, burstPerHost int) *PerHostRateLimiter {
	return &PerHostRateLimiter{
		limiters: make(map[string]*RateLimiter),
		rate:     ratePerHost,
		burst:    burstPerHost,
	}
}

// Wait waits for rate limit on specific host
func (phrl *PerHostRateLimiter) Wait(ctx context.Context, host string) error {
	limiter := phrl.getLimiter(host)
	return limiter.Wait(ctx)
}

// Allow checks if request to host is allowed
func (phrl *PerHostRateLimiter) Allow(host string) bool {
	limiter := phrl.getLimiter(host)
	return limiter.Allow()
}

// getLimiter gets or creates limiter for host
func (phrl *PerHostRateLimiter) getLimiter(host string) *RateLimiter {
	phrl.mu.RLock()
	limiter, exists := phrl.limiters[host]
	phrl.mu.RUnlock()

	if exists {
		return limiter
	}

	phrl.mu.Lock()
	defer phrl.mu.Unlock()

	// Double check after acquiring write lock
	if limiter, exists = phrl.limiters[host]; exists {
		return limiter
	}

	limiter = NewRateLimiter(phrl.rate, phrl.burst)
	phrl.limiters[host] = limiter
	return limiter
}
