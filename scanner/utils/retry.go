package utils

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxRetries      int
	InitialDelay    time.Duration
	MaxDelay        time.Duration
	BackoffFactor   float64
	Jitter          bool
	RetryableErrors []error
}

// DefaultRetryConfig returns sensible defaults
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:    3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func(ctx context.Context) error

// RetryWithBackoff retries a function with exponential backoff
func RetryWithBackoff(ctx context.Context, config RetryConfig, fn RetryableFunc) error {
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}
	if config.InitialDelay <= 0 {
		config.InitialDelay = 100 * time.Millisecond
	}
	if config.MaxDelay <= 0 {
		config.MaxDelay = 10 * time.Second
	}
	if config.BackoffFactor <= 0 {
		config.BackoffFactor = 2.0
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// Check context before attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := fn(ctx)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryable(err, config.RetryableErrors) {
			return err
		}

		// Don't sleep after last attempt
		if attempt == config.MaxRetries {
			break
		}

		// Calculate delay with optional jitter
		currentDelay := delay
		if config.Jitter {
			jitterRange := float64(delay) * 0.3
			jitter := rand.Float64()*jitterRange*2 - jitterRange
			currentDelay = time.Duration(float64(delay) + jitter)
		}

		// Wait before retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(currentDelay):
		}

		// Increase delay for next attempt
		delay = time.Duration(float64(delay) * config.BackoffFactor)
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", config.MaxRetries, lastErr)
}

// isRetryable checks if an error should be retried
func isRetryable(err error, retryableErrors []error) bool {
	// If no specific retryable errors defined, retry all
	if len(retryableErrors) == 0 {
		return true
	}

	for _, retryableErr := range retryableErrors {
		if errors.Is(err, retryableErr) {
			return true
		}
	}

	return false
}

// RetryResult wraps result with retry metadata
type RetryResult struct {
	Attempts int
	Duration time.Duration
	Error    error
}

// RetryWithResult retries and returns metadata
func RetryWithResult(ctx context.Context, config RetryConfig, fn RetryableFunc) RetryResult {
	start := time.Now()
	attempts := 0

	err := RetryWithBackoff(ctx, config, func(ctx context.Context) error {
		attempts++
		return fn(ctx)
	})

	return RetryResult{
		Attempts: attempts,
		Duration: time.Since(start),
		Error:    err,
	}
}

// ExponentialBackoff calculates delay for a given attempt
func ExponentialBackoff(attempt int, baseDelay time.Duration, maxDelay time.Duration) time.Duration {
	delay := baseDelay * time.Duration(math.Pow(2, float64(attempt)))
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

// JitterDuration adds random jitter to a duration
func JitterDuration(d time.Duration, factor float64) time.Duration {
	if factor <= 0 || factor > 1 {
		factor = 0.3
	}
	jitterRange := float64(d) * factor
	jitter := rand.Float64()*jitterRange*2 - jitterRange
	return time.Duration(float64(d) + jitter)
}

// RetryPolicy defines custom retry behavior
type RetryPolicy struct {
	ShouldRetry func(error) bool
	Delay       func(attempt int) time.Duration
}

// NewLinearRetryPolicy creates policy with linear backoff
func NewLinearRetryPolicy(baseDelay time.Duration) RetryPolicy {
	return RetryPolicy{
		ShouldRetry: func(err error) bool { return true },
		Delay: func(attempt int) time.Duration {
			return baseDelay * time.Duration(attempt+1)
		},
	}
}

// NewExponentialRetryPolicy creates policy with exponential backoff
func NewExponentialRetryPolicy(baseDelay, maxDelay time.Duration) RetryPolicy {
	return RetryPolicy{
		ShouldRetry: func(err error) bool { return true },
		Delay: func(attempt int) time.Duration {
			return ExponentialBackoff(attempt, baseDelay, maxDelay)
		},
	}
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	maxFailures     int
	resetTimeout    time.Duration
	failures        int
	lastFailureTime time.Time
	state           string // closed, open, half-open
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        "closed",
	}
}

// Execute runs function through circuit breaker
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if cb.state == "open" {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = "half-open"
		} else {
			return errors.New("circuit breaker is open")
		}
	}

	err := fn()

	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()

		if cb.failures >= cb.maxFailures {
			cb.state = "open"
		}
		return err
	}

	// Success - reset
	cb.failures = 0
	cb.state = "closed"
	return nil
}

// State returns current circuit breaker state
func (cb *CircuitBreaker) State() string {
	return cb.state
}
