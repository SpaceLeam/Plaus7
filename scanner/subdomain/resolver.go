package subdomain

import (
	"context"
	"net"
	"sync"
	"time"
)

// ResolverConfig holds DNS resolver configuration
type ResolverConfig struct {
	Resolvers []string
	Timeout   time.Duration
	Retries   int
	Workers   int
}

// ResolutionResult holds DNS resolution results
type ResolutionResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	Alive     bool     `json:"alive"`
	Error     string   `json:"error,omitempty"`
}

// Resolver handles concurrent DNS resolution
type Resolver struct {
	config    ResolverConfig
	resolvers []*net.Resolver
}

// NewResolver creates a new DNS resolver
func NewResolver(config ResolverConfig) *Resolver {
	if len(config.Resolvers) == 0 {
		config.Resolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Retries == 0 {
		config.Retries = 2
	}
	if config.Workers == 0 {
		config.Workers = 100
	}

	resolvers := make([]*net.Resolver, len(config.Resolvers))
	for i, addr := range config.Resolvers {
		resolvers[i] = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: config.Timeout}
				return d.DialContext(ctx, "udp", addr)
			},
		}
	}

	return &Resolver{
		config:    config,
		resolvers: resolvers,
	}
}

// Resolve resolves a list of subdomains concurrently
func (r *Resolver) Resolve(ctx context.Context, subdomains []string) []ResolutionResult {
	jobs := make(chan string, r.config.Workers*2)
	results := make(chan ResolutionResult, len(subdomains))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < r.config.Workers; i++ {
		wg.Add(1)
		go func(resolverIdx int) {
			defer wg.Done()
			resolver := r.resolvers[resolverIdx%len(r.resolvers)]
			r.worker(ctx, resolver, jobs, results)
		}(i)
	}

	// Feed jobs
	go func() {
		for _, sub := range subdomains {
			select {
			case <-ctx.Done():
				break
			default:
				jobs <- sub
			}
		}
		close(jobs)
	}()

	// Wait and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var resolved []ResolutionResult
	for result := range results {
		if result.Alive {
			resolved = append(resolved, result)
		}
	}

	return resolved
}

// worker resolves subdomains from job channel
func (r *Resolver) worker(ctx context.Context, resolver *net.Resolver, jobs <-chan string, results chan<- ResolutionResult) {
	for subdomain := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			result := r.resolveWithRetry(ctx, resolver, subdomain)
			results <- result
		}
	}
}

// resolveWithRetry attempts to resolve with retries
func (r *Resolver) resolveWithRetry(ctx context.Context, resolver *net.Resolver, subdomain string) ResolutionResult {
	var lastErr error

	for attempt := 0; attempt <= r.config.Retries; attempt++ {
		resolveCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
		ips, err := resolver.LookupIPAddr(resolveCtx, subdomain)
		cancel()

		if err == nil && len(ips) > 0 {
			ipStrings := make([]string, len(ips))
			for i, ip := range ips {
				ipStrings[i] = ip.IP.String()
			}
			return ResolutionResult{
				Subdomain: subdomain,
				IPs:       ipStrings,
				Alive:     true,
			}
		}
		lastErr = err

		// Exponential backoff
		if attempt < r.config.Retries {
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
		}
	}

	errMsg := ""
	if lastErr != nil {
		errMsg = lastErr.Error()
	}

	return ResolutionResult{
		Subdomain: subdomain,
		Alive:     false,
		Error:     errMsg,
	}
}

// FilterAlive filters a list of subdomains to only alive ones
func (r *Resolver) FilterAlive(ctx context.Context, subdomains []string) []string {
	results := r.Resolve(ctx, subdomains)

	alive := make([]string, 0, len(results))
	for _, result := range results {
		if result.Alive {
			alive = append(alive, result.Subdomain)
		}
	}

	return alive
}
