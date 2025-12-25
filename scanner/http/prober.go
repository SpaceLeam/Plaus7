package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ProbeConfig holds HTTP prober configuration
type ProbeConfig struct {
	Targets        []string
	Workers        int
	Timeout        int
	FollowRedirect bool
	MaxRedirects   int
	TLSVerify      bool
	Retries        int
	RateLimit      int
	UserAgent      string
	Headers        map[string]string
}

// ProbeResult holds the result of an HTTP probe
type ProbeResult struct {
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code"`
	ContentLength int64             `json:"content_length"`
	ContentType   string            `json:"content_type,omitempty"`
	Title         string            `json:"title,omitempty"`
	Server        string            `json:"server,omitempty"`
	Technologies  []string          `json:"technologies,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Redirected    bool              `json:"redirected,omitempty"`
	FinalURL      string            `json:"final_url,omitempty"`
	ResponseTime  int64             `json:"response_time_ms"`
	Timestamp     string            `json:"timestamp"`
}

// Prober handles HTTP probing operations
type Prober struct {
	config  ProbeConfig
	client  *http.Client
	limiter *rate.Limiter
}

// NewProber creates a new HTTP prober
func NewProber(config ProbeConfig) *Prober {
	if config.Workers == 0 {
		config.Workers = 100
	}
	if config.Timeout == 0 {
		config.Timeout = 10
	}
	if config.MaxRedirects == 0 {
		config.MaxRedirects = 5
	}
	if config.Retries == 0 {
		config.Retries = 2
	}
	if config.RateLimit == 0 {
		config.RateLimit = 500
	}
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	// Create transport with TLS config
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.TLSVerify,
		},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Create client with redirect policy
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	if !config.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		}
	}

	return &Prober{
		config:  config,
		client:  client,
		limiter: rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit),
	}
}

// Probe performs HTTP probing on all targets
func (p *Prober) Probe() ([]ProbeResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	jobs := make(chan string, p.config.Workers*2)
	results := make(chan ProbeResult, len(p.config.Targets))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < p.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.worker(ctx, jobs, results)
		}()
	}

	// Feed jobs
	go func() {
		for _, target := range p.config.Targets {
			select {
			case <-ctx.Done():
				break
			default:
				jobs <- target
			}
		}
		close(jobs)
	}()

	// Wait and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect successful probes
	var probed []ProbeResult
	for result := range results {
		if result.StatusCode > 0 {
			probed = append(probed, result)
		}
	}

	return probed, nil
}

// worker processes probe jobs
func (p *Prober) worker(ctx context.Context, jobs <-chan string, results chan<- ProbeResult) {
	for target := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			// Rate limiting
			p.limiter.Wait(ctx)

			// Normalize URL
			urls := p.normalizeURL(target)

			for _, url := range urls {
				result := p.probeWithRetry(ctx, url)
				if result.StatusCode > 0 {
					results <- result
					break // Found working URL, skip alternates
				}
			}
		}
	}
}

// normalizeURL ensures URL has scheme
func (p *Prober) normalizeURL(target string) []string {
	target = strings.TrimSpace(target)

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}

	// Try HTTPS first, then HTTP
	return []string{
		"https://" + target,
		"http://" + target,
	}
}

// probeWithRetry probes URL with retry logic
func (p *Prober) probeWithRetry(ctx context.Context, url string) ProbeResult {
	var lastResult ProbeResult

	for attempt := 0; attempt <= p.config.Retries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}

		result := p.probe(ctx, url)
		if result.StatusCode > 0 {
			return result
		}
		lastResult = result
	}

	return lastResult
}

// probe sends HTTP request and extracts information
func (p *Prober) probe(ctx context.Context, url string) ProbeResult {
	result := ProbeResult{
		URL:       url,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", p.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	for key, value := range p.config.Headers {
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	result.ResponseTime = time.Since(start).Milliseconds()

	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength

	// Extract headers
	result.Headers = make(map[string]string)
	for key, values := range resp.Header {
		result.Headers[key] = strings.Join(values, ", ")
	}

	// Content-Type
	result.ContentType = resp.Header.Get("Content-Type")

	// Server header
	result.Server = resp.Header.Get("Server")

	// Check if redirected
	if resp.Request.URL.String() != url {
		result.Redirected = true
		result.FinalURL = resp.Request.URL.String()
	}

	// Read body for title and tech detection (limit to 100KB)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	bodyStr := string(body)

	// Extract title
	result.Title = extractTitle(bodyStr)

	// Detect technologies
	result.Technologies = detectTechnologies(resp.Header, bodyStr)

	return result
}

// extractTitle extracts page title from HTML
func extractTitle(body string) string {
	// Case-insensitive title extraction
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Truncate long titles
		if len(title) > 100 {
			title = title[:100] + "..."
		}
		return title
	}
	return ""
}

// detectTechnologies identifies technologies from response
func detectTechnologies(headers http.Header, body string) []string {
	var techs []string
	seen := make(map[string]bool)

	addTech := func(tech string) {
		if !seen[tech] {
			seen[tech] = true
			techs = append(techs, tech)
		}
	}

	// Header-based detection
	server := headers.Get("Server")
	if server != "" {
		if strings.Contains(strings.ToLower(server), "nginx") {
			addTech("Nginx")
		}
		if strings.Contains(strings.ToLower(server), "apache") {
			addTech("Apache")
		}
		if strings.Contains(strings.ToLower(server), "cloudflare") {
			addTech("Cloudflare")
		}
		if strings.Contains(strings.ToLower(server), "iis") {
			addTech("IIS")
		}
	}

	poweredBy := headers.Get("X-Powered-By")
	if poweredBy != "" {
		if strings.Contains(strings.ToLower(poweredBy), "php") {
			addTech("PHP")
		}
		if strings.Contains(strings.ToLower(poweredBy), "asp.net") {
			addTech("ASP.NET")
		}
		if strings.Contains(strings.ToLower(poweredBy), "express") {
			addTech("Express.js")
		}
	}

	// Body-based detection
	bodyLower := strings.ToLower(body)

	// JavaScript frameworks
	if strings.Contains(bodyLower, "react") || strings.Contains(body, "__NEXT_DATA__") {
		addTech("React")
	}
	if strings.Contains(body, "ng-") || strings.Contains(bodyLower, "angular") {
		addTech("Angular")
	}
	if strings.Contains(bodyLower, "vue") {
		addTech("Vue.js")
	}
	if strings.Contains(bodyLower, "jquery") {
		addTech("jQuery")
	}

	// CMS
	if strings.Contains(bodyLower, "wordpress") || strings.Contains(body, "wp-content") {
		addTech("WordPress")
	}
	if strings.Contains(bodyLower, "drupal") {
		addTech("Drupal")
	}
	if strings.Contains(bodyLower, "joomla") {
		addTech("Joomla")
	}

	// Frameworks
	if strings.Contains(bodyLower, "laravel") {
		addTech("Laravel")
	}
	if strings.Contains(bodyLower, "django") {
		addTech("Django")
	}
	if strings.Contains(bodyLower, "rails") || strings.Contains(body, "csrf-token") {
		addTech("Ruby on Rails")
	}

	// Cloud/CDN
	if headers.Get("CF-Ray") != "" {
		addTech("Cloudflare")
	}
	if strings.Contains(headers.Get("Via"), "cloudfront") {
		addTech("CloudFront")
	}

	return techs
}
