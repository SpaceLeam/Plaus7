package http

import (
	"context"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// CrawlConfig holds crawler configuration
type CrawlConfig struct {
	StartURLs []string
	MaxDepth  int
	MaxURLs   int
	Workers   int
	Timeout   int
	RateLimit int
	SameHost  bool
	JSParse   bool
	UserAgent string
}

// CrawlResult holds discovered URLs
type CrawlResult struct {
	URL       string   `json:"url"`
	Source    string   `json:"source"`
	Depth     int      `json:"depth"`
	Type      string   `json:"type"` // page, form, api, js, css
	Params    []string `json:"params,omitempty"`
	Timestamp string   `json:"timestamp"`
}

// Crawler handles web crawling operations
type Crawler struct {
	config  CrawlConfig
	prober  *Prober
	limiter *rate.Limiter
	seen    map[string]bool
	seenMu  sync.Mutex
	results chan CrawlResult
}

// NewCrawler creates a new web crawler
func NewCrawler(config CrawlConfig) *Crawler {
	if config.MaxDepth == 0 {
		config.MaxDepth = 3
	}
	if config.MaxURLs == 0 {
		config.MaxURLs = 1000
	}
	if config.Workers == 0 {
		config.Workers = 20
	}
	if config.Timeout == 0 {
		config.Timeout = 10
	}
	if config.RateLimit == 0 {
		config.RateLimit = 50
	}
	if config.UserAgent == "" {
		config.UserAgent = "ReconCrawler/1.0"
	}

	probeConfig := ProbeConfig{
		Workers:        config.Workers,
		Timeout:        config.Timeout,
		FollowRedirect: true,
		MaxRedirects:   3,
		TLSVerify:      false,
		UserAgent:      config.UserAgent,
	}

	return &Crawler{
		config:  config,
		prober:  NewProber(probeConfig),
		limiter: rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit),
		seen:    make(map[string]bool),
	}
}

// CrawlJob represents a URL to crawl
type CrawlJob struct {
	URL   string
	Depth int
}

// Crawl starts the crawling process
func (c *Crawler) Crawl() ([]CrawlResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	c.results = make(chan CrawlResult, c.config.MaxURLs)
	jobs := make(chan CrawlJob, c.config.Workers*10)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < c.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.worker(ctx, jobs)
		}()
	}

	// Seed initial URLs
	go func() {
		for _, startURL := range c.config.StartURLs {
			if c.markSeen(startURL) {
				jobs <- CrawlJob{URL: startURL, Depth: 0}
			}
		}
	}()

	// Wait for completion with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Close jobs after a delay if no more work
	go func() {
		time.Sleep(5 * time.Second)
		for {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case <-done:
				close(jobs)
				return
			default:
				if c.urlCount() >= c.config.MaxURLs {
					close(jobs)
					return
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	<-done
	close(c.results)

	// Collect results
	var results []CrawlResult
	for result := range c.results {
		results = append(results, result)
	}

	return results, nil
}

// worker processes crawl jobs
func (c *Crawler) worker(ctx context.Context, jobs chan CrawlJob) {
	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			if c.urlCount() >= c.config.MaxURLs {
				return
			}

			c.limiter.Wait(ctx)
			c.crawlURL(ctx, job, jobs)
		}
	}
}

// crawlURL fetches and parses a URL
func (c *Crawler) crawlURL(ctx context.Context, job CrawlJob, jobs chan CrawlJob) {
	result := c.prober.probe(ctx, job.URL)
	if result.StatusCode == 0 {
		return
	}

	// Record this URL
	c.results <- CrawlResult{
		URL:       job.URL,
		Source:    "crawl",
		Depth:     job.Depth,
		Type:      c.classifyURL(job.URL, result.ContentType),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Don't crawl deeper if at max depth
	if job.Depth >= c.config.MaxDepth {
		return
	}

	// Only continue if HTML content
	if !strings.Contains(result.ContentType, "text/html") {
		return
	}

	// Fetch full body for link extraction
	fullResult := c.prober.probe(ctx, job.URL)
	if fullResult.StatusCode == 0 {
		return
	}

	// We need to get body again - probe now returns headers info
	// Re-request to get body
	body := c.fetchBody(ctx, job.URL)
	if body == "" {
		return
	}

	// Extract links
	baseURL, _ := url.Parse(job.URL)
	links := c.extractLinks(body, baseURL)

	// Queue new links
	for _, link := range links {
		if c.urlCount() >= c.config.MaxURLs {
			break
		}

		if c.config.SameHost && !c.isSameHost(link, baseURL.Host) {
			continue
		}

		if c.markSeen(link) {
			select {
			case jobs <- CrawlJob{URL: link, Depth: job.Depth + 1}:
			default:
				// Channel full, skip
			}
		}
	}

	// Extract JavaScript URLs if enabled
	if c.config.JSParse {
		jsURLs := c.extractJSEndpoints(body, baseURL)
		for _, jsURL := range jsURLs {
			if c.markSeen(jsURL) {
				c.results <- CrawlResult{
					URL:       jsURL,
					Source:    "js-parse",
					Depth:     job.Depth,
					Type:      "api",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}
			}
		}
	}

	// Extract form actions
	forms := c.extractForms(body, baseURL)
	for _, form := range forms {
		if c.markSeen(form.URL) {
			c.results <- CrawlResult{
				URL:       form.URL,
				Source:    "form",
				Depth:     job.Depth,
				Type:      "form",
				Params:    form.Params,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
		}
	}
}

// fetchBody gets the body content of a URL
func (c *Crawler) fetchBody(ctx context.Context, targetURL string) string {
	resp, err := c.prober.client.Get(targetURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB limit
	return string(body)
}

// extractLinks extracts all links from HTML
func (c *Crawler) extractLinks(body string, base *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	// href links
	hrefRe := regexp.MustCompile(`href=["']([^"']+)["']`)
	for _, match := range hrefRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			link := c.resolveURL(match[1], base)
			if link != "" && !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	// src links
	srcRe := regexp.MustCompile(`src=["']([^"']+)["']`)
	for _, match := range srcRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			link := c.resolveURL(match[1], base)
			if link != "" && !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	return links
}

// extractJSEndpoints extracts API endpoints from JavaScript
func (c *Crawler) extractJSEndpoints(body string, base *url.URL) []string {
	var endpoints []string
	seen := make(map[string]bool)

	// Common API patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"']+)["']`),
		regexp.MustCompile(`["'](/v[0-9]+/[^"']+)["']`),
		regexp.MustCompile(`["'](/graphql[^"']*)["']`),
		regexp.MustCompile(`fetch\(["']([^"']+)["']`),
		regexp.MustCompile(`axios\.[a-z]+\(["']([^"']+)["']`),
		regexp.MustCompile(`url:\s*["']([^"']+)["']`),
	}

	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(body, -1) {
			if len(match) > 1 {
				endpoint := c.resolveURL(match[1], base)
				if endpoint != "" && !seen[endpoint] {
					seen[endpoint] = true
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	return endpoints
}

// FormInfo holds form information
type FormInfo struct {
	URL    string
	Params []string
}

// extractForms extracts form actions and parameters
func (c *Crawler) extractForms(body string, base *url.URL) []FormInfo {
	var forms []FormInfo

	// Simple form extraction
	formRe := regexp.MustCompile(`(?s)<form[^>]*action=["']([^"']+)["'][^>]*>(.*?)</form>`)
	inputRe := regexp.MustCompile(`name=["']([^"']+)["']`)

	for _, match := range formRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 2 {
			action := c.resolveURL(match[1], base)
			if action == "" {
				action = base.String()
			}

			var params []string
			for _, input := range inputRe.FindAllStringSubmatch(match[2], -1) {
				if len(input) > 1 {
					params = append(params, input[1])
				}
			}

			forms = append(forms, FormInfo{URL: action, Params: params})
		}
	}

	return forms
}

// resolveURL resolves a relative URL against a base
func (c *Crawler) resolveURL(href string, base *url.URL) string {
	href = strings.TrimSpace(href)

	// Skip invalid URLs
	if href == "" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "data:") {
		return ""
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(parsed)

	// Only allow http/https
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}

// isSameHost checks if URL is on same host
func (c *Crawler) isSameHost(urlStr, host string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsed.Host == host || strings.HasSuffix(parsed.Host, "."+host)
}

// markSeen marks URL as seen, returns true if new
func (c *Crawler) markSeen(urlStr string) bool {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()

	// Normalize URL
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	normalized := parsed.Scheme + "://" + parsed.Host + parsed.Path

	if c.seen[normalized] {
		return false
	}
	c.seen[normalized] = true
	return true
}

// urlCount returns number of seen URLs
func (c *Crawler) urlCount() int {
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	return len(c.seen)
}

// classifyURL determines the type of URL
func (c *Crawler) classifyURL(urlStr, contentType string) string {
	lower := strings.ToLower(urlStr)

	if strings.Contains(lower, "/api/") || strings.Contains(lower, "/graphql") {
		return "api"
	}
	if strings.HasSuffix(lower, ".js") {
		return "js"
	}
	if strings.HasSuffix(lower, ".css") {
		return "css"
	}
	if strings.Contains(contentType, "json") {
		return "api"
	}
	if strings.Contains(contentType, "javascript") {
		return "js"
	}

	return "page"
}
