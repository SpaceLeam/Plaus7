package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config holds subdomain scanner configuration
type Config struct {
	Domain     string
	Wordlist   string
	Workers    int
	Timeout    int
	Passive    bool
	Bruteforce bool
}

// Result represents a discovered subdomain
type Result struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"`
	Source    string   `json:"source"`
	Timestamp string   `json:"timestamp"`
}

// Scanner handles subdomain enumeration
type Scanner struct {
	config   Config
	results  chan Result
	seen     map[string]bool
	seenLock sync.Mutex
	client   *http.Client
}

// NewScanner creates a new subdomain scanner
func NewScanner(config Config) *Scanner {
	return &Scanner{
		config: config,
		seen:   make(map[string]bool),
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
	}
}

// Enumerate performs subdomain enumeration
func (s *Scanner) Enumerate() ([]Result, error) {
	s.results = make(chan Result, 10000)
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.Timeout)*time.Minute)
	defer cancel()

	// Passive enumeration
	if s.config.Passive {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.passiveEnumerate(ctx)
		}()
	}

	// Bruteforce enumeration
	if s.config.Bruteforce && s.config.Wordlist != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.bruteforceEnumerate(ctx)
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(s.results)
	}()

	var results []Result
	for result := range s.results {
		results = append(results, result)
	}

	return results, nil
}

// passiveEnumerate uses passive sources
func (s *Scanner) passiveEnumerate(ctx context.Context) {
	sources := []struct {
		name string
		fn   func(context.Context, string) []string
	}{
		{"crtsh", s.queryCrtSh},
		{"hackertarget", s.queryHackerTarget},
		{"threatcrowd", s.queryThreatCrowd},
	}

	var wg sync.WaitGroup
	for _, source := range sources {
		wg.Add(1)
		go func(name string, fn func(context.Context, string) []string) {
			defer wg.Done()
			subdomains := fn(ctx, s.config.Domain)
			for _, sub := range subdomains {
				s.addResult(sub, name)
			}
		}(source.name, source.fn)
	}
	wg.Wait()
}

// queryCrtSh queries Certificate Transparency logs
func (s *Scanner) queryCrtSh(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	var subdomains []string
	seen := make(map[string]bool)

	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimPrefix(name, "*.")
			name = strings.TrimSpace(name)
			if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains
}

// queryHackerTarget queries HackerTarget API
func (s *Scanner) queryHackerTarget(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var subdomains []string
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			sub := strings.TrimSpace(parts[0])
			if sub != "" && strings.HasSuffix(sub, domain) {
				subdomains = append(subdomains, sub)
			}
		}
	}

	return subdomains
}

// queryThreatCrowd queries ThreatCrowd API
func (s *Scanner) queryThreatCrowd(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	return result.Subdomains
}

// bruteforceEnumerate performs DNS bruteforce
func (s *Scanner) bruteforceEnumerate(ctx context.Context) {
	file, err := os.Open(s.config.Wordlist)
	if err != nil {
		return
	}
	defer file.Close()

	// Create worker pool
	jobs := make(chan string, s.config.Workers*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.bruteforceWorker(ctx, jobs)
		}()
	}

	// Feed jobs
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			word := strings.TrimSpace(scanner.Text())
			if word != "" && !strings.HasPrefix(word, "#") {
				jobs <- word
			}
		}
	}
	close(jobs)

	wg.Wait()
}

// bruteforceWorker resolves subdomains from wordlist
func (s *Scanner) bruteforceWorker(ctx context.Context, jobs <-chan string) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	for word := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			subdomain := fmt.Sprintf("%s.%s", word, s.config.Domain)
			ips, err := resolver.LookupIPAddr(ctx, subdomain)
			if err == nil && len(ips) > 0 {
				s.addResult(subdomain, "bruteforce")
			}
		}
	}
}

// addResult adds a unique result
func (s *Scanner) addResult(subdomain, source string) {
	s.seenLock.Lock()
	defer s.seenLock.Unlock()

	if s.seen[subdomain] {
		return
	}
	s.seen[subdomain] = true

	s.results <- Result{
		Subdomain: subdomain,
		Source:    source,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}
