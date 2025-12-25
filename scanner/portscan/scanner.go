package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config holds port scanner configuration
type Config struct {
	Targets       []string
	Ports         []int
	Workers       int
	Timeout       int
	RateLimit     int
	ServiceDetect bool
}

// Result represents a port scan result
type Result struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Open      bool   `json:"open"`
	Service   string `json:"service,omitempty"`
	Banner    string `json:"banner,omitempty"`
	Timestamp string `json:"timestamp"`
}

// Scanner handles port scanning operations
type Scanner struct {
	config  Config
	limiter *rate.Limiter
}

// NewScanner creates a new port scanner
func NewScanner(config Config) *Scanner {
	if config.Workers == 0 {
		config.Workers = 300
	}
	if config.Timeout == 0 {
		config.Timeout = 3
	}
	if config.RateLimit == 0 {
		config.RateLimit = 1000
	}

	return &Scanner{
		config:  config,
		limiter: rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit),
	}
}

// ScanJob represents a single scan job
type ScanJob struct {
	Host string
	Port int
}

// Scan performs the port scan
func (s *Scanner) Scan() ([]Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	jobs := make(chan ScanJob, s.config.Workers*2)
	results := make(chan Result, len(s.config.Targets)*len(s.config.Ports))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, results)
		}()
	}

	// Feed jobs
	go func() {
		for _, target := range s.config.Targets {
			for _, port := range s.config.Ports {
				select {
				case <-ctx.Done():
					break
				default:
					jobs <- ScanJob{Host: target, Port: port}
				}
			}
		}
		close(jobs)
	}()

	// Wait and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect open ports only
	var openPorts []Result
	for result := range results {
		if result.Open {
			openPorts = append(openPorts, result)
		}
	}

	return openPorts, nil
}

// worker processes scan jobs
func (s *Scanner) worker(ctx context.Context, jobs <-chan ScanJob, results chan<- Result) {
	timeout := time.Duration(s.config.Timeout) * time.Second

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			// Rate limiting
			s.limiter.Wait(ctx)

			result := s.scanPort(job.Host, job.Port, timeout)

			// Service detection if enabled
			if result.Open && s.config.ServiceDetect {
				result.Service = s.detectService(job.Host, job.Port, timeout)
			}

			results <- result
		}
	}
}

// scanPort checks if a port is open
func (s *Scanner) scanPort(host string, port int, timeout time.Duration) Result {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return Result{
			Host:      host,
			Port:      port,
			Open:      false,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
	}
	defer conn.Close()

	return Result{
		Host:      host,
		Port:      port,
		Open:      true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// detectService attempts to identify the service
func (s *Scanner) detectService(host string, port int, timeout time.Duration) string {
	// Well-known ports
	wellKnown := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := wellKnown[port]; ok {
		return service
	}

	// Try banner grabbing
	banner := s.grabBanner(host, port, timeout)
	if banner != "" {
		return s.identifyFromBanner(banner)
	}

	return "unknown"
}

// grabBanner attempts to grab service banner
func (s *Scanner) grabBanner(host string, port int, timeout time.Duration) string {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		// Try sending a simple probe
		conn.Write([]byte("\r\n"))
		n, _ = conn.Read(buffer)
	}

	if n > 0 {
		return string(buffer[:n])
	}

	return ""
}

// identifyFromBanner identifies service from banner
func (s *Scanner) identifyFromBanner(banner string) string {
	patterns := map[string]string{
		"SSH":        "ssh",
		"HTTP":       "http",
		"SMTP":       "smtp",
		"FTP":        "ftp",
		"MySQL":      "mysql",
		"PostgreSQL": "postgresql",
		"MongoDB":    "mongodb",
		"Redis":      "redis",
		"nginx":      "nginx",
		"Apache":     "apache",
	}

	for pattern, service := range patterns {
		if containsIgnoreCase(banner, pattern) {
			return service
		}
	}

	return "unknown"
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldBytes(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

// equalFoldBytes compares two strings case-insensitively
func equalFoldBytes(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		sr := s[i]
		tr := t[i]
		if sr >= 'A' && sr <= 'Z' {
			sr = sr + 32
		}
		if tr >= 'A' && tr <= 'Z' {
			tr = tr + 32
		}
		if sr != tr {
			return false
		}
	}
	return true
}
