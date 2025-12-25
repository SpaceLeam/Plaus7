package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/recon-suite/scanner/http"
	"github.com/recon-suite/scanner/portscan"
	"github.com/recon-suite/scanner/subdomain"
)

const version = "1.0.0"

// Output formats
type OutputFormat string

const (
	FormatJSON OutputFormat = "json"
	FormatTXT  OutputFormat = "txt"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "subdomain":
		runSubdomainEnum()
	case "portscan":
		runPortScan()
	case "probe":
		runHTTPProbe()
	case "version":
		fmt.Printf("Recon Scanner v%s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	usage := `
Recon Scanner - Smart Reconnaissance Tool
==========================================

Usage: scanner <command> [options]

Commands:
  subdomain   Enumerate subdomains for a target domain
  portscan    Scan ports on target hosts
  probe       HTTP/HTTPS probing on targets
  version     Show version information
  help        Show this help message

Examples:
  scanner subdomain -d example.com -w 200 -o results.json
  scanner portscan -t hosts.txt -p 1-1000 -w 300 -o ports.json
  scanner probe -l urls.txt -w 100 -o alive.json

Use "scanner <command> -h" for more information about a command.
`
	fmt.Println(usage)
}

func runSubdomainEnum() {
	fs := flag.NewFlagSet("subdomain", flag.ExitOnError)
	domain := fs.String("d", "", "Target domain to enumerate")
	wordlist := fs.String("w", "", "Wordlist for bruteforce (optional)")
	workers := fs.Int("c", 100, "Number of concurrent workers")
	timeout := fs.Int("t", 30, "Timeout in seconds")
	output := fs.String("o", "", "Output file (default: stdout)")
	format := fs.String("f", "json", "Output format: json, txt")
	passive := fs.Bool("passive", true, "Enable passive enumeration")
	bruteforce := fs.Bool("bruteforce", false, "Enable bruteforce enumeration")

	fs.Parse(os.Args[2:])

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "Error: -d (domain) is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	config := subdomain.Config{
		Domain:     *domain,
		Wordlist:   *wordlist,
		Workers:    *workers,
		Timeout:    *timeout,
		Passive:    *passive,
		Bruteforce: *bruteforce,
	}

	scanner := subdomain.NewScanner(config)
	results, err := scanner.Enumerate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	outputResults(results, *output, OutputFormat(*format))
}

func runPortScan() {
	fs := flag.NewFlagSet("portscan", flag.ExitOnError)
	target := fs.String("t", "", "Target host or file with hosts (one per line)")
	ports := fs.String("p", "1-1000", "Port range or comma-separated ports")
	workers := fs.Int("c", 300, "Number of concurrent workers")
	timeout := fs.Int("timeout", 3, "Timeout per port in seconds")
	output := fs.String("o", "", "Output file (default: stdout)")
	format := fs.String("f", "json", "Output format: json, txt")
	serviceDetect := fs.Bool("sV", false, "Enable service detection")

	fs.Parse(os.Args[2:])

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: -t (target) is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Parse targets (single host or file)
	targets := parseTargets(*target)

	// Parse ports
	portList := parsePorts(*ports)

	config := portscan.Config{
		Targets:       targets,
		Ports:         portList,
		Workers:       *workers,
		Timeout:       *timeout,
		ServiceDetect: *serviceDetect,
	}

	scanner := portscan.NewScanner(config)
	results, err := scanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	outputResults(results, *output, OutputFormat(*format))
}

func runHTTPProbe() {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	target := fs.String("l", "", "File with URLs (one per line) or single URL")
	workers := fs.Int("c", 100, "Number of concurrent workers")
	timeout := fs.Int("t", 10, "Timeout in seconds")
	output := fs.String("o", "", "Output file (default: stdout)")
	format := fs.String("f", "json", "Output format: json, txt")
	followRedirect := fs.Bool("fr", true, "Follow redirects")
	maxRedirects := fs.Int("maxr", 5, "Maximum redirects to follow")
	tlsVerify := fs.Bool("tls", false, "Verify TLS certificates")
	retries := fs.Int("retries", 2, "Number of retries on failure")

	fs.Parse(os.Args[2:])

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: -l (target) is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Parse targets
	targets := parseTargets(*target)

	config := http.ProbeConfig{
		Targets:        targets,
		Workers:        *workers,
		Timeout:        *timeout,
		FollowRedirect: *followRedirect,
		MaxRedirects:   *maxRedirects,
		TLSVerify:      *tlsVerify,
		Retries:        *retries,
	}

	prober := http.NewProber(config)
	results, err := prober.Probe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	outputResults(results, *output, OutputFormat(*format))
}

// parseTargets reads targets from file or returns single target
func parseTargets(target string) []string {
	// Check if it's a file
	if _, err := os.Stat(target); err == nil {
		data, err := os.ReadFile(target)
		if err != nil {
			return []string{target}
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		var targets []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		return targets
	}
	return []string{target}
}

// parsePorts parses port specification (e.g., "80,443,8080" or "1-1000")
func parsePorts(spec string) []int {
	var ports []int

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "-") {
			// Range
			var start, end int
			fmt.Sscanf(part, "%d-%d", &start, &end)
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			// Single port
			var p int
			fmt.Sscanf(part, "%d", &p)
			if p > 0 {
				ports = append(ports, p)
			}
		}
	}

	return ports
}

// outputResults writes results to file or stdout
func outputResults(results interface{}, outputFile string, format OutputFormat) {
	var output []byte
	var err error

	switch format {
	case FormatJSON:
		output, err = json.MarshalIndent(results, "", "  ")
	case FormatTXT:
		output = formatAsText(results)
	default:
		output, err = json.MarshalIndent(results, "", "  ")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, output, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(string(output))
	}
}

// formatAsText converts results to plain text format
func formatAsText(results interface{}) []byte {
	var lines []string

	switch v := results.(type) {
	case []string:
		lines = v
	case []subdomain.Result:
		for _, r := range v {
			lines = append(lines, r.Subdomain)
		}
	case []portscan.Result:
		for _, r := range v {
			lines = append(lines, fmt.Sprintf("%s:%d %s", r.Host, r.Port, r.Service))
		}
	case []http.ProbeResult:
		for _, r := range v {
			lines = append(lines, r.URL)
		}
	default:
		data, _ := json.Marshal(results)
		return data
	}

	return []byte(strings.Join(lines, "\n"))
}
