package http

import (
	"crypto/md5"
	"encoding/hex"
	"regexp"
	"strings"
)

// AnalysisResult holds response analysis results
type AnalysisResult struct {
	URL             string          `json:"url"`
	Title           string          `json:"title,omitempty"`
	Description     string          `json:"description,omitempty"`
	Technologies    []string        `json:"technologies,omitempty"`
	Endpoints       []string        `json:"endpoints,omitempty"`
	Parameters      []string        `json:"parameters,omitempty"`
	Forms           []FormDetails   `json:"forms,omitempty"`
	Comments        []string        `json:"comments,omitempty"`
	Emails          []string        `json:"emails,omitempty"`
	SecurityHeaders SecurityHeaders `json:"security_headers"`
	Interesting     []string        `json:"interesting,omitempty"`
	Hash            string          `json:"hash"`
}

// FormDetails holds extracted form details
type FormDetails struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Fields []string `json:"fields"`
}

// SecurityHeaders holds security header analysis
type SecurityHeaders struct {
	CSP           string `json:"csp,omitempty"`
	HSTS          string `json:"hsts,omitempty"`
	XFrameOptions string `json:"x_frame_options,omitempty"`
	XContentType  string `json:"x_content_type_options,omitempty"`
	XSSProtection string `json:"x_xss_protection,omitempty"`
	CORS          string `json:"cors,omitempty"`
	MissingCount  int    `json:"missing_count"`
}

// ResponseAnalyzer handles deep response analysis
type ResponseAnalyzer struct{}

// NewResponseAnalyzer creates a new response analyzer
func NewResponseAnalyzer() *ResponseAnalyzer {
	return &ResponseAnalyzer{}
}

// Analyze performs deep analysis on HTTP response
func (ra *ResponseAnalyzer) Analyze(url string, headers map[string]string, body string) AnalysisResult {
	result := AnalysisResult{
		URL:  url,
		Hash: ra.hashBody(body),
	}

	// Extract title
	result.Title = extractTitle(body)

	// Extract meta description
	result.Description = ra.extractDescription(body)

	// Detect technologies
	result.Technologies = ra.detectAllTechnologies(headers, body)

	// Extract endpoints from JS
	result.Endpoints = ra.extractEndpoints(body)

	// Extract parameters
	result.Parameters = ra.extractParameters(body)

	// Extract forms
	result.Forms = ra.extractFormDetails(body)

	// Extract comments
	result.Comments = ra.extractComments(body)

	// Extract emails
	result.Emails = ra.extractEmails(body)

	// Analyze security headers
	result.SecurityHeaders = ra.analyzeSecurityHeaders(headers)

	// Find interesting patterns
	result.Interesting = ra.findInteresting(body)

	return result
}

// hashBody creates MD5 hash of body
func (ra *ResponseAnalyzer) hashBody(body string) string {
	hash := md5.Sum([]byte(body))
	return hex.EncodeToString(hash[:])
}

// extractDescription extracts meta description
func (ra *ResponseAnalyzer) extractDescription(body string) string {
	re := regexp.MustCompile(`(?i)<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Try alternate format
	re2 := regexp.MustCompile(`(?i)<meta[^>]*content=["']([^"']+)["'][^>]*name=["']description["']`)
	matches2 := re2.FindStringSubmatch(body)
	if len(matches2) > 1 {
		return strings.TrimSpace(matches2[1])
	}

	return ""
}

// detectAllTechnologies comprehensive tech detection
func (ra *ResponseAnalyzer) detectAllTechnologies(headers map[string]string, body string) []string {
	var techs []string
	seen := make(map[string]bool)

	addTech := func(tech string) {
		if !seen[tech] {
			seen[tech] = true
			techs = append(techs, tech)
		}
	}

	bodyLower := strings.ToLower(body)

	// Server technologies from headers
	if server, ok := headers["Server"]; ok {
		serverLower := strings.ToLower(server)
		if strings.Contains(serverLower, "nginx") {
			addTech("Nginx")
		}
		if strings.Contains(serverLower, "apache") {
			addTech("Apache")
		}
		if strings.Contains(serverLower, "iis") {
			addTech("IIS")
		}
		if strings.Contains(serverLower, "gunicorn") {
			addTech("Gunicorn")
		}
		if strings.Contains(serverLower, "openresty") {
			addTech("OpenResty")
		}
	}

	// X-Powered-By
	if powered, ok := headers["X-Powered-By"]; ok {
		poweredLower := strings.ToLower(powered)
		if strings.Contains(poweredLower, "php") {
			addTech("PHP")
		}
		if strings.Contains(poweredLower, "asp.net") {
			addTech("ASP.NET")
		}
		if strings.Contains(poweredLower, "express") {
			addTech("Express.js")
		}
		if strings.Contains(poweredLower, "next") {
			addTech("Next.js")
		}
	}

	// JavaScript frameworks
	if strings.Contains(body, "__NEXT_DATA__") || strings.Contains(body, "_next/static") {
		addTech("Next.js")
	}
	if strings.Contains(body, "__NUXT__") {
		addTech("Nuxt.js")
	}
	if strings.Contains(bodyLower, "react") || strings.Contains(body, "data-reactroot") {
		addTech("React")
	}
	if strings.Contains(body, "ng-app") || strings.Contains(body, "ng-controller") {
		addTech("AngularJS")
	}
	if strings.Contains(body, "_angular") {
		addTech("Angular")
	}
	if strings.Contains(body, "Vue.") || strings.Contains(body, "v-bind") {
		addTech("Vue.js")
	}
	if strings.Contains(bodyLower, "svelte") {
		addTech("Svelte")
	}

	// CMS
	if strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes") {
		addTech("WordPress")
	}
	if strings.Contains(body, "Drupal.") {
		addTech("Drupal")
	}
	if strings.Contains(bodyLower, "joomla") {
		addTech("Joomla")
	}
	if strings.Contains(body, "shopify") {
		addTech("Shopify")
	}
	if strings.Contains(body, "wix.com") {
		addTech("Wix")
	}

	// CSS Frameworks
	if strings.Contains(bodyLower, "bootstrap") {
		addTech("Bootstrap")
	}
	if strings.Contains(bodyLower, "tailwind") {
		addTech("Tailwind CSS")
	}

	// CDN/Security
	if _, ok := headers["Cf-Ray"]; ok {
		addTech("Cloudflare")
	}
	if strings.Contains(headers["Via"], "cloudfront") {
		addTech("CloudFront")
	}
	if strings.Contains(headers["Server"], "AmazonS3") {
		addTech("Amazon S3")
	}

	return techs
}

// extractEndpoints finds API endpoints in body
func (ra *ResponseAnalyzer) extractEndpoints(body string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/v?[0-9]*/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["'](/graphql[^"']*)["']`),
		regexp.MustCompile(`["'](/rest/[a-zA-Z0-9/_-]+)["']`),
		regexp.MustCompile(`["']https?://[^"']+/api/[^"']+["']`),
		regexp.MustCompile(`endpoint:\s*["']([^"']+)["']`),
		regexp.MustCompile(`baseURL:\s*["']([^"']+)["']`),
	}

	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(body, -1) {
			if len(match) > 1 && !seen[match[1]] {
				seen[match[1]] = true
				endpoints = append(endpoints, match[1])
			}
		}
	}

	return endpoints
}

// extractParameters finds parameter names
func (ra *ResponseAnalyzer) extractParameters(body string) []string {
	var params []string
	seen := make(map[string]bool)

	// Form inputs
	inputRe := regexp.MustCompile(`name=["']([a-zA-Z0-9_-]+)["']`)
	for _, match := range inputRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			params = append(params, match[1])
		}
	}

	// URL parameters in JS
	paramRe := regexp.MustCompile(`[?&]([a-zA-Z0-9_]+)=`)
	for _, match := range paramRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			params = append(params, match[1])
		}
	}

	return params
}

// extractFormDetails extracts detailed form information
func (ra *ResponseAnalyzer) extractFormDetails(body string) []FormDetails {
	var forms []FormDetails

	formRe := regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	actionRe := regexp.MustCompile(`action=["']([^"']+)["']`)
	methodRe := regexp.MustCompile(`(?i)method=["']([^"']+)["']`)
	inputRe := regexp.MustCompile(`name=["']([^"']+)["']`)

	for _, match := range formRe.FindAllStringSubmatch(body, -1) {
		if len(match) < 3 {
			continue
		}

		attrs := match[1]
		content := match[2]

		form := FormDetails{Method: "GET"}

		if actionMatch := actionRe.FindStringSubmatch(attrs); len(actionMatch) > 1 {
			form.Action = actionMatch[1]
		}

		if methodMatch := methodRe.FindStringSubmatch(attrs); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		for _, inputMatch := range inputRe.FindAllStringSubmatch(content, -1) {
			if len(inputMatch) > 1 {
				form.Fields = append(form.Fields, inputMatch[1])
			}
		}

		forms = append(forms, form)
	}

	return forms
}

// extractComments finds HTML/JS comments
func (ra *ResponseAnalyzer) extractComments(body string) []string {
	var comments []string

	// HTML comments
	htmlRe := regexp.MustCompile(`<!--([\s\S]*?)-->`)
	for _, match := range htmlRe.FindAllStringSubmatch(body, 20) {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if len(comment) > 5 && len(comment) < 500 {
				comments = append(comments, comment)
			}
		}
	}

	// JS single-line comments with interesting content
	jsRe := regexp.MustCompile(`//\s*(TODO|FIXME|BUG|HACK|XXX|DEBUG|PASSWORD|SECRET|KEY|TOKEN)[^\n]+`)
	for _, match := range jsRe.FindAllString(body, 10) {
		comments = append(comments, match)
	}

	return comments
}

// extractEmails finds email addresses
func (ra *ResponseAnalyzer) extractEmails(body string) []string {
	var emails []string
	seen := make(map[string]bool)

	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	for _, match := range emailRe.FindAllString(body, 20) {
		if !seen[match] {
			seen[match] = true
			emails = append(emails, match)
		}
	}

	return emails
}

// analyzeSecurityHeaders checks security headers
func (ra *ResponseAnalyzer) analyzeSecurityHeaders(headers map[string]string) SecurityHeaders {
	sh := SecurityHeaders{}
	missing := 0

	if csp, ok := headers["Content-Security-Policy"]; ok {
		sh.CSP = csp
	} else {
		missing++
	}

	if hsts, ok := headers["Strict-Transport-Security"]; ok {
		sh.HSTS = hsts
	} else {
		missing++
	}

	if xfo, ok := headers["X-Frame-Options"]; ok {
		sh.XFrameOptions = xfo
	} else {
		missing++
	}

	if xcto, ok := headers["X-Content-Type-Options"]; ok {
		sh.XContentType = xcto
	} else {
		missing++
	}

	if xxss, ok := headers["X-Xss-Protection"]; ok {
		sh.XSSProtection = xxss
	}

	if cors, ok := headers["Access-Control-Allow-Origin"]; ok {
		sh.CORS = cors
	}

	sh.MissingCount = missing
	return sh
}

// findInteresting finds potentially interesting patterns
func (ra *ResponseAnalyzer) findInteresting(body string) []string {
	var interesting []string

	patterns := map[string]*regexp.Regexp{
		"AWS Key":        regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Private Key":    regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
		"API Key":        regexp.MustCompile(`(?i)api[_-]?key["']\s*[:=]\s*["'][a-zA-Z0-9_-]{20,}["']`),
		"Password Field": regexp.MustCompile(`(?i)password["']\s*[:=]\s*["'][^"']+["']`),
		"Internal IP":    regexp.MustCompile(`(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}`),
		"Debug Enabled":  regexp.MustCompile(`(?i)debug\s*[:=]\s*true`),
		"Admin Path":     regexp.MustCompile(`["'](/admin[^"']*|/dashboard[^"']*)["']`),
		"File Path":      regexp.MustCompile(`(?:\/etc\/|\/var\/|C:\\\\|\/home\/)[^\s"'<>]+`),
		"SQL Query":      regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.+FROM`),
		"Backup File":    regexp.MustCompile(`(?i)["'][^"']+\.(bak|backup|old|sql|tar|zip)["']`),
	}

	for name, pattern := range patterns {
		matches := pattern.FindAllString(body, 3)
		for _, match := range matches {
			if len(match) < 200 {
				interesting = append(interesting, name+": "+match)
			}
		}
	}

	return interesting
}
