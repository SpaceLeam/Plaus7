package portscan

import (
	"fmt"
	"net"
	"time"
)

// ServiceDetector handles service fingerprinting
type ServiceDetector struct {
	timeout time.Duration
}

// NewServiceDetector creates a new service detector
func NewServiceDetector(timeout time.Duration) *ServiceDetector {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &ServiceDetector{timeout: timeout}
}

// ServiceInfo holds detected service information
type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Product string `json:"product,omitempty"`
}

// Detect identifies the service running on a port
func (sd *ServiceDetector) Detect(host string, port int) ServiceInfo {
	info := ServiceInfo{Name: "unknown"}

	// First, try well-known ports
	if name := sd.wellKnownPort(port); name != "" {
		info.Name = name
	}

	// Try to grab banner
	banner := sd.grabBanner(host, port)
	if banner != "" {
		info.Banner = banner
		parsed := sd.parseBanner(banner)
		if parsed.Name != "" {
			info.Name = parsed.Name
		}
		if parsed.Version != "" {
			info.Version = parsed.Version
		}
		if parsed.Product != "" {
			info.Product = parsed.Product
		}
	}

	// Try HTTP probe if port looks like HTTP
	if sd.looksLikeHTTP(port) && info.Name == "unknown" {
		httpInfo := sd.probeHTTP(host, port)
		if httpInfo.Name != "" {
			return httpInfo
		}
	}

	return info
}

// wellKnownPort returns service name for well-known ports
func (sd *ServiceDetector) wellKnownPort(port int) string {
	ports := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		67:    "dhcp",
		68:    "dhcp",
		69:    "tftp",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		123:   "ntp",
		135:   "msrpc",
		137:   "netbios-ns",
		138:   "netbios-dgm",
		139:   "netbios-ssn",
		143:   "imap",
		161:   "snmp",
		162:   "snmptrap",
		389:   "ldap",
		443:   "https",
		445:   "microsoft-ds",
		465:   "smtps",
		514:   "syslog",
		515:   "printer",
		587:   "submission",
		636:   "ldaps",
		873:   "rsync",
		993:   "imaps",
		995:   "pop3s",
		1080:  "socks",
		1433:  "mssql",
		1434:  "mssql-m",
		1521:  "oracle",
		1723:  "pptp",
		2049:  "nfs",
		2082:  "cpanel",
		2083:  "cpanel-ssl",
		2181:  "zookeeper",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		4369:  "epmd",
		5432:  "postgresql",
		5672:  "amqp",
		5900:  "vnc",
		5984:  "couchdb",
		6379:  "redis",
		6667:  "irc",
		8000:  "http-alt",
		8080:  "http-proxy",
		8443:  "https-alt",
		8888:  "http-alt",
		9000:  "cslistener",
		9090:  "zeus-admin",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		11211: "memcached",
		27017: "mongodb",
		27018: "mongodb",
		28017: "mongodb-web",
	}

	return ports[port]
}

// grabBanner attempts to get service banner
func (sd *ServiceDetector) grabBanner(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, sd.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(sd.timeout))

	// Read initial banner
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)

	// If no immediate response, try sending probe
	if n == 0 || err != nil {
		probes := [][]byte{
			[]byte("\r\n"),
			[]byte("HEAD / HTTP/1.0\r\n\r\n"),
			[]byte("HELP\r\n"),
		}

		for _, probe := range probes {
			conn.SetDeadline(time.Now().Add(sd.timeout))
			conn.Write(probe)
			n, err = conn.Read(buffer)
			if n > 0 && err == nil {
				break
			}
		}
	}

	if n > 0 {
		// Clean up non-printable characters
		return cleanBanner(string(buffer[:n]))
	}

	return ""
}

// cleanBanner removes non-printable characters
func cleanBanner(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] < 127 || s[i] == '\n' || s[i] == '\r' || s[i] == '\t' {
			result = append(result, s[i])
		}
	}
	// Truncate to 256 chars
	if len(result) > 256 {
		result = result[:256]
	}
	return string(result)
}

// parseBanner extracts service info from banner
func (sd *ServiceDetector) parseBanner(banner string) ServiceInfo {
	info := ServiceInfo{}

	// SSH
	if len(banner) > 3 && banner[:4] == "SSH-" {
		info.Name = "ssh"
		// Extract version like SSH-2.0-OpenSSH_8.2p1
		if len(banner) > 10 {
			info.Version = banner[4:min(len(banner), 50)]
		}
		return info
	}

	// HTTP
	if len(banner) > 4 && (banner[:4] == "HTTP" || banner[:4] == "http") {
		info.Name = "http"
		// Look for Server header
		if idx := findString(banner, "Server:"); idx != -1 {
			end := findChar(banner[idx:], '\r')
			if end == -1 {
				end = findChar(banner[idx:], '\n')
			}
			if end == -1 {
				end = min(len(banner)-idx, 100)
			}
			info.Product = banner[idx+8 : idx+end]
		}
		return info
	}

	// MySQL
	if containsIgnoreCase(banner, "mysql") || containsIgnoreCase(banner, "mariadb") {
		info.Name = "mysql"
		return info
	}

	// PostgreSQL
	if containsIgnoreCase(banner, "postgresql") {
		info.Name = "postgresql"
		return info
	}

	// Redis
	if containsIgnoreCase(banner, "redis") || banner[:1] == "-" || banner[:1] == "+" {
		info.Name = "redis"
		return info
	}

	// FTP
	if len(banner) > 3 && banner[:3] == "220" {
		info.Name = "ftp"
		info.Banner = banner
		return info
	}

	// SMTP
	if len(banner) > 3 && (banner[:3] == "220" || banner[:4] == "250 ") {
		if containsIgnoreCase(banner, "smtp") || containsIgnoreCase(banner, "mail") {
			info.Name = "smtp"
			return info
		}
	}

	return info
}

// looksLikeHTTP checks if port is typically HTTP
func (sd *ServiceDetector) looksLikeHTTP(port int) bool {
	httpPorts := map[int]bool{
		80: true, 443: true, 8000: true, 8080: true,
		8443: true, 8888: true, 3000: true, 5000: true,
		9000: true, 9090: true,
	}
	return httpPorts[port]
}

// probeHTTP sends HTTP request to detect web server
func (sd *ServiceDetector) probeHTTP(host string, port int) ServiceInfo {
	info := ServiceInfo{}

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, sd.timeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(sd.timeout))

	// Send HTTP request
	request := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	conn.Write([]byte(request))

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return info
	}

	response := string(buffer[:n])

	if len(response) > 4 && response[:4] == "HTTP" {
		info.Name = "http"

		// Extract Server header
		if idx := findString(response, "Server:"); idx != -1 {
			end := findChar(response[idx:], '\r')
			if end == -1 {
				end = findChar(response[idx:], '\n')
			}
			if end > 8 {
				info.Product = response[idx+8 : idx+end]
			}
		}
	}

	return info
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldBytes(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func findChar(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
