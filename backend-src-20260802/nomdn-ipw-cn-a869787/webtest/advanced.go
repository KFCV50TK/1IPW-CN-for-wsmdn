package webtest

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CustomDNSQuery sends one bounded DNS query to a caller-selected public
// resolver. The resolver must be an IP literal so this endpoint cannot be
// used to resolve an attacker-controlled DNS name into an internal target.
type CustomDNSQuery struct {
	Domain         string   `json:"domain"`
	RecordType     string   `json:"record_type"`
	Server         string   `json:"server"`
	DNSSEC         bool     `json:"dnssec"`
	RCode          int      `json:"rcode"`
	Duration       float64  `json:"duration"`
	Authoritative  bool     `json:"authoritative"`
	Truncated      bool     `json:"truncated"`
	Authenticated  bool     `json:"authenticated"`
	Answers        []string `json:"answers"`
	Authorities    []string `json:"authorities"`
	Additionals    []string `json:"additionals"`
	Validation     string   `json:"validation,omitempty"`
	ValidationNote string   `json:"validation_note,omitempty"`
}

var allowedRecordTypes = map[string]uint16{
	"a":      dns.TypeA,
	"aaaa":   dns.TypeAAAA,
	"cname":  dns.TypeCNAME,
	"mx":     dns.TypeMX,
	"ns":     dns.TypeNS,
	"txt":    dns.TypeTXT,
	"srv":    dns.TypeSRV,
	"caa":    dns.TypeCAA,
	"ptr":    dns.TypePTR,
	"ds":     dns.TypeDS,
	"dnskey": dns.TypeDNSKEY,
	"rrsig":  dns.TypeRRSIG,
	"nsec":   dns.TypeNSEC,
	"nsec3":  dns.TypeNSEC3,
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func normalizeResolver(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("DNS server is required")
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host, port = server, "53"
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return "", fmt.Errorf("DNS server must be a public IP address")
	}
	if isPrivateIP(ip) {
		return "", fmt.Errorf("private or internal DNS servers are not allowed")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid DNS server port")
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func normalizeQuery(domain, recordType string) (string, uint16, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, " /\\") {
		return "", 0, fmt.Errorf("invalid domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", 0, fmt.Errorf("invalid domain")
		}
	}
	typeCode, ok := allowedRecordTypes[strings.ToLower(strings.TrimSpace(recordType))]
	if !ok {
		return "", 0, fmt.Errorf("unsupported DNS record type")
	}
	return domain, typeCode, nil
}

func formatRRs(records []dns.RR, limit int) []string {
	result := make([]string, 0, len(records))
	for _, record := range records {
		if len(result) >= limit {
			break
		}
		value := record.String()
		if len(value) > 2048 {
			value = value[:2048]
		}
		result = append(result, value)
	}
	return result
}

func QueryCustomDNS(ctx context.Context, domain, recordType, server string, dnssec bool) (*CustomDNSQuery, error) {
	domain, typeCode, err := normalizeQuery(domain, recordType)
	if err != nil {
		return nil, err
	}
	server, err = normalizeResolver(server)
	if err != nil {
		return nil, err
	}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), typeCode)
	message.RecursionDesired = true
	message.AuthenticatedData = dnssec
	message.SetEdns0(1232, dnssec)

	client := &dns.Client{Timeout: 5 * time.Second}
	start := time.Now()
	response, _, err := client.ExchangeContext(ctx, message, server)
	if err != nil {
		return nil, err
	}
	result := &CustomDNSQuery{
		Domain:        domain,
		RecordType:    strings.ToUpper(recordType),
		Server:        server,
		DNSSEC:        dnssec,
		RCode:         response.Rcode,
		Duration:      float64(time.Since(start).Microseconds()) / 1000,
		Authoritative: response.Authoritative,
		Truncated:     response.Truncated,
		Authenticated: response.AuthenticatedData,
		Answers:       formatRRs(response.Answer, 100),
		Authorities:   formatRRs(response.Ns, 100),
		Additionals:   formatRRs(response.Extra, 100),
	}
	if dnssec {
		if response.AuthenticatedData {
			result.Validation = "ad-bit"
		} else {
			result.Validation = "not-validated"
		}
		result.ValidationNote = "AD 位来自所选解析器，未在本地验证 DNSSEC 链"
	}
	if result.RCode != dns.RcodeSuccess && result.RCode != dns.RcodeNameError {
		return result, fmt.Errorf("DNS server returned RCODE %d", result.RCode)
	}
	return result, nil
}
