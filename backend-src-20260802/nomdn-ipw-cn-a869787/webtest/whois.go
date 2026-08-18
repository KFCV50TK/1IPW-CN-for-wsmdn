package webtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WhoisRegistrar describes the registrar fields exposed by the compatibility API.
type WhoisRegistrar struct {
	Name   string `json:"name"`
	IANAID string `json:"ianaId"`
}

type WhoisContact struct {
	Name       string `json:"name"`
	Org        string `json:"org"`
	Phone      string `json:"phone"`
	Email      string `json:"email"`
	Province   string `json:"province"`
	ContactURI string `json:"contactUri"`
}

type WhoisDates struct {
	Registration string `json:"registration"`
	Expiration   string `json:"expiration"`
	LastChanged  string `json:"lastChanged"`
}

type WhoisResult struct {
	Domain       string         `json:"domain"`
	Status       []string       `json:"status"`
	Registrar    WhoisRegistrar `json:"registrar"`
	Registrant   WhoisContact   `json:"registrant"`
	Technical    WhoisContact   `json:"technical"`
	AbuseContact WhoisContact   `json:"abuseContact"`
	Dates        WhoisDates     `json:"dates"`
	Nameservers  []string       `json:"nameservers"`
	WhoisServer  string         `json:"whoisServer"`
	Raw          string         `json:"raw"`
	Error        string         `json:"error"`
}

type ASNWhoisResult struct {
	ASNumber   string `json:"asNumber"`
	ASName     string `json:"asName"`
	OrgName    string `json:"orgName"`
	OrgID      string `json:"orgId"`
	Country    string `json:"country"`
	RegDate    string `json:"regDate"`
	Updated    string `json:"updated"`
	AbuseName  string `json:"abuseName"`
	AbuseEmail string `json:"abuseEmail"`
	AbusePhone string `json:"abusePhone"`
	Raw        string `json:"raw"`
	Error      string `json:"error"`
}

var tldWhoisServers = map[string]string{
	"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
	"org": "whois.pir.org", "info": "whois.afilias.net", "biz": "whois.biz",
	"name": "whois.nic.name", "xyz": "whois.nic.xyz", "top": "whois.nic.top",
	"shop": "whois.nic.shop", "io": "whois.nic.io", "co": "whois.nic.co",
	"me": "whois.nic.me", "dev": "whois.nic.google", "app": "whois.nic.google",
	"cn": "whois.cnnic.cn", "cc": "whois.nic.cc", "tv": "whois.nic.tv",
	"uk": "whois.nic.uk", "de": "whois.denic.de", "fr": "whois.nic.fr",
}

var whoisDomainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func normalizeWhoisDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || len(domain) > 253 || !whoisDomainPattern.MatchString(domain) {
		return "", fmt.Errorf("invalid domain")
	}
	return domain, nil
}

func QueryWhois(domain string) (*WhoisResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return QueryWhoisContext(ctx, domain)
}

func QueryWhoisContext(ctx context.Context, domain string) (*WhoisResult, error) {
	domain, err := normalizeWhoisDomain(domain)
	if err != nil {
		return nil, err
	}
	server, err := resolveWhoisServer(ctx, domain)
	if err != nil {
		return nil, err
	}
	raw, err := queryWhoisRaw(ctx, server, domain)
	if err != nil {
		// A few registries intermittently fail their referral server. Retry via
		// IANA's referral before returning an upstream error.
		if fallback, fallbackErr := resolveWhoisServerFromIANA(ctx, domain); fallbackErr == nil && fallback != server {
			server = fallback
			raw, err = queryWhoisRaw(ctx, server, domain)
		}
		if err != nil {
			return nil, err
		}
	}
	result := parseWhoisResult(domain, server, raw)
	return result, nil
}

func resolveWhoisServer(ctx context.Context, domain string) (string, error) {
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return "", fmt.Errorf("invalid domain")
	}
	if server := tldWhoisServers[labels[len(labels)-1]]; server != "" {
		return server, nil
	}
	return resolveWhoisServerFromIANA(ctx, domain)
}

func resolveWhoisServerFromIANA(ctx context.Context, domain string) (string, error) {
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return "", fmt.Errorf("invalid domain")
	}
	raw, err := queryWhoisRaw(ctx, "whois.iana.org", labels[len(labels)-1])
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(raw, "\n") {
		key, value := splitWhoisLine(line)
		if strings.EqualFold(key, "whois") && value != "" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("WHOIS server is unavailable for %s", domain)
}

func queryWhoisRaw(ctx context.Context, server, query string) (string, error) {
	if strings.TrimSpace(server) == "" {
		return "", fmt.Errorf("WHOIS server is empty")
	}
	dialer := net.Dialer{Timeout: 8 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer connection.Close()
	deadline := time.Now().Add(8 * time.Second)
	if requestDeadline, ok := ctx.Deadline(); ok && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	_ = connection.SetDeadline(deadline)
	if _, err := fmt.Fprintf(connection, "%s\r\n", query); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(connection, 128*1024+1))
	if err != nil {
		return "", err
	}
	if len(data) > 128*1024 {
		return "", fmt.Errorf("WHOIS response is too large")
	}
	return strings.TrimSpace(string(data)), nil
}

func splitWhoisLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
		return "", ""
	}
	separator := strings.IndexAny(line, ":=")
	if separator <= 0 {
		return "", ""
	}
	return strings.TrimSpace(line[:separator]), strings.TrimSpace(line[separator+1:])
}

func normalizeWhoisKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "_", " ")
	key = strings.ReplaceAll(key, "-", " ")
	return strings.Join(strings.Fields(key), " ")
}

func parseWhoisFields(raw string) map[string][]string {
	fields := make(map[string][]string)
	for _, line := range strings.Split(raw, "\n") {
		key, value := splitWhoisLine(line)
		if key == "" || value == "" {
			continue
		}
		fields[normalizeWhoisKey(key)] = append(fields[normalizeWhoisKey(key)], strings.TrimSpace(value))
	}
	return fields
}

func fieldFirst(fields map[string][]string, keys ...string) string {
	for _, key := range keys {
		if values := fields[normalizeWhoisKey(key)]; len(values) > 0 {
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return strings.TrimSpace(value)
				}
			}
		}
	}
	return ""
}

func fieldAll(fields map[string][]string, keys ...string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, key := range keys {
		for _, value := range fields[normalizeWhoisKey(key)] {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[strings.ToLower(value)]; ok {
				continue
			}
			seen[strings.ToLower(value)] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func parseWhoisContact(fields map[string][]string, prefix string) WhoisContact {
	prefix = normalizeWhoisKey(prefix)
	return WhoisContact{
		Name:       fieldFirst(fields, prefix+" name", prefix, prefix+" contact name"),
		Org:        fieldFirst(fields, prefix+" organization", prefix+" organisation", prefix+" org"),
		Phone:      fieldFirst(fields, prefix+" phone", prefix+" phone number", prefix+" telephone"),
		Email:      fieldFirst(fields, prefix+" email", prefix+" email address"),
		Province:   fieldFirst(fields, prefix+" state/province", prefix+" state", prefix+" province", prefix+" region"),
		ContactURI: fieldFirst(fields, prefix+" contact uri", prefix+" contact url", prefix+" url"),
	}
}

func parseWhoisResult(domain, server, raw string) *WhoisResult {
	fields := parseWhoisFields(raw)
	result := &WhoisResult{
		Domain: strings.ToUpper(domain),
		Status: fieldAll(fields, "domain status", "status"),
		Registrar: WhoisRegistrar{
			Name:   fieldFirst(fields, "registrar", "registrar name", "sponsoring registrar"),
			IANAID: fieldFirst(fields, "registrar iana id", "iana id", "registrar id"),
		},
		Registrant:   parseWhoisContact(fields, "registrant"),
		Technical:    parseWhoisContact(fields, "technical"),
		AbuseContact: parseWhoisContact(fields, "abuse"),
		Dates: WhoisDates{
			Registration: fieldFirst(fields, "creation date", "created date", "created on", "registered on", "registration date", "registration time"),
			Expiration:   fieldFirst(fields, "registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "paid till"),
			LastChanged:  fieldFirst(fields, "updated date", "last updated on", "last updated date", "last changed", "modification date"),
		},
		Nameservers: fieldAll(fields, "name server", "nameserver", "nserver"),
		WhoisServer: server,
		Raw:         raw,
		Error:       fieldFirst(fields, "error", "remarks"),
	}
	return result
}

func QueryASNWhois(asn string) (*ASNWhoisResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return QueryASNWhoisContext(ctx, asn)
}

func QueryASNWhoisContext(ctx context.Context, asn string) (*ASNWhoisResult, error) {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	asn = strings.TrimPrefix(asn, "AS")
	if _, err := strconv.ParseUint(asn, 10, 32); err != nil {
		return nil, fmt.Errorf("invalid ASN")
	}
	query := "AS" + asn
	servers := []string{"whois.arin.net", "whois.ripe.net", "whois.apnic.net", "whois.lacnic.net", "whois.afrinic.net"}
	var lastErr error
	for _, server := range servers {
		raw, err := queryWhoisRaw(ctx, server, query)
		if err != nil {
			lastErr = err
			continue
		}
		result := parseASNWhoisResult(query, raw)
		if result.ASNumber != "" || result.OrgName != "" || result.ASName != "" {
			return result, nil
		}
		lastErr = fmt.Errorf("ASN data is unavailable")
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ASN WHOIS data is unavailable")
	}
	return nil, lastErr
}

func parseASNWhoisResult(asn, raw string) *ASNWhoisResult {
	fields := parseWhoisFields(raw)
	result := &ASNWhoisResult{
		ASNumber:   fieldFirst(fields, "as number", "aut num", "aut-num", "as handle", "origin"),
		ASName:     fieldFirst(fields, "as name", "as-name"),
		OrgName:    fieldFirst(fields, "org name", "org-name", "organization", "organisation", "org"),
		OrgID:      fieldFirst(fields, "org id", "org-id", "organisation id", "handle"),
		Country:    fieldFirst(fields, "country", "country code"),
		RegDate:    fieldFirst(fields, "reg date", "regdate", "created", "created date", "registration date"),
		Updated:    fieldFirst(fields, "updated", "updated date", "last modified", "last-modified", "last changed"),
		AbuseName:  fieldFirst(fields, "abuse name", "abuse contact name", "abuse-c"),
		AbuseEmail: fieldFirst(fields, "abuse email", "abuse-mailbox", "abuse mailbox", "email"),
		AbusePhone: fieldFirst(fields, "abuse phone", "abuse telephone", "phone"),
		Raw:        raw,
	}
	if result.ASNumber == "" {
		result.ASNumber = asn
	}
	result.ASNumber = strings.TrimPrefix(strings.ToUpper(result.ASNumber), "AS")
	return result
}

// Keep deterministic output when callers inspect a field map during debugging.
func sortedWhoisKeys(fields map[string][]string) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
