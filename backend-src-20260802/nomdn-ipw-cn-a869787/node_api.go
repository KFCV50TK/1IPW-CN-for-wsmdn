package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lemon-ipw/ssrf"
	"lemon-ipw/webtest"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultKeyStore  = "node_keys.json"
	maxHTTPBody      = 64 * 1024
	maxHTTPTimeout   = 10 * time.Second
	defaultTraceHops = 18
)

type nodeAPIKey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type keyStore struct {
	mu   sync.Mutex
	path string
	keys []nodeAPIKey
}

var nodeKeys = &keyStore{}

func initKeyStore() error {
	path := strings.TrimSpace(os.Getenv("IPW_API_KEY_STORE"))
	if path == "" {
		path = defaultKeyStore
	}
	nodeKeys.path = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		nodeKeys.keys = []nodeAPIKey{}
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		nodeKeys.keys = []nodeAPIKey{}
		return nil
	}
	if err := json.Unmarshal(data, &nodeKeys.keys); err != nil {
		return fmt.Errorf("invalid API key store: %w", err)
	}
	return nil
}

func (s *keyStore) persistLocked() error {
	data, err := json.MarshalIndent(s.keys, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashAPIKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newAPIKey() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "sk-ipw-" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (s *keyStore) valid(value string) bool {
	if !strings.HasPrefix(value, "sk-ipw-") {
		return false
	}
	hash := hashAPIKey(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.keys {
		if key.Hash == hash && key.RevokedAt == nil {
			return true
		}
	}
	return false
}

func bearerToken(c *gin.Context) string {
	value := strings.TrimSpace(c.GetHeader("Authorization"))
	if len(value) > 7 && strings.EqualFold(value[:7], "Bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return strings.TrimSpace(c.GetHeader("X-IPW-Admin-Token"))
}

func requireNodeKey(c *gin.Context) bool {
	if !nodeKeys.valid(bearerToken(c)) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "valid API key required"})
		return false
	}
	return true
}

func limitNodeBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

func requireAdmin(c *gin.Context) bool {
	expected := strings.TrimSpace(os.Getenv("IPW_ADMIN_TOKEN"))
	if expected == "" || bearerToken(c) == "" || !secureStringEqual(bearerToken(c), expected) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "admin token required"})
		return false
	}
	return true
}

func secureStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

func createKeyHandler(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = "Unnamed key"
	}
	if len(name) > 80 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is too long"})
		return
	}
	plain, err := newAPIKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create key"})
		return
	}
	key := nodeAPIKey{ID: keyID(), Name: name, Hash: hashAPIKey(plain), CreatedAt: time.Now().UTC()}
	nodeKeys.mu.Lock()
	nodeKeys.keys = append(nodeKeys.keys, key)
	err = nodeKeys.persistLocked()
	nodeKeys.mu.Unlock()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not persist key"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": key.ID, "name": key.Name, "key": plain, "created_at": key.CreatedAt})
}

func keyID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buffer)
}

func listKeysHandler(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	nodeKeys.mu.Lock()
	defer nodeKeys.mu.Unlock()
	result := make([]nodeAPIKey, len(nodeKeys.keys))
	copy(result, nodeKeys.keys)
	for index := range result {
		result[index].Hash = ""
	}
	c.JSON(http.StatusOK, gin.H{"keys": result})
}

func revokeKeyHandler(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	nodeKeys.mu.Lock()
	found := false
	for index := range nodeKeys.keys {
		if nodeKeys.keys[index].ID != id {
			continue
		}
		now := time.Now().UTC()
		nodeKeys.keys[index].RevokedAt = &now
		found = true
		break
	}
	var err error
	if found {
		err = nodeKeys.persistLocked()
	}
	nodeKeys.mu.Unlock()
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not persist key"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

type httpProbeRequest struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Body   string `json:"body"`
}

func validatePublicURL(raw string) (*url.URL, context.Context, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, nil, fmt.Errorf("URL must use http or https")
	}
	ips, err := resolvePublicIPs(parsed.Hostname())
	if err != nil {
		return nil, nil, err
	}
	ctx := context.WithValue(context.Background(), ssrf.ValidatedIPsKey(), ssrf.ValidatedTarget{
		Host: strings.TrimSuffix(strings.ToLower(parsed.Hostname()), "."),
		IPs:  ips,
	})
	return parsed, ctx, nil
}

func resolvePublicIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ssrf.IsPrivateIP(ip) {
			return nil, fmt.Errorf("private or internal targets are not allowed")
		}
		return []net.IP{ip}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	public := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ssrf.IsPrivateIP(ip) {
			return nil, fmt.Errorf("host resolves to a private or internal address")
		}
		public = append(public, ip)
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("no public address found for %s", host)
	}
	return public, nil
}

func httpProbeHandler(c *gin.Context) {
	if !requireNodeKey(c) {
		return
	}
	var input httpProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	parsed, ctx, err := validatePublicURL(input.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodPost {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only GET and POST are supported"})
		return
	}
	if len(input.Body) > 4096 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body is too large"})
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, maxHTTPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, parsed.String(), strings.NewReader(input.Body))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	request.Header.Set("User-Agent", "IPW-Network-Diagnostic/1.0")
	request.Header.Set("Accept", "*/*")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	}
	validated, _ := ctx.Value(ssrf.ValidatedIPsKey()).(ssrf.ValidatedTarget)
	dialer := &net.Dialer{Timeout: maxHTTPTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()},
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr == nil && strings.EqualFold(strings.TrimSuffix(host, "."), validated.Host) {
				var lastErr error
				for _, ip := range validated.IPs {
					connection, dialErr := dialer.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), port))
					if dialErr == nil {
						return connection, nil
					}
					lastErr = dialErr
				}
				return nil, lastErr
			}
			return dialer.DialContext(dialCtx, network, address)
		},
	}
	client := &http.Client{Timeout: maxHTTPTimeout, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody+1))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	truncated := len(body) > maxHTTPBody
	if truncated {
		body = body[:maxHTTPBody]
	}
	c.JSON(http.StatusOK, gin.H{
		"url":          parsed.String(),
		"method":       method,
		"status":       response.StatusCode,
		"duration":     float64(time.Since(start).Microseconds()) / 1000,
		"content_type": response.Header.Get("Content-Type"),
		"size":         len(body),
		"truncated":    truncated,
		"body":         string(body),
	})
}

type socketProbeRequest struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Timeout int    `json:"timeout_ms"`
}

func publicAddress(host string, port int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("host and port are required")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ssrf.IsPrivateIP(ip) {
			return "", fmt.Errorf("private or internal targets are not allowed")
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ssrf.IsPrivateIP(ip) {
			return "", fmt.Errorf("host resolves to a private or internal address")
		}
	}
	return net.JoinHostPort(ips[0].String(), strconv.Itoa(port)), nil
}

func socketTimeout(value int) time.Duration {
	if value < 100 || value > 5000 {
		return 3 * time.Second
	}
	return time.Duration(value) * time.Millisecond
}

func tcpProbeHandler(c *gin.Context) {
	if !requireNodeKey(c) {
		return
	}
	var input socketProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	address, err := publicAddress(input.Host, input.Port)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	start := time.Now()
	connection, err := net.DialTimeout("tcp", address, socketTimeout(input.Timeout))
	duration := float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"protocol": "tcp", "address": address, "success": false, "duration": duration, "error": err.Error()})
		return
	}
	connection.Close()
	c.JSON(http.StatusOK, gin.H{"protocol": "tcp", "address": address, "success": true, "duration": duration})
}

func udpProbeHandler(c *gin.Context) {
	if !requireNodeKey(c) {
		return
	}
	var input socketProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	address, err := publicAddress(input.Host, input.Port)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	timeout := socketTimeout(input.Timeout)
	connection, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"protocol": "udp", "address": address, "success": false, "confirmed": false, "error": err.Error()})
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	_, writeErr := connection.Write([]byte("IPW-UDP-PROBE\n"))
	if writeErr != nil {
		c.JSON(http.StatusOK, gin.H{"protocol": "udp", "address": address, "success": false, "confirmed": false, "duration": float64(time.Since(start).Microseconds()) / 1000, "error": writeErr.Error()})
		return
	}
	buffer := make([]byte, 256)
	read, readErr := connection.Read(buffer)
	result := gin.H{"protocol": "udp", "address": address, "success": true, "confirmed": readErr == nil, "duration": float64(time.Since(start).Microseconds()) / 1000, "bytes_written": 14}
	if readErr == nil {
		result["bytes_read"] = read
	} else {
		result["note"] = "UDP write completed; the target did not return an echo response"
	}
	c.JSON(http.StatusOK, result)
}

type traceProbeRequest struct {
	Host    string `json:"host"`
	MaxHops int    `json:"max_hops"`
}

type traceHop struct {
	Hop        int     `json:"hop"`
	Address    string  `json:"address,omitempty"`
	RTT        float64 `json:"rtt_ms,omitempty"`
	TimedOut   bool    `json:"timed_out"`
	Annotation string  `json:"annotation,omitempty"`
}

var traceHopLinePattern = regexp.MustCompile(`^\s*(\d+)\s+(.+?)\s*$`)

func parseTracerouteOutput(output string) []traceHop {
	hops := make([]traceHop, 0, defaultTraceHops)
	for _, line := range strings.Split(output, "\n") {
		match := traceHopLinePattern.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		hopNumber, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		fields := strings.Fields(match[2])
		if len(fields) == 0 {
			continue
		}
		hop := traceHop{Hop: hopNumber}
		if fields[0] == "*" {
			hop.TimedOut = true
			hops = append(hops, hop)
			continue
		}
		hop.Address = fields[0]
		for index := 1; index < len(fields); index++ {
			candidate := strings.TrimSuffix(fields[index], "ms")
			if value, parseErr := strconv.ParseFloat(candidate, 64); parseErr == nil {
				hop.RTT = value
				break
			}
		}
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "!") {
				hop.Annotation = field
				break
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

func tracerouteHandler(c *gin.Context) {
	if !requireNodeKey(c) {
		return
	}
	var input traceProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	host := strings.TrimSpace(input.Host)
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host is required"})
		return
	}
	ips, err := resolvePublicIPs(host)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	maxHops := input.MaxHops
	if maxHops < 5 || maxHops > 20 {
		maxHops = defaultTraceHops
	}
	binary, err := exec.LookPath("traceroute")
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "traceroute is unavailable on this node"})
		return
	}
	targetIP := ips[0]
	family := "-4"
	if targetIP.To4() == nil {
		family = "-6"
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(maxHops+4)*time.Second)
	defer cancel()
	start := time.Now()
	command := exec.CommandContext(ctx, binary, family, "-n", "-m", strconv.Itoa(maxHops), "-q", "1", "-w", "1", targetIP.String())
	output, commandErr := command.CombinedOutput()
	hops := parseTracerouteOutput(string(output))
	if len(hops) == 0 && commandErr != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = commandErr.Error()
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": message})
		return
	}
	reached := false
	for _, hop := range hops {
		if hopIP := net.ParseIP(hop.Address); hopIP != nil && hopIP.Equal(targetIP) {
			reached = true
			break
		}
	}
	result := gin.H{
		"target":      host,
		"resolved_ip": targetIP.String(),
		"max_hops":    maxHops,
		"hop_count":   len(hops),
		"reached":     reached,
		"duration":    float64(time.Since(start).Microseconds()) / 1000,
		"hops":        hops,
	}
	if ctx.Err() == context.DeadlineExceeded {
		result["note"] = "trace reached the node time limit"
	} else if commandErr != nil {
		result["note"] = "trace ended before the destination responded"
	}
	c.JSON(http.StatusOK, result)
}

type dnsProbeRequest struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Server string `json:"server"`
}

func dnsProbeHandler(c *gin.Context, dnssec bool) {
	if !requireNodeKey(c) {
		return
	}
	var input dnsProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	result, err := webtest.QueryCustomDNS(c.Request.Context(), input.Domain, input.Type, input.Server, dnssec)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func asnHandler(c *gin.Context) {
	if !requireNodeKey(c) {
		return
	}
	var input struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(input.IP))
	if ip == nil || ssrf.IsPrivateIP(ip) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a public IP address is required"})
		return
	}
	asn, organization, err := lookupASN(ip.String())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ip": ip.String(), "asn": asn, "organization": organization})
}

func lookupASN(ip string) (string, string, error) {
	connection, err := net.DialTimeout("tcp", "whois.cymru.com:43", 5*time.Second)
	if err != nil {
		return "", "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(connection, " -v %s\r\n", ip); err != nil {
		return "", "", err
	}
	data, err := io.ReadAll(io.LimitReader(connection, 16*1024))
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "AS ") || strings.HasPrefix(line, "AS|") || strings.HasPrefix(line, "Bulk mode") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}
		asn := strings.TrimSpace(parts[0])
		organization := strings.TrimSpace(parts[6])
		if asn != "" && organization != "" {
			if !strings.HasPrefix(asn, "AS") {
				asn = "AS" + asn
			}
			return asn, organization, nil
		}
	}
	return "", "", fmt.Errorf("ASN data is unavailable")
}

var whoisServers = map[string]string{
	"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "org": "whois.publicinterestregistry.org",
	"cn": "whois.cnnic.cn", "top": "whois.nic.top", "xyz": "whois.nic.xyz", "shop": "whois.nic.shop",
	"io": "whois.nic.io", "co": "whois.nic.co", "me": "whois.nic.me", "dev": "whois.nic.google",
	"app": "whois.nic.google", "biz": "whois.nic.biz", "cc": "whois.nic.cc", "tv": "whois.nic.tv",
}

var validDomain = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type whoisDetails struct {
	Registrar       string   `json:"registrar,omitempty"`
	Registrant      string   `json:"registrant,omitempty"`
	RegistrantEmail string   `json:"registrant_email,omitempty"`
	Created         string   `json:"created,omitempty"`
	Updated         string   `json:"updated,omitempty"`
	Expires         string   `json:"expires,omitempty"`
	ROID            string   `json:"roid,omitempty"`
	DNSSEC          string   `json:"dnssec,omitempty"`
	Statuses        []string `json:"statuses"`
	NameServers     []string `json:"nameservers"`
}

func parseWhoisDetails(raw string) whoisDetails {
	fields := make(map[string][]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		separator := strings.Index(line, ":")
		separatorWidth := 1
		if separator < 0 {
			separator = strings.Index(line, "：")
			separatorWidth = len("：")
		}
		if separator <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:separator]))
		value := strings.TrimSpace(line[separator+separatorWidth:])
		if key != "" && value != "" {
			fields[key] = append(fields[key], value)
		}
	}
	values := func(keys ...string) []string {
		result := make([]string, 0)
		seen := make(map[string]struct{})
		for _, key := range keys {
			for _, value := range fields[strings.ToLower(key)] {
				normalized := strings.ToLower(strings.TrimSpace(value))
				if _, ok := seen[normalized]; ok {
					continue
				}
				seen[normalized] = struct{}{}
				result = append(result, strings.TrimSpace(value))
			}
		}
		return result
	}
	first := func(keys ...string) string {
		matched := values(keys...)
		if len(matched) == 0 {
			return ""
		}
		return matched[0]
	}
	return whoisDetails{
		Registrar:       first("registrar", "sponsoring registrar", "注册商"),
		Registrant:      first("registrant", "registrant name", "注册人"),
		RegistrantEmail: first("registrant contact email", "registrant email", "注册人邮箱"),
		Created:         first("creation date", "created on", "registered on", "registration time", "registration date", "created date", "注册时间"),
		Updated:         first("updated date", "last updated on", "updated on", "last updated date", "modification date", "更新时间"),
		Expires:         first("registry expiry date", "expiration date", "registrar registration expiration date", "expiry date", "expiration time", "expiry time", "renewal date", "paid-till", "到期时间"),
		ROID:            first("roid"),
		DNSSEC:          first("dnssec"),
		Statuses:        values("domain status", "status", "域名状态"),
		NameServers:     values("name server", "nserver", "名称服务器"),
	}
}

// localCheckWrapper 包装 GET+路径参数的 handler 为 POST+JSON，用于公共节点代理。
// 接受 {"domain":"x"} 或 {"ip":"x"} 或 {"url":"x"} 或 {"target":"x"}，
// 注入为路径参数后委派给原 handler。batch 直接透传 body。
func localCheckWrapper(c *gin.Context, paramKey string, targetHandler func(*gin.Context)) {
	if !requireNodeKey(c) {
		return
	}
	var body map[string]interface{}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}
	val := ""
	for _, k := range []string{paramKey, "target"} {
		if v, ok := body[k].(string); ok && strings.TrimSpace(v) != "" {
			val = strings.TrimSpace(v)
			break
		}
	}
	if val == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": paramKey + " is required"})
		return
	}
	c.Params = append(c.Params, gin.Param{Key: paramKey, Value: val})
	targetHandler(c)
}

func whoisHandler(c *gin.Context) {
	if !requireNodeKey(c) {
		return
	}
	var input struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input.Domain), "."))
	if !validDomain.MatchString(domain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain"})
		return
	}
	labels := strings.Split(domain, ".")
	server, ok := whoisServers[labels[len(labels)-1]]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this TLD is not supported"})
		return
	}
	result, err := queryWhois(server, domain)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domain": domain, "server": server, "raw": result, "parsed": parseWhoisDetails(result)})
}

func queryWhois(server, domain string) (string, error) {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), 8*time.Second)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := fmt.Fprintf(connection, "%s\r\n", domain); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(connection, 128*1024))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func registerNodeAPIRoutes(r *gin.Engine) {
	if err := initKeyStore(); err != nil {
		panic(err)
	}
	register := func(prefix string) {
		admin := r.Group(prefix+"/admin", limitNodeBody(maxHTTPBody))
		admin.GET("/keys", listKeysHandler)
		admin.POST("/keys", createKeyHandler)
		admin.DELETE("/keys/:id", revokeKeyHandler)
		protected := r.Group(prefix, limitNodeBody(maxHTTPBody))
		protected.POST("/http-test", httpProbeHandler)
		protected.POST("/tcp-test", tcpProbeHandler)
		protected.POST("/udp-test", udpProbeHandler)
		protected.POST("/traceroute", tracerouteHandler)
		protected.POST("/dns-query", func(c *gin.Context) { dnsProbeHandler(c, false) })
		protected.POST("/dnssec-query", func(c *gin.Context) { dnsProbeHandler(c, true) })
		protected.POST("/asn", asnHandler)
		protected.POST("/whois", whoisHandler)
		protected.POST("/email-security", func(c *gin.Context) { localCheckWrapper(c, "domain", emailSecurityHandler) })
		protected.POST("/rbl", func(c *gin.Context) { localCheckWrapper(c, "ip", rblCheckHandler) })
		protected.POST("/cdn", func(c *gin.Context) { localCheckWrapper(c, "url", cdnDetectHandler) })
		protected.POST("/security-headers", func(c *gin.Context) { localCheckWrapper(c, "url", securityHeadersHandler) })
	}
	// /api is the browser reverse-proxy prefix on the main site. Direct node
	// access and the Hong Kong node use /v1, so both forms are supported.
	register("/v1")
	register("/api/v1")
}
