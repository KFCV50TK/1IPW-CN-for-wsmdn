package main

// 探测族 API（POST /v1/http-test 等）与节点侧主动测量。
//
// 鉴权（重构后）：RFC 6750 Bearer Token —— Authorization: Bearer <ACCESS_TOKEN>，
// 全后端唯一一把钥匙，查询族（GET /v1/*）与探测族（POST /v1/http-test 等）
// 共用。token 为空则全部开放（上游默认行为，兼容匿名节点）。
//
// 删除的三套自建机制（2026-08-16 重构）：
//   - sk-ipw- key 库（node_keys.json 持久化、SHA-256 hash 校验、吊销）
//   - IPW_ADMIN_TOKEN + /admin/keys 管理端点
//   - X-IPW-Admin-Token 请求头
// 多套并行体系没有带来额外安全 —— 公开侧流量走 public_query 代理（带
// 限流与并发闸），节点与主站之间一把共享 token 已足够，且与上游
// rc7.1 的 ACCESS_TOKEN 约定对齐，前端配置里各节点共用同一 token。

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"lemon-ipw/ssrf"
	"lemon-ipw/webtest"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	maxHTTPBody      = 64 * 1024
	maxHTTPTimeout   = 10 * time.Second
	defaultTraceHops = 18
)

// bearerToken 按 RFC 6750 §2.1 解析 Authorization 头。
// 只认标准 Bearer 方案（大小写不敏感）；非 Bearer 方案返回空。
func bearerToken(c *gin.Context) string {
	value := strings.TrimSpace(c.GetHeader("Authorization"))
	if len(value) > 7 && strings.EqualFold(value[:7], "Bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return ""
}

// secureStringEqual 常数时间字符串比较，防时序侧信道。
// 先各自哈希成等长再比，规避 subtle 包要求等长输入的限制。
func secureStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// requireBearer 是统一鉴权检查：与查询族共用 ACCESS_TOKEN。
// token 未配置（空）时放行 —— 匿名节点的兼容行为。
func requireBearer(c *gin.Context) bool {
	if ACCESS_TOKEN != "" && !secureStringEqual(bearerToken(c), ACCESS_TOKEN) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return false
	}
	return true
}

// requireBearerMiddleware 中间件形态，挂在路由组上。
// OPTIONS 预检直接放行 —— CORS 预检不带凭证，拦了会破坏浏览器跨域。
func requireBearerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		if !requireBearer(c) {
			return
		}
		c.Next()
	}
}

func limitNodeBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

type httpProbeRequest struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Body   string `json:"body"`
}

// validatePublicURL 解析并校验探测目标，返回携带 SSRF 已验证 IP 的
// 派生 context。base 应传请求 context —— 客户端断开时 DNS 解析与
// 后续探测随之取消。
func validatePublicURL(base context.Context, raw string) (*url.URL, context.Context, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, nil, fmt.Errorf("URL must use http or https")
	}
	ips, err := resolvePublicIPs(base, parsed.Hostname())
	if err != nil {
		return nil, nil, err
	}
	ctx := context.WithValue(base, ssrf.ValidatedIPsKey(), ssrf.ValidatedTarget{
		Host: strings.TrimSuffix(strings.ToLower(parsed.Hostname()), "."),
		IPs:  ips,
	})
	return parsed, ctx, nil
}

// resolvePublicIPs 解析主机名为公网 IP 列表；解析结果里有任何一个
// 内网地址就整体拒绝 —— 防止多 A 记录里混一个内网 IP 绕过 SSRF。
func resolvePublicIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ssrf.IsPrivateIP(ip) {
			return nil, fmt.Errorf("private or internal targets are not allowed")
		}
		return []net.IP{ip}, nil
	}
	// 用 resolver 而非包级 LookupIP：继承请求 context 的取消
	var r net.Resolver
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	public := make([]net.IP, 0, len(ips))
	for _, addr := range ips {
		if ssrf.IsPrivateIP(addr.IP) {
			return nil, fmt.Errorf("host resolves to a private or internal address")
		}
		public = append(public, addr.IP)
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("no public address found for %s", host)
	}
	return public, nil
}

func httpProbeHandler(c *gin.Context) {
	if !requireBearer(c) {
		return
	}
	var input httpProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	parsed, ctx, err := validatePublicURL(c.Request.Context(), input.URL)
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

func publicAddress(ctx context.Context, host string, port int) (string, error) {
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
	// 跟请求取消；任一解析结果是内网地址即整体拒绝（同 resolvePublicIPs）
	var r net.Resolver
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ssrf.IsPrivateIP(addr.IP) {
			return "", fmt.Errorf("host resolves to a private or internal address")
		}
	}
	return net.JoinHostPort(addrs[0].IP.String(), strconv.Itoa(port)), nil
}

func socketTimeout(value int) time.Duration {
	if value < 100 || value > 5000 {
		return 3 * time.Second
	}
	return time.Duration(value) * time.Millisecond
}

func tcpProbeHandler(c *gin.Context) {
	if !requireBearer(c) {
		return
	}
	var input socketProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	address, err := publicAddress(c.Request.Context(), input.Host, input.Port)
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
	if !requireBearer(c) {
		return
	}
	var input socketProbeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	address, err := publicAddress(c.Request.Context(), input.Host, input.Port)
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
	if !requireBearer(c) {
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
	ips, err := resolvePublicIPs(c.Request.Context(), host)
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
	if !requireBearer(c) {
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
	if !requireBearer(c) {
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
	if !requireBearer(c) {
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
	if !requireBearer(c) {
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

// registerNodeAPIRoutes 注册探测族路由。鉴权在各 handler 入口的
// requireBearer（统一 ACCESS_TOKEN）；admin key 管理端点已随自建
// 密钥体系删除。
func registerNodeAPIRoutes(r *gin.Engine) {
	register := func(prefix string) {
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
	// /api 是主站对浏览器的反向代理前缀；直连节点与香港节点用 /v1，
	// 两种形态都注册，代理与节点不必同构。
	register("/v1")
	register("/api/v1")
}
