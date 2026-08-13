package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	maxPublicQueryBody     = 8 * 1024
	maxPublicQueryResponse = 256 * 1024
	publicQueryTimeout     = 25 * time.Second
)

var publicProbePaths = map[string]string{
	"http":     "/v1/http-test",
	"tcp":      "/v1/tcp-test",
	"udp":      "/v1/udp-test",
	"trace":    "/v1/traceroute",
	"speed":    "/v1/speed",
	"dns":      "/v1/dns-query",
	"dnssec":   "/v1/dnssec-query",
	"asn":      "/v1/asn",
	"whois":    "/v1/whois",
	"email":    "/v1/email-security",
	"rbl":      "/v1/rbl",
	"cdn":      "/v1/cdn",
	"security": "/v1/security-headers",
}

func publicQueryString(input map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		value, ok := input[key]
		if !ok {
			continue
		}
		var parsed string
		if json.Unmarshal(value, &parsed) == nil && strings.TrimSpace(parsed) != "" {
			return strings.TrimSpace(parsed)
		}
	}
	return ""
}

func publicSpeedVersion(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "4", "v4", "ipv4":
		return "v4", nil
	case "6", "v6", "ipv6":
		return "v6", nil
	default:
		return "", fmt.Errorf("speed version must be v4 or v6")
	}
}

// publicSpeedRequestURL converts the public POST contract into the legacy GET
// route exposed by Lemon IPW RC7.1 speed nodes. Keeping the translation here
// lets existing nodes remain on the upstream route without browser-side calls.
func publicSpeedRequestURL(nodeURL *url.URL, input map[string]json.RawMessage) (string, error) {
	target := publicQueryString(input, "target", "url", "host")
	if target == "" {
		return "", fmt.Errorf("target is required")
	}
	version, err := publicSpeedVersion(publicQueryString(input, "version", "stack"))
	if err != nil {
		return "", err
	}
	normalized := target
	if !strings.Contains(normalized, "://") {
		normalized = "https://" + normalized
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("target must be a valid website host or URL")
	}
	host := strings.TrimSpace(parsed.Host)
	if host == "" {
		return "", fmt.Errorf("target must be a valid website host or URL")
	}
	return strings.TrimRight(nodeURL.String(), "/") + "/v1/speed/" + version + "/" + url.PathEscape(host), nil
}

type publicQueryNode struct {
	ID    string
	Label string
	URL   *url.URL
	Key   string
}

type publicRateEntry struct {
	window time.Time
	count  int
}

type publicQueryProxy struct {
	nodes       map[string]publicQueryNode
	client      *http.Client
	rateLimit   int
	concurrency chan struct{}
	mu          sync.Mutex
	rates       map[string]publicRateEntry
}

func publicClientIP(c *gin.Context) string {
	// Do not trust the X-IPW-Client-IP header from clients: it can be forged to
	// bypass rate limiting. Nginx already sets trusted forwarding headers and
	// Gin's ClientIP resolves the real client through configured proxies.
	return c.ClientIP()
}

func publicNodeFromEnv(id, label, envPrefix string) (publicQueryNode, bool) {
	rawURL := strings.TrimSpace(os.Getenv(envPrefix + "_URL"))
	key := strings.TrimSpace(os.Getenv(envPrefix + "_KEY"))
	if rawURL == "" || key == "" {
		return publicQueryNode{}, false
	}
	parsed, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return publicQueryNode{}, false
	}
	return publicQueryNode{ID: id, Label: label, URL: parsed, Key: key}, true
}

func newPublicQueryProxy() *publicQueryProxy {
	nodes := make(map[string]publicQueryNode)
	configured := []struct {
		id, label, env string
	}{
		{"zaozhuang", "中国 山东 枣庄 移动/电信双线", "IPW_PUBLIC_NODE_ZAOZHUANG"},
		{"hongkong", "中国 香港 Cogent", "IPW_PUBLIC_NODE_HONGKONG"},
		{"xian2", "中国 陕西 西安二 电信", "IPW_PUBLIC_NODE_XIAN2"},
		{"shiyan", "中国 湖北 十堰 电信", "IPW_PUBLIC_NODE_SHIYAN"},
		{"hongkong2", "中国 香港 VpsQuan", "IPW_PUBLIC_NODE_HONGKONG2"},
		{"jdcloud", "中国 北京 京东云 三网BGP", "IPW_PUBLIC_NODE_JDCLOUD"},
		{"huawei", "中国 华为云 北京", "IPW_PUBLIC_NODE_HUAWEI"},
	}
	for _, item := range configured {
		if node, ok := publicNodeFromEnv(item.id, item.label, item.env); ok {
			nodes[item.id] = node
		}
	}
	rateLimit := 30
	if parsed, err := strconv.Atoi(strings.TrimSpace(os.Getenv("IPW_PUBLIC_RATE_LIMIT"))); err == nil && parsed >= 5 && parsed <= 120 {
		rateLimit = parsed
	}
	return &publicQueryProxy{
		nodes: nodes,
		client: &http.Client{
			Timeout: publicQueryTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		rateLimit:   rateLimit,
		concurrency: make(chan struct{}, 24),
		rates:       make(map[string]publicRateEntry),
	}
}

func (proxy *publicQueryProxy) allow(identity string) (bool, int) {
	now := time.Now()
	window := now.Truncate(time.Minute)
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	entry := proxy.rates[identity]
	if !entry.window.Equal(window) {
		entry = publicRateEntry{window: window}
	}
	if entry.count >= proxy.rateLimit {
		return false, int(time.Until(window.Add(time.Minute)).Seconds()) + 1
	}
	entry.count++
	proxy.rates[identity] = entry
	if len(proxy.rates) > 4096 {
		for key, value := range proxy.rates {
			if value.window.Before(window) {
				delete(proxy.rates, key)
			}
		}
	}
	return true, 0
}

func (proxy *publicQueryProxy) listNodes(c *gin.Context) {
	type nodeView struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	result := make([]nodeView, 0, len(proxy.nodes))
	for _, node := range proxy.nodes {
		result = append(result, nodeView{ID: node.ID, Label: node.Label})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	c.Header("Cache-Control", "public, max-age=60")
	c.JSON(http.StatusOK, gin.H{"nodes": result})
}

func (proxy *publicQueryProxy) run(c *gin.Context) {
	node, ok := proxy.nodes[strings.ToLower(strings.TrimSpace(c.Param("node")))]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "query node is unavailable"})
		return
	}
	probe := strings.ToLower(strings.TrimSpace(c.Param("probe")))
	upstreamPath, ok := publicProbePaths[probe]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "query type is unavailable"})
		return
	}
	allowed, retryAfter := proxy.allow(publicClientIP(c))
	if !allowed {
		c.Header("Retry-After", strconv.Itoa(retryAfter))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many queries; please try again shortly"})
		return
	}
	select {
	case proxy.concurrency <- struct{}{}:
		defer func() { <-proxy.concurrency }()
	default:
		c.Header("Retry-After", "2")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "query service is busy; please try again"})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPublicQueryBody)
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "query payload is too large"})
		return
	}
	var input map[string]json.RawMessage
	if len(bytes.TrimSpace(body)) == 0 || json.Unmarshal(body, &input) != nil || input == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	requestMethod := http.MethodPost
	requestBody := io.Reader(bytes.NewReader(body))
	requestURL := strings.TrimRight(node.URL.String(), "/") + upstreamPath
	if probe == "speed" {
		requestURL, err = publicSpeedRequestURL(node.URL, input)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		requestMethod = http.MethodGet
		requestBody = nil
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), publicQueryTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, requestMethod, requestURL, requestBody)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not create node request"})
		return
	}
	request.Header.Set("Accept", "application/json")
	if requestMethod != http.MethodGet {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+node.Key)
	response, err := proxy.client.Do(request)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("%s node is temporarily unavailable", node.Label)})
		return
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxPublicQueryResponse+1))
	if err != nil || len(responseBody) > maxPublicQueryResponse {
		c.JSON(http.StatusBadGateway, gin.H{"error": "node response is invalid or too large"})
		return
	}
	var responseJSON json.RawMessage
	if len(responseBody) == 0 || json.Unmarshal(responseBody, &responseJSON) != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "node returned an invalid response"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(response.StatusCode, "application/json; charset=utf-8", responseBody)
}

func registerPublicQueryRoutes(r *gin.Engine) {
	proxy := newPublicQueryProxy()
	if len(proxy.nodes) == 0 {
		return
	}
	register := func(prefix string) {
		group := r.Group(prefix)
		group.GET("/nodes", proxy.listNodes)
		group.POST("/:node/:probe", proxy.run)
	}
	register("/v1/public-query")
	register("/api/v1/public-query")
}
