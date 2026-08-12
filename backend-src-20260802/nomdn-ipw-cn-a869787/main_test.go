package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lemon-ipw/ssrf"
)

func TestPublicSpeedRequestURLUsesRC71Route(t *testing.T) {
	nodeURL, err := url.Parse("https://node.example")
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]json.RawMessage{
		"target":  json.RawMessage(`"https://example.com/path?q=1"`),
		"version": json.RawMessage(`"ipv4"`),
	}
	got, err := publicSpeedRequestURL(nodeURL, input)
	if err != nil {
		t.Fatalf("publicSpeedRequestURL returned error: %v", err)
	}
	if want := "https://node.example/v1/speed/v4/example.com"; got != want {
		t.Fatalf("publicSpeedRequestURL = %q, want %q", got, want)
	}
}

func TestPublicSpeedRequestURLSupportsURLAliasAndIPv6(t *testing.T) {
	nodeURL, err := url.Parse("https://node.example/base/")
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]json.RawMessage{
		"url":   json.RawMessage(`"example.net:8443"`),
		"stack": json.RawMessage(`"v6"`),
	}
	got, err := publicSpeedRequestURL(nodeURL, input)
	if err != nil {
		t.Fatalf("publicSpeedRequestURL returned error: %v", err)
	}
	if want := "https://node.example/base/v1/speed/v6/example.net:8443"; got != want {
		t.Fatalf("publicSpeedRequestURL = %q, want %q", got, want)
	}
}

func TestPublicSpeedRequestURLRejectsInvalidVersion(t *testing.T) {
	nodeURL, err := url.Parse("https://node.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = publicSpeedRequestURL(nodeURL, map[string]json.RawMessage{
		"target":  json.RawMessage(`"example.com"`),
		"version": json.RawMessage(`"dual"`),
	})
	if err == nil {
		t.Fatal("expected invalid speed version error")
	}
}

func TestPublicQuerySpeedCallsLegacyNodeRoute(t *testing.T) {
	var gotMethod, gotPath, gotAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gotMethod = request.Method
		gotPath = request.URL.EscapedPath()
		gotAuthorization = request.Header.Get("Authorization")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"version":"v4","is_reachable":true}`))
	}))
	defer upstream.Close()

	nodeURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &publicQueryProxy{
		nodes: map[string]publicQueryNode{
			"test": {ID: "test", Label: "Test node", URL: nodeURL, Key: "node-key"},
		},
		client:      upstream.Client(),
		rateLimit:   30,
		concurrency: make(chan struct{}, 1),
		rates:       make(map[string]publicRateEntry),
	}
	router := gin.New()
	router.POST("/v1/public-query/:node/:probe", proxy.run)
	request := httptest.NewRequest(http.MethodPost, "/v1/public-query/test/speed", strings.NewReader(`{"target":"https://example.com/path","version":"v4"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("public speed status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("node method = %q, want GET", gotMethod)
	}
	if gotPath != "/v1/speed/v4/example.com" {
		t.Fatalf("node path = %q, want RC7.1 speed route", gotPath)
	}
	if gotAuthorization != "Bearer node-key" {
		t.Fatalf("node authorization = %q", gotAuthorization)
	}
}

func TestNewPublicQueryProxyLoadsShiyanNode(t *testing.T) {
	t.Setenv("IPW_PUBLIC_NODE_SHIYAN_URL", "https://shiyan-node.example")
	t.Setenv("IPW_PUBLIC_NODE_SHIYAN_KEY", "shiyan-key")
	proxy := newPublicQueryProxy()
	node, ok := proxy.nodes["shiyan"]
	if !ok {
		t.Fatal("expected shiyan node to be loaded")
	}
	if node.Label != "中国 湖北 十堰 电信" || node.URL.String() != "https://shiyan-node.example" || node.Key != "shiyan-key" {
		t.Fatalf("unexpected shiyan node: %#v", node)
	}
}

func TestNewPublicQueryProxyLoadsHongKongVpsQuanNode(t *testing.T) {
	t.Setenv("IPW_PUBLIC_NODE_HONGKONG2_URL", "https://hongkong2-node.example")
	t.Setenv("IPW_PUBLIC_NODE_HONGKONG2_KEY", "hongkong2-key")
	proxy := newPublicQueryProxy()
	node, ok := proxy.nodes["hongkong2"]
	if !ok {
		t.Fatal("expected hongkong2 node to be loaded")
	}
	if node.Label != "中国 香港 VpsQuan" || node.URL.String() != "https://hongkong2-node.example" || node.Key != "hongkong2-key" {
		t.Fatalf("unexpected hongkong2 node: %#v", node)
	}
}

func TestNewPublicQueryProxyLoadsJDCloudNode(t *testing.T) {
	t.Setenv("IPW_PUBLIC_NODE_JDCLOUD_URL", "https://jdcloud-node.example")
	t.Setenv("IPW_PUBLIC_NODE_JDCLOUD_KEY", "jdcloud-key")
	proxy := newPublicQueryProxy()
	node, ok := proxy.nodes["jdcloud"]
	if !ok {
		t.Fatal("expected jdcloud node to be loaded")
	}
	if node.Label != "中国 北京 京东云 三网BGP" || node.URL.String() != "https://jdcloud-node.example" || node.Key != "jdcloud-key" {
		t.Fatalf("unexpected jdcloud node: %#v", node)
	}
}

func TestWebsiteSpeedRouteCanRequireNodeKey(t *testing.T) {
	t.Setenv("IPW_SPEED_API_KEY_REQUIRED", "true")
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/v1/speed/v4/example.com", nil)
	context.Params = gin.Params{{Key: "version", Value: "v4"}, {Key: "url", Value: "/example.com"}}
	websiteSpeedRouteHandler(context)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("protected speed status = %d, want 401", recorder.Code)
	}
}

func TestRequestURLFromQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest("GET", "/v1/detail?url="+url.QueryEscape("https://example.com/path?check=1"), nil)

	parsed, err := requestURL(context, "url", "url")
	if err != nil {
		t.Fatalf("requestURL returned error: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() != "example.com" || parsed.Path != "/path" {
		t.Fatalf("unexpected parsed URL: %s", parsed.String())
	}
}

func TestRequestURLFromWildcard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Params = gin.Params{{Key: "url", Value: "/https://example.com/path"}}

	parsed, err := requestURL(context, "url", "url")
	if err != nil {
		t.Fatalf("requestURL returned error: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() != "example.com" || parsed.Path != "/path" {
		t.Fatalf("unexpected parsed URL: %s", parsed.String())
	}
}

func TestNormalizeURLAfterProxySlashCollapse(t *testing.T) {
	for _, input := range []string{"https:/example.com/path", "http:/example.com/path"} {
		parsed, err := parseURL(input)
		if err != nil {
			t.Fatalf("parseURL(%q) returned error: %v", input, err)
		}
		if parsed.Hostname() != "example.com" || parsed.Path != "/path" {
			t.Fatalf("unexpected parsed URL for %q: %s", input, parsed.String())
		}
	}
}

func TestParseWhoisDetailsCNNIC(t *testing.T) {
	raw := `Domain Name: baidu.cn
ROID: 20030312s10001s00062053-cn
Domain Status: clientDeleteProhibited
Registrant: 北京百度网讯科技有限公司
Registrant Contact Email: eric@baidu.com
Sponsoring Registrar: 互联网域名系统北京市工程研究中心有限公司
Name Server: ns1.baidu.cn
Name Server: ns2.baidu.cn
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2029-03-17 12:48:36
DNSSEC: unsigned`

	details := parseWhoisDetails(raw)
	if details.Created != "2003-03-17 12:20:05" {
		t.Fatalf("unexpected registration time: %q", details.Created)
	}
	if details.Expires != "2029-03-17 12:48:36" {
		t.Fatalf("unexpected expiration time: %q", details.Expires)
	}
	if details.Registrar == "" || details.Registrant == "" {
		t.Fatalf("missing CNNIC registrar or registrant: %#v", details)
	}
	if len(details.NameServers) != 2 || details.NameServers[0] != "ns1.baidu.cn" {
		t.Fatalf("unexpected name servers: %#v", details.NameServers)
	}
}

func TestParseTracerouteOutput(t *testing.T) {
	hops := parseTracerouteOutput("traceroute to 8.8.8.8, 18 hops max\n 1  192.0.2.1  1.234 ms\n 2  *\n 3  8.8.8.8  9.876 ms\n")
	if len(hops) != 3 {
		t.Fatalf("unexpected hop count: %d", len(hops))
	}
	if hops[0].Hop != 1 || hops[0].Address != "192.0.2.1" || hops[0].RTT != 1.234 {
		t.Fatalf("unexpected first hop: %#v", hops[0])
	}
	if !hops[1].TimedOut {
		t.Fatalf("expected timeout hop: %#v", hops[1])
	}
	if hops[2].Address != "8.8.8.8" || hops[2].RTT != 9.876 {
		t.Fatalf("unexpected destination hop: %#v", hops[2])
	}
}

func TestIsPrivateIPRejectsCGNATAndReservedRanges(t *testing.T) {
	for _, raw := range []string{
		"100.64.0.1", "100.127.255.254", "198.18.0.1", "240.0.0.1",
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1",
		"0.0.0.0", "255.255.255.255", "224.0.0.1", "2001:db8::1", "fe80::1",
		"::1", "fc00::1",
	} {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("failed to parse %q", raw)
		}
		if !ssrf.IsPrivateIP(ip) {
			t.Errorf("expected %q to be treated as private/internal", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "223.5.5.5", "2606:4700:4700::1111"} {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("failed to parse %q", raw)
		}
		if ssrf.IsPrivateIP(ip) {
			t.Errorf("expected %q to be public", raw)
		}
	}
}

func TestSecurityHeadersRejectsPrivateTarget(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, target := range []string{"127.0.0.1:8080", "http://[::1]:80/", "100.64.0.1", "10.0.0.1"} {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		context.Params = gin.Params{{Key: "url", Value: "/" + target}}
		context.Request = httptest.NewRequest(http.MethodGet, "/v1/security-headers/"+target, nil)
		securityHeadersHandler(context)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("securityHeadersHandler(%q) status = %d, want 400", target, recorder.Code)
		}
	}
}
