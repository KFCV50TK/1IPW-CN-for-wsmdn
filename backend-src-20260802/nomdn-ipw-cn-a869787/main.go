package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"lemon-ipw/ipdb"
	"lemon-ipw/ssrf"
	"lemon-ipw/webtest"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/viper"
	"golang.org/x/sync/singleflight"
	"resty.dev/v3"
)

func initHTTPClients() {
	setTransport := func(network string) *http.Transport {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				if ssrf.Enabled() {
					host, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					ip, err := selectTargetIP(ctx, host, network)
					if err != nil {
						return nil, err
					}
					addr = net.JoinHostPort(ip.String(), port)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	V6Client = resty.New()
	V4Client = resty.New()
	V6Client.SetTransport(setTransport("tcp6"))
	V4Client.SetTransport(setTransport("tcp4"))
	V6Client.SetTimeout(10 * time.Second)
	V4Client.SetTimeout(10 * time.Second)
	// Cap upstream response bodies (e.g. 8 MiB) so a malicious public server
	// cannot make the service buffer unlimited data (memory DoS).
	V6Client.SetResponseBodyLimit(maxUpstreamBody)
	V4Client.SetResponseBodyLimit(maxUpstreamBody)
	V6Client.SetRedirectPolicy(resty.RedirectPolicyFunc(ssrf.SecureCheckRedirect))
	V4Client.SetRedirectPolicy(resty.RedirectPolicyFunc(ssrf.SecureCheckRedirect))
	V6Client.AddContentDecompresser("zstd", decompressZstd)
	V4Client.AddContentDecompresser("zstd", decompressZstd)

}

func fakePerfectWebsiteResult(host string) *WebsiteCheckDetail {
	cleanHost := strings.TrimPrefix(host, "https://")
	cleanHost = strings.TrimPrefix(cleanHost, "http://")
	return &WebsiteCheckDetail{
		HostRecord:       cleanHost,
		HTTPStatusCode:   200,
		HTTPSSStatusCode: 200,
		DNSLookupTime:    0.5,
		TCPConnectTime:   1.0,
		HTTPConnectTime:  1.5,
		FirstByteTime:    2.0,
		TotalTime:        100,
		PageSize:         52428,
		DownloadSpeed:    512.0,
		IsReachable:      true,
	}
}

// selectTargetIP selects an address that has already passed SSRF validation.
// Falling back to the webtest resolver is only needed for redirects or callers
// that did not provide a validated request context.
func selectTargetIP(ctx context.Context, host string, network string) (net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ssrf.IsPrivateIP(ip) {
			return nil, fmt.Errorf("request to private/internal address is not allowed")
		}
		if network == "tcp4" && ip.To4() == nil {
			return nil, fmt.Errorf("no IPv4 address found for %s", host)
		}
		if network == "tcp6" && ip.To4() != nil {
			return nil, fmt.Errorf("no IPv6 address found for %s", host)
		}
		return ip, nil
	}

	if target, ok := ctx.Value(ssrf.ValidatedIPsKey()).(ssrf.ValidatedTarget); ok && strings.EqualFold(strings.TrimSuffix(host, "."), target.Host) {
		for _, ip := range target.IPs {
			if ssrf.IsPrivateIP(ip) {
				return nil, fmt.Errorf("request to private/internal address is not allowed")
			}
			if network == "tcp4" && ip.To4() != nil {
				return ip, nil
			}
			if network == "tcp6" && ip.To4() == nil && ip.To16() != nil {
				return ip, nil
			}
		}
	}

	var result webtest.DNSResult
	var err error
	if network == "tcp4" {
		result, err = webtest.ResolveARecord(host)
	} else {
		result, err = webtest.ResolveAAAARecord(host)
	}
	if err != nil {
		return nil, err
	}
	for _, ipText := range result.Record {
		ip := net.ParseIP(ipText)
		if ip == nil {
			continue
		}
		if ssrf.IsPrivateIP(ip) {
			return nil, fmt.Errorf("request to private/internal address is not allowed")
		}
		return ip, nil
	}
	return nil, fmt.Errorf("no %s address found for %s", network, host)
}

func fakeInvalidSSLResult(host string) *SSLCheckDetail {
	return &SSLCheckDetail{
		CertValidityDays:   0,
		IsExpired:          true,
		CertStartTime:      time.Time{},
		CertEndTime:        time.Time{},
		HTTPVersion:        "",
		HostRecord:         host,
		HTTPSSStatusCode:   0,
		TotalTime:          0,
		DownloadSpeed:      0,
		Domain:             host,
		IssuerOrganization: []string{},
		IssuerCommonName:   "Invalid Certificate",
		SubjectCommonName:  host,
		IsReachable:        false,
	}
}

// Create Zstandard decompress logic
// 创建 Zstandard 解压缩逻辑
var zstdReaderPool = sync.Pool{
	New: func() interface{} {
		// 当池子空了，创建一个新的解码器
		decoder, _ := zstd.NewReader(nil)
		return decoder
	},
}

func decompressZstd(r io.ReadCloser) (io.ReadCloser, error) {
	zr := zstdReaderPool.Get().(*zstd.Decoder)
	if err := zr.Reset(r); err != nil {
		zr.Close()
		var newErr error
		zr, newErr = zstd.NewReader(r)
		if newErr != nil {
			return nil, newErr
		}
	}
	return &zstdReader{s: r, r: zr}, nil
}

type zstdReader struct {
	s         io.ReadCloser
	r         *zstd.Decoder
	closeOnce sync.Once
	closeErr  error
}

func (b *zstdReader) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}

func (b *zstdReader) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.s.Close()
		if err := b.r.Reset(nil); err != nil {
			b.r.Close()
			if b.closeErr == nil {
				b.closeErr = err
			}
		} else {
			zstdReaderPool.Put(b.r)
		}
	})
	return b.closeErr
}
func cleanHostRecord(addr string) string {
	if strings.HasPrefix(addr, "[") {
		rightBracket := strings.Index(addr, "]")
		if rightBracket != -1 {
			return addr[1:rightBracket]
		}
	}

	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		colonCount := strings.Count(addr, ":")
		if colonCount > 1 {
			return addr[:idx]
		}
		if colonCount == 1 {
			return addr[:idx]
		}
	}

	return addr
}

// normalizeURL normalizes the input URL by ensuring it has a scheme (http or https).
// normalizeURL 通过确保输入 URL 具有方案（http 或 https）来规范化输入 URL。
func normalizeURL(input string) string {
	input = strings.TrimSpace(input)
	// Remove a wildcard route separator before repairing a proxy-collapsed
	// scheme such as "/https:/example.com".
	if strings.HasPrefix(input, "/") && !strings.HasPrefix(input, "//") {
		input = strings.TrimPrefix(input, "/")
	}
	// Some proxies collapse the second slash in a legacy wildcard URL.
	// Restore the scheme before parsing so "https:/example.com" does not
	// become a hostname named "https".
	if strings.HasPrefix(input, "https:/") && !strings.HasPrefix(input, "https://") {
		input = "https://" + strings.TrimPrefix(input, "https:/")
	}
	if strings.HasPrefix(input, "http:/") && !strings.HasPrefix(input, "http://") {
		input = "http://" + strings.TrimPrefix(input, "http:/")
	}
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return input
	}
	if strings.HasPrefix(input, "//") {
		return "https:" + input
	}
	return "https://" + input
}

// parseURL parses the input string into a URL object after normalizing it.
// parseURL 在规范化输入字符串后，将其解析为 URL 对象。

func parseURL(input string) (*url.URL, error) {
	input = normalizeURL(input)
	parsed, err := url.Parse(input)
	if err != nil {
		return nil, err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid URL: expected http or https URL with a hostname")
	}
	return parsed, nil
}

// decodePathValue handles values sent through Gin wildcard routes. Depending
// on the reverse proxy, the value may be decoded once before reaching Gin or
// remain percent-encoded. Decode at most twice to support both cases without
// turning arbitrary input into an unbounded decode loop.
func decodePathValue(input string) (string, error) {
	input = strings.TrimSpace(input)
	for i := 0; i < 2 && strings.Contains(input, "%"); i++ {
		decoded, err := url.PathUnescape(input)
		if err != nil {
			return "", err
		}
		if decoded == input {
			break
		}
		input = decoded
	}
	return input, nil
}

func requestURL(c *gin.Context, queryKey string, pathKey string) (*url.URL, error) {
	raw := c.Query(queryKey)
	if raw == "" {
		raw = c.Param(pathKey)
		decoded, err := decodePathValue(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid URL encoding: %w", err)
		}
		raw = decoded
	}
	return parseURL(raw)
}

func requestDomain(c *gin.Context) (string, error) {
	raw := c.Query("domain")
	if raw == "" {
		raw = c.Param("domain")
		decoded, err := decodePathValue(raw)
		if err != nil {
			return "", fmt.Errorf("invalid domain encoding: %w", err)
		}
		raw = decoded
	}
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(strings.Trim(raw, "[]")); ip != nil {
		return ip.String(), nil
	}
	parsed, err := parseURL(raw)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(parsed.Hostname(), "."), nil
}

// Setting struct represents the configuration settings for the application, including port, GitHub proxy, and single-stack mode.
// Setting 结构体表示应用程序的配置设置，包括端口、GitHub 代理和单栈模式。
type Setting struct {
	Port         any    `json:"port"`
	GHProxy      string `json:"gh-proxy"`
	SINGLE_STACK string `json:"single-stack"`
}

func (s *Setting) PortString() string {
	switch v := s.Port.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return ""
	}
}

// Global variables and structs
// 全局变量与结构体
var (
	PORTS          string
	BIND_ADDRESS   string
	GH_PROXY       string
	LOG_LEVEL      string
	SINGLE_STACK   string
	DNS_SERVER     string
	sfGroup        singleflight.Group
	V6Client       *resty.Client
	V4Client       *resty.Client
	IPDB           string
	CORS           string
	ACCEPT_DOMAINS []string
)

type WebsiteCheckResult struct {
	IPv4 *WebsiteCheckDetail `json:"ipv4"`
	IPv6 *WebsiteCheckDetail `json:"ipv6"`
}

type WebsiteCheckDetail struct {
	HostRecord       string  `json:"host_record"`
	HTTPStatusCode   int     `json:"http_status_code"`
	HTTPSSStatusCode int     `json:"https_status_code"`
	DNSLookupTime    float64 `json:"dns_lookup_time"`
	TCPConnectTime   float64 `json:"tcp_connect_time"`
	HTTPConnectTime  float64 `json:"http_connect_time"`
	FirstByteTime    float64 `json:"first_byte_time"`
	TotalTime        float64 `json:"total_time"`
	PageSize         int64   `json:"page_size"`
	DownloadSpeed    float64 `json:"download_speed"`
	IsReachable      bool    `json:"is_reachable"`
}

type SSLCheckDetail struct {
	CertValidityDays    int       `json:"cert_validity_days"`
	CertStartTime       time.Time `json:"cert_start_time"`
	CertEndTime         time.Time `json:"cert_end_time"`
	HTTPVersion         string    `json:"http_version"`
	HostRecord          string    `json:"host_record"`
	HTTPSSStatusCode    int       `json:"https_status_code"`
	TotalTime           float64   `json:"total_time"`
	DownloadSpeed       float64   `json:"download_speed"`
	Domain              string    `json:"domain"`
	IssuerOrganization  []string  `json:"issuer_organization"`
	IssuerCommonName    string    `json:"issuer_common_name"`
	SubjectCommonName   string    `json:"subject_common_name"`
	IsExpired           bool      `json:"is_expired"`
	IsReachable         bool      `json:"is_reachable"`
	CertValidated       bool      `json:"certificate_validated,omitempty"`
	CertValidationError string    `json:"certificate_validation_error,omitempty"`
}

type SSLCheckResult struct {
	IPv4 *SSLCheckDetail `json:"ipv4"`
	IPv6 *SSLCheckDetail `json:"ipv6"`
}
type TCPingResult struct {
	IPv4 *webtest.TCPingStats `json:"ipv4"`
	IPv6 *webtest.TCPingStats `json:"ipv6"`
}
type WebsiteSpeedTestResult struct {
	Version          string  `json:"version"`
	HostRecord       string  `json:"host_record"`
	HTTPStatusCode   int     `json:"http_status_code"`
	HTTPSSStatusCode int     `json:"https_status_code"`
	DNSLookupTime    float64 `json:"dns_lookup_time"`
	TCPConnectTime   float64 `json:"tcp_connect_time"`
	HTTPConnectTime  float64 `json:"http_connect_time"`
	FirstByteTime    float64 `json:"first_byte_time"`
	TotalTime        float64 `json:"total_time"`
	PageSize         int64   `json:"page_size"`
	DownloadSpeed    float64 `json:"download_speed"`
	Message          string  `json:"message"`
	Headers          string  `json:"headers"`
	IsReachable      bool    `json:"is_reachable"`
}

// Business Endpoints
// 业务端点

func checkWebsite(url string, version string) (*WebsiteCheckDetail, error) {
	ctx := context.Background()
	var err error
	ctx, err = ssrf.ValidateOutboundTarget(ctx, url)
	if err != nil {
		return nil, err
	}

	client := V4Client
	if version == "v6" {
		client = V6Client
	}

	startTime := time.Now()
	resp, err := client.R().EnableTrace().SetContext(ctx).Get(url)

	// HTTPS 请求失败时 fallback 到 HTTP
	fallbackToHTTP := false
	if err != nil && strings.HasPrefix(url, "https://") {
		httpURL := strings.Replace(url, "https://", "http://", 1)
		startTime = time.Now()
		resp, err = client.R().EnableTrace().SetContext(ctx).Get(httpURL)
		fallbackToHTTP = true
	}

	if err != nil {
		return nil, err
	}
	endTime := time.Now()

	body := resp.Bytes()
	trace := resp.Request.TraceInfo()

	hostRecord := cleanHostRecord(trace.RemoteAddr)

	dnsLookupTime := trace.DNSLookup.Seconds() * 1000
	if dnsLookupTime == 0 {
		dnsLookupTime = measureDNSTime(url, version)
	}
	tcpConnectTime := trace.TCPConnTime.Seconds() * 1000
	httpConnectTime := trace.ConnTime.Seconds() * 1000
	firstByteTime := trace.ServerTime.Seconds() * 1000

	totalTime := float64(endTime.Sub(startTime).Milliseconds())
	var downloadSpeed float64
	if totalTime > 0 {
		downloadSpeed = float64(len(body)) / 1024.0 / (totalTime / 1000.0)
	}

	httpStatus := resp.StatusCode()
	httpsStatus := resp.StatusCode()
	if fallbackToHTTP {
		httpsStatus = 0
	}

	result := &WebsiteCheckDetail{
		HostRecord:       hostRecord,
		HTTPStatusCode:   httpStatus,
		HTTPSSStatusCode: httpsStatus,
		DNSLookupTime:    dnsLookupTime,
		TCPConnectTime:   tcpConnectTime,
		HTTPConnectTime:  httpConnectTime,
		FirstByteTime:    firstByteTime,
		TotalTime:        totalTime,
		PageSize:         int64(len(body)),
		DownloadSpeed:    downloadSpeed,
		IsReachable:      true,
	}

	return result, nil
}

func measureDNSTime(urlStr string, version string) float64 {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return 0
	}
	host := parsed.Hostname()
	if host == "" {
		return 0
	}
	start := time.Now()
	var dnsErr error
	if version == "v6" {
		_, dnsErr = webtest.ResolveAAAARecord(host)
	} else {
		_, dnsErr = webtest.ResolveARecord(host)
	}
	if dnsErr != nil {
		return 0
	}
	return time.Since(start).Seconds() * 1000
}

func websiteSpeed(url string, version string) (*WebsiteSpeedTestResult, error) {
	ctx := context.Background()
	var err error
	ctx, err = ssrf.ValidateOutboundTarget(ctx, url)
	if err != nil {
		return nil, err
	}

	client := V4Client
	if version == "v6" {
		client = V6Client
	}

	startTime := time.Now()
	resp, err := client.R().EnableTrace().SetContext(ctx).Get(url)

	fallbackToHTTP := false
	if err != nil && strings.HasPrefix(url, "https://") {
		httpURL := strings.Replace(url, "https://", "http://", 1)
		startTime = time.Now()
		resp, err = client.R().EnableTrace().SetContext(ctx).Get(httpURL)
		fallbackToHTTP = true
	}

	if err != nil {
		return nil, err
	}
	endTime := time.Now()

	body := resp.Bytes()
	trace := resp.Request.TraceInfo()

	hostRecord := cleanHostRecord(trace.RemoteAddr)

	dnsLookupTime := trace.DNSLookup.Seconds() * 1000
	if dnsLookupTime == 0 {
		dnsLookupTime = measureDNSTime(url, version)
	}
	tcpConnectTime := trace.TCPConnTime.Seconds() * 1000
	httpConnectTime := trace.ConnTime.Seconds() * 1000
	firstByteTime := trace.ServerTime.Seconds() * 1000

	totalTime := float64(endTime.Sub(startTime).Milliseconds())
	var downloadSpeed float64
	if totalTime > 0 {
		downloadSpeed = float64(len(body)) / 1024.0 / (totalTime / 1000.0)
	}
	dumpBytes, _ := httputil.DumpResponse(resp.RawResponse, false)
	httpStatus := resp.StatusCode()
	httpsStatus := resp.StatusCode()
	if fallbackToHTTP {
		httpsStatus = 0
	}
	result := &WebsiteSpeedTestResult{
		Version:          version,
		Headers:          string(dumpBytes),
		HostRecord:       hostRecord,
		HTTPStatusCode:   httpStatus,
		HTTPSSStatusCode: httpsStatus,
		DNSLookupTime:    dnsLookupTime,
		TCPConnectTime:   tcpConnectTime,
		HTTPConnectTime:  httpConnectTime,
		FirstByteTime:    firstByteTime,
		TotalTime:        totalTime,
		PageSize:         int64(len(body)),
		DownloadSpeed:    downloadSpeed,
		IsReachable:      true,
	}

	return result, nil
}

func checkSSL(targetURL string, version string) (*SSLCheckDetail, error) {
	ctx := context.Background()
	var err error
	ctx, err = ssrf.ValidateOutboundTarget(ctx, targetURL)
	if err != nil {
		return nil, err
	}

	client := V4Client
	if version == "v6" {
		client = V6Client
	}

	startTime := time.Now()
	resp, err := client.R().EnableTrace().SetContext(ctx).SetDoNotParseResponse(true).Get(targetURL)
	if err != nil {
		return nil, err
	}
	endTime := time.Now()
	if resp.RawResponse != nil {
		defer resp.RawResponse.Body.Close()
	}

	trace := resp.Request.TraceInfo()
	hostRecord := cleanHostRecord(trace.RemoteAddr)

	totalTime := float64(endTime.Sub(startTime).Milliseconds())

	// Do not download the response body for an SSL check; use Content-Length
	// (when present) only for the speed estimate.
	var pageSize int64
	if contentLength := resp.Header().Get("Content-Length"); contentLength != "" {
		pageSize, _ = strconv.ParseInt(contentLength, 10, 64)
	}
	var downloadSpeed float64
	if totalTime > 0 && pageSize > 0 {
		downloadSpeed = float64(pageSize) / 1024.0 / (totalTime / 1000.0)
	}

	rawResp := resp.RawResponse
	var cert *x509.Certificate
	var remainingDays int
	var isExpired bool
	var issuerOrganization []string
	var issuerCommonName, subjectCommonName, domain string

	if rawResp.TLS != nil && len(rawResp.TLS.PeerCertificates) > 0 {
		cert = rawResp.TLS.PeerCertificates[0]
		now := time.Now()
		remainingDays = int(cert.NotAfter.Sub(now).Hours() / 24)
		isExpired = now.After(cert.NotAfter) || now.Before(cert.NotBefore)
		issuerOrganization = cert.Issuer.Organization
		issuerCommonName = cert.Issuer.CommonName
		subjectCommonName = cert.Subject.CommonName
		domain = cleanHostRecord(cert.Subject.CommonName)
	} else {
		return nil, fmt.Errorf("no SSL certificate found")
	}

	// Actually validate the certificate chain and hostname against the system
	// trust store, so self-signed/expired/mismatched certificates are reported
	// honestly instead of being marked reachable-and-valid.
	certValidated := false
	var certValidationError string
	parsedURL, parseErr := url.Parse(targetURL)
	hostname := ""
	if parseErr == nil {
		hostname = parsedURL.Hostname()
	}
	if cert != nil && hostname != "" {
		intermediates := x509.NewCertPool()
		for _, intermediate := range rawResp.TLS.PeerCertificates[1:] {
			intermediates.AddCert(intermediate)
		}
		if _, verifyErr := cert.Verify(x509.VerifyOptions{
			DNSName:       hostname,
			Intermediates: intermediates,
			Roots:         systemCertPool(),
		}); verifyErr != nil {
			certValidationError = verifyErr.Error()
		} else {
			certValidated = true
		}
	}

	result := &SSLCheckDetail{
		CertValidityDays:    remainingDays,
		IsExpired:           isExpired,
		CertStartTime:       cert.NotBefore,
		CertEndTime:         cert.NotAfter,
		HTTPVersion:         resp.Proto(),
		HostRecord:          hostRecord,
		HTTPSSStatusCode:    resp.StatusCode(),
		TotalTime:           totalTime,
		DownloadSpeed:       downloadSpeed,
		Domain:              domain,
		IssuerOrganization:  issuerOrganization,
		IssuerCommonName:    issuerCommonName,
		SubjectCommonName:   subjectCommonName,
		IsReachable:         true,
		CertValidated:       certValidated,
		CertValidationError: certValidationError,
	}

	return result, nil
}

func checkWebsiteHandler(c *gin.Context) {
	parsedURL, err := requestURL(c, "url", "url")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	testUrl := parsedURL.String()
	if ssrf.HasLocalOrPrivateIP(parsedURL.Hostname()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "private or internal addresses are not allowed"})
		return
	}

	if cached, ok := websiteCache.Get(testUrl); ok {
		c.JSON(200, cached)
		return
	}

	rawResult, _, _ := sfGroup.Do("website:"+testUrl, func() (interface{}, error) {
		result := &WebsiteCheckResult{}
		switch SINGLE_STACK {
		case "ipv4":
			ipv4, errV4 := checkWebsite(testUrl, "v4")
			if errV4 != nil {
				ipv4 = &WebsiteCheckDetail{
					HostRecord:  "Error: " + errV4.Error(),
					IsReachable: false,
				}
			}
			result.IPv4 = ipv4
			result.IPv6 = &WebsiteCheckDetail{
				HostRecord:  "Skipped due to SINGLE_STACK=ipv4",
				IsReachable: false,
			}
		case "ipv6":
			ipv6, errV6 := checkWebsite(testUrl, "v6")
			if errV6 != nil {
				ipv6 = &WebsiteCheckDetail{
					HostRecord:  "Error: " + errV6.Error(),
					IsReachable: false,
				}
			}
			result.IPv6 = ipv6
			result.IPv4 = &WebsiteCheckDetail{
				HostRecord:  "Skipped due to SINGLE_STACK=ipv6",
				IsReachable: false,
			}
		default:
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				ipv6, errV6 := checkWebsite(testUrl, "v6")
				if errV6 != nil {
					ipv6 = &WebsiteCheckDetail{
						HostRecord:  "Error: " + errV6.Error(),
						IsReachable: false,
					}
				}
				result.IPv6 = ipv6
			}()

			go func() {
				defer wg.Done()
				ipv4, errV4 := checkWebsite(testUrl, "v4")
				if errV4 != nil {
					ipv4 = &WebsiteCheckDetail{
						HostRecord:  "Error: " + errV4.Error(),
						IsReachable: false,
					}
				}
				result.IPv4 = ipv4
			}()

			wg.Wait()
		}

		websiteCache.Set(testUrl, result)

		if (result.IPv4 != nil && !result.IPv4.IsReachable) || (result.IPv6 != nil && !result.IPv6.IsReachable) {
			go func() {
				time.Sleep(30 * time.Second)
				websiteCache.Delete(testUrl)
			}()
		}

		return result, nil
	})

	c.JSON(200, rawResult.(*WebsiteCheckResult))
}
func websiteSpeedTestHandler(c *gin.Context) {
	parsedURL, err := requestURL(c, "url", "url")
	version := c.Param("version")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	url := parsedURL.String()

	// 检查请求版本是否与 SINGLE_STACK 配置匹配
	switch SINGLE_STACK {
	case "ipv4":
		if version != "v4" {
			c.JSON(http.StatusBadRequest, &WebsiteSpeedTestResult{
				Version:    "v4",
				HostRecord: "Skipped due to SINGLE_STACK=ipv4",
			})
			return
		}
	case "ipv6":
		if version != "v6" {
			c.JSON(http.StatusBadRequest, &WebsiteSpeedTestResult{
				Version:    "v6",
				HostRecord: "Skipped due to SINGLE_STACK=ipv6",
			})
			return
		}
	}

	// 缓存键：URL + 版本
	cacheKey := fmt.Sprintf("%s:%s", url, version)

	// 检查缓存
	if cached, ok := speedCache.Get(cacheKey); ok {
		c.JSON(200, cached)
		return
	}

	var result *WebsiteSpeedTestResult

	switch version {
	case "v6", "v4":
		rawResult, _, _ := sfGroup.Do(cacheKey, func() (interface{}, error) {
			r, e := websiteSpeed(url, version)
			if e != nil {
				errorResult := &WebsiteSpeedTestResult{
					HostRecord: "Error: " + e.Error(),
				}
				speedCache.Set(cacheKey, errorResult)
				go func() {
					time.Sleep(30 * time.Second)
					speedCache.Delete(cacheKey)
				}()
				return errorResult, nil
			}
			speedCache.Set(cacheKey, r)
			return r, nil
		})
		result = rawResult.(*WebsiteSpeedTestResult)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid version",
		})
		return
	}

	c.JSON(200, result)
}

func websiteSpeedRouteHandler(c *gin.Context) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("IPW_SPEED_API_KEY_REQUIRED")), "true") {
		if !requireNodeKey(c) {
			return
		}
	}
	websiteSpeedTestHandler(c)
}

func sslCheckHandler(c *gin.Context) {
	parsedURL, err := requestURL(c, "url", "url")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	testUrl := parsedURL.String()
	if ssrf.HasLocalOrPrivateIP(parsedURL.Hostname()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "private or internal addresses are not allowed"})
		return
	}

	if cached, ok := sslCache.Get(testUrl); ok {
		c.JSON(200, cached)
		return
	}

	rawResult, _, _ := sfGroup.Do("ssl:"+testUrl, func() (interface{}, error) {
		result := &SSLCheckResult{}
		switch SINGLE_STACK {
		case "ipv4":
			ipv4, errV4 := checkSSL(testUrl, "v4")
			if errV4 != nil {
				ipv4 = &SSLCheckDetail{
					HostRecord:  "Error: " + errV4.Error(),
					IsExpired:   true,
					IsReachable: false,
				}
			}
			result.IPv4 = ipv4
			result.IPv6 = &SSLCheckDetail{
				HostRecord:  "Skipped due to SINGLE_STACK=ipv4",
				IsExpired:   true,
				IsReachable: false,
			}
		case "ipv6":
			ipv6, errV6 := checkSSL(testUrl, "v6")
			if errV6 != nil {
				ipv6 = &SSLCheckDetail{
					HostRecord:  "Error: " + errV6.Error(),
					IsExpired:   true,
					IsReachable: false,
				}
			}
			result.IPv6 = ipv6
			result.IPv4 = &SSLCheckDetail{
				HostRecord:  "Skipped due to SINGLE_STACK=ipv6",
				IsExpired:   true,
				IsReachable: false,
			}
		default:
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				ipv6, errV6 := checkSSL(testUrl, "v6")
				if errV6 != nil {
					ipv6 = &SSLCheckDetail{
						HostRecord:  "Error: " + errV6.Error(),
						IsExpired:   true,
						IsReachable: false,
					}
				}
				result.IPv6 = ipv6
			}()

			go func() {
				defer wg.Done()
				ipv4, errV4 := checkSSL(testUrl, "v4")
				if errV4 != nil {
					ipv4 = &SSLCheckDetail{
						HostRecord:  "Error: " + errV4.Error(),
						IsExpired:   true,
						IsReachable: false,
					}
				}
				result.IPv4 = ipv4
			}()

			wg.Wait()
		}

		sslCache.Set(testUrl, result)

		if (result.IPv4 != nil && !result.IPv4.IsReachable) || (result.IPv6 != nil && !result.IPv6.IsReachable) {
			go func() {
				time.Sleep(30 * time.Second)
				sslCache.Delete(testUrl)
			}()
		}

		return result, nil
	})

	c.JSON(200, rawResult.(*SSLCheckResult))
}

func locateIP(c *gin.Context) {
	ip := c.Param("ip")
	slog.Debug("Locating IP", "ip", ip)
	c.JSON(http.StatusOK, ipdb.SearchIP(ip))
}
func locateUserIP(c *gin.Context) {
	ip := c.ClientIP()
	// 可能会有误报，因为某些环境下 ClientIP() 可能返回代理服务器的 IP 地址，而不是用户的真实 IP 地址
	slog.Debug("Locating user IP", "ip", ip)
	c.JSON(http.StatusOK, ipdb.SearchIP(ip))
}

func curlIPHandler(c *gin.Context) {
	// Nginx passes the verified client address through X-Forwarded-For.
	// The backend is loopback-only in production, so Gin's ClientIP is safe here.
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(c.ClientIP()+"\n"))
}

func dnsQueryHandler(c *gin.Context) {
	domain, err := requestDomain(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	recodeType := c.Param("type")
	switch recodeType {
	case "a":
		result, err := webtest.ResolveARecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "aaaa":
		result, err := webtest.ResolveAAAARecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "cname":
		result, err := webtest.ResolveCNAMERecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "mx":
		result, err := webtest.ResolveMXRecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "ns":
		result, err := webtest.ResolveNSRecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "ptr":
		result, err := webtest.ResolvePTRRecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "srv":
		result, err := webtest.ResolveSRVRecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "txt":
		result, err := webtest.ResolveTXTRecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	case "caa":
		result, err := webtest.ResolveCAARecord(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, result)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid record type",
		})
		return
	}
}
func pingHandler(c *gin.Context) {
	host := c.Param("ip")
	port := c.Query("port")
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "IP or hostname parameter is required",
		})
		return
	}
	if port == "" {
		port = "80"
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid port number",
		})
		return
	}

	count := 4
	if countStr := c.Query("count"); countStr != "" {
		n, err := strconv.Atoi(countStr)
		if err != nil || n < 1 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "count must be a positive integer",
			})
			return
		}
		// Cap per-request attempts so a single request cannot tie up the
		// service for minutes.
		if n > 4 {
			n = 4
		}
		count = n
	}

	// Per-IP rate limit and global concurrency guard keep TCPing from being
	// abused as an unauthenticated port scanner / resource hog.
	if !allowTcping(c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many tcping requests; please try again shortly"})
		return
	}
	select {
	case pingSem <- struct{}{}:
		defer func() { <-pingSem }()
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tcping service is busy; please try again"})
		return
	}

	cacheKey := fmt.Sprintf("%s:%s:%d", host, port, count)
	if cached, ok := pingCache.Get(cacheKey); ok {
		c.JSON(200, cached)
		return
	}

	rawResult, _, _ := sfGroup.Do(cacheKey, func() (interface{}, error) {
		result := &TCPingResult{}

		switch SINGLE_STACK {
		case "ipv4":
			ipv4, errV4 := webtest.TCPingRun(c.Request.Context(), host, port, count, "v4", 3*time.Second, 100*time.Millisecond)
			if errV4 != nil {
				ipv4 = &webtest.TCPingStats{
					IP: "Error: " + errV4.Error(),
				}
			}
			result.IPv4 = ipv4
			result.IPv6 = &webtest.TCPingStats{
				IP: "Skipped due to SINGLE_STACK=ipv4",
			}
		case "ipv6":
			ipv6, errV6 := webtest.TCPingRun(c.Request.Context(), host, port, count, "v6", 3*time.Second, 100*time.Millisecond)
			if errV6 != nil {
				ipv6 = &webtest.TCPingStats{
					IP: "Error: " + errV6.Error(),
				}
			}
			result.IPv6 = ipv6
			result.IPv4 = &webtest.TCPingStats{
				IP: "Skipped due to SINGLE_STACK=ipv6",
			}
		default:
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				ipv6, errV6 := webtest.TCPingRun(c.Request.Context(), host, port, count, "v6", 3*time.Second, 100*time.Millisecond)
				if errV6 != nil {
					ipv6 = &webtest.TCPingStats{
						IP: "Error: " + errV6.Error(),
					}
				}
				result.IPv6 = ipv6
			}()

			go func() {
				defer wg.Done()
				ipv4, errV4 := webtest.TCPingRun(c.Request.Context(), host, port, count, "v4", 3*time.Second, 100*time.Millisecond)
				if errV4 != nil {
					ipv4 = &webtest.TCPingStats{
						IP: "Error: " + errV4.Error(),
					}
				}
				result.IPv4 = ipv4
			}()

			wg.Wait()
		}

		pingCache.Set(cacheKey, result)

		ipv4Failed := result.IPv4 != nil && strings.HasPrefix(result.IPv4.IP, "Error:")
		ipv6Failed := result.IPv6 != nil && strings.HasPrefix(result.IPv6.IP, "Error:")
		if ipv4Failed && ipv6Failed {
			go func() {
				time.Sleep(30 * time.Second)
				pingCache.Delete(cacheKey)
			}()
		}

		return result, nil
	})

	c.JSON(200, rawResult.(*TCPingResult))
}

func healchCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

// speedtestUploadHandler receives and discards an uploaded payload so the
// browser can measure real user-to-node upload speed.
func speedtestUploadHandler(c *gin.Context) {
	const maxUpload = 512 << 20 // 512 MiB
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpload)
	start := time.Now()
	received, err := io.Copy(io.Discard, c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "upload failed"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"received": received, "elapsed_ms": time.Since(start).Milliseconds()})
}

// speedtestPayloadHandler streams a fixed-size, non-compressible payload so
// browsers can measure real user-to-node download speed (speedtest style).
func speedtestPayloadHandler(c *gin.Context) {
	size := int64(20 << 20) // 20 MiB default
	if raw := strings.TrimSpace(c.Query("bytes")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1<<20 || parsed > 512<<20 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bytes must be between 1 MiB and 512 MiB"})
			return
		}
		size = parsed
	}
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(size, 10))
	c.Header("Cache-Control", "no-store")
	// Deterministic pseudo-random data: not compressible, so proxies cannot
	// inflate the measured speed.
	rng := rand.New(rand.NewSource(0x1d37))
	buffer := make([]byte, 128*1024)
	written := int64(0)
	for written < size {
		chunk := len(buffer)
		if remaining := size - written; int64(chunk) > remaining {
			chunk = int(remaining)
		}
		if _, err := rng.Read(buffer[:chunk]); err != nil {
			break
		}
		n, err := c.Writer.Write(buffer[:chunk])
		if err != nil {
			break
		}
		written += int64(n)
	}
}
func readConfig() {
	PORTS = os.Getenv("PORTS")
	BIND_ADDRESS = strings.TrimSpace(os.Getenv("BIND_ADDRESS"))
	GH_PROXY = os.Getenv("GH_PROXY")
	// SINGLE_STACK can be "ipv4", "ipv6", or empty for both.
	// Empty string is a valid value meaning dual-stack, not "unconfigured".
	// 如果当前测速节点机器是单栈网络，建议设置 SINGLE_STACK 环境变量来跳过另一个协议的测试，以避免不必要的错误日志和延迟
	SINGLE_STACK = strings.ToLower(strings.TrimSpace(os.Getenv("SINGLE_STACK")))
	DNS_SERVER = os.Getenv("DNS_SERVER")
	IPDB = os.Getenv("IPDB")
	CORS = os.Getenv("CORS")
	ssrf.SetEnabled(os.Getenv("BLOCK_PRIVATE_IPS") != "false" && os.Getenv("BLOCK_PRIVATE_IPS") != "0")

	// SINGLE_STACK is intentionally excluded: empty string is a valid value (dual-stack).

	viper.SetConfigName("setting")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("Failed to read config file, using defaults", "error", err)
	}
	if PORTS == "" {
		PORTS = viper.GetString("port")
	}
	if GH_PROXY == "" {
		GH_PROXY = viper.GetString("gh-proxy")
	}
	if SINGLE_STACK == "" {
		SINGLE_STACK = strings.ToLower(strings.TrimSpace(viper.GetString("single-stack")))
	}
	if DNS_SERVER == "" {
		DNS_SERVER = viper.GetString("dns-server")
	}
	if IPDB == "" {
		IPDB = viper.GetString("ipdb")
	}
	if CORS == "" {
		CORS = viper.GetString("cors")
	}
	if PORTS == "" {
		PORTS = "8080"
	}
	if CORS != "" {
		for _, origin := range strings.Split(CORS, ",") {
			if origin = strings.TrimSpace(origin); origin != "" {
				ACCEPT_DOMAINS = append(ACCEPT_DOMAINS, origin)
			}
		}
	}
	if BIND_ADDRESS == "" {
		BIND_ADDRESS = "0.0.0.0"
	}
	slog.Info("SSRF protection initialized", "blockPrivateIPs", ssrf.Enabled())
}

func main() {
	readConfig()
	webtest.SetDNSServer(DNS_SERVER)
	ssrf.SetDNSServer(DNS_SERVER)
	initHTTPClients()
	if IPDB != "false" {
		ipdb.Init(GH_PROXY)
	}
	slog.Info("Starting server", "port", PORTS, "gh_proxy", GH_PROXY, "single_stack", SINGLE_STACK, "dns_server", DNS_SERVER)

	r := gin.Default()
	if len(ACCEPT_DOMAINS) > 0 {
		r.Use(cors.New(cors.Config{
			AllowOrigins:  ACCEPT_DOMAINS,
			AllowMethods:  []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions},
			AllowHeaders:  []string{"Origin", "Content-Type", "Accept", "Authorization", "X-API-Key", "X-IPW-Admin-Token"},
			ExposeHeaders: []string{"Content-Length"},
			MaxAge:        12 * time.Hour,
		}))
	} else {
		r.Use(cors.Default())
	}
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("IPW_NODE_API_ENABLED")), "false") {
		registerNodeAPIRoutes(r)
	}
	registerPublicQueryRoutes(r)

	r.GET("/v1/detail/*url", checkWebsiteHandler)
	r.GET("/v1/detail", checkWebsiteHandler)
	r.GET("/v1/ssl/*url", sslCheckHandler)
	r.GET("/v1/ssl", sslCheckHandler)

	r.GET("/v1/tcping/:ip", pingHandler)
	r.GET("/v1/dns/:type/*domain", dnsQueryHandler)
	r.GET("/v1/speed/:version/*url", websiteSpeedRouteHandler)
	r.GET("/v1/speed/:version", websiteSpeedRouteHandler)

	r.GET("/", healchCheck)
	r.GET("/v1/speedtest-payload", speedtestPayloadHandler)
	r.POST("/v1/speedtest-upload", speedtestUploadHandler)
	r.GET("/v1/curl", curlIPHandler)
	if IPDB != "false" {
		r.GET("/v1/location/:ip", locateIP)
		r.GET("/v1/location", locateUserIP)

		// extra feature routes
		r.GET("/v1/email-security/:domain", emailSecurityHandler)
		r.GET("/v1/rbl/:ip", rblCheckHandler)
		r.GET("/v1/cdn/*url", cdnDetectHandler)
		r.POST("/v1/batch-location", batchLocationHandler)
		r.GET("/v1/security-headers/*url", securityHeadersHandler)
		r.GET("/v1/ct-logs/:domain", ctLogHandler)
	}
	server := &http.Server{
		Addr:              net.JoinHostPort(BIND_ADDRESS, PORTS),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       180 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Server failed to start", "error", err)
	}
}
