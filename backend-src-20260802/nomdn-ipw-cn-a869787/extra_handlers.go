package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"lemon-ipw/ipdb"
	"lemon-ipw/ssrf"
)

// ============ 1. 邮件安全检测 (SPF/DKIM/DMARC) ============
type EmailSecurityResult struct {
	Domain string               `json:"domain"`
	SPF    *EmailSecurityRecord `json:"spf"`
	DKIM   *EmailSecurityRecord `json:"dkim"`
	DMARC  *EmailSecurityRecord `json:"dmarc"`
	Score  int                  `json:"score"`
	Status string               `json:"status"` // "secure", "partial", "vulnerable"
}

type EmailSecurityRecord struct {
	Found   bool     `json:"found"`
	Record  string   `json:"record,omitempty"`
	Status  string   `json:"status"` // "pass", "fail", "warning"
	Details []string `json:"details,omitempty"`
}

func emailSecurityHandler(c *gin.Context) {
	domain := strings.TrimSpace(c.Param("domain"))
	if domain == "" {
		c.JSON(400, gin.H{"error": "域名不能为空"})
		return
	}

	if ssrf.HasLocalOrPrivateIP(domain) {
		c.JSON(200, EmailSecurityResult{
			Domain: domain,
			Status: "blocked",
			Score:  0,
		})
		return
	}

	result := EmailSecurityResult{
		Domain: domain,
		Score:  0,
	}

	spf := checkSPF(domain)
	result.SPF = spf
	if spf.Found && spf.Status == "pass" {
		result.Score += 40
	}

	dmarc := checkDMARC(domain)
	result.DMARC = dmarc
	if dmarc.Found && dmarc.Status == "pass" {
		result.Score += 30
	}

	result.DKIM = &EmailSecurityRecord{
		Found:   false,
		Status:  "unknown",
		Details: []string{"DKIM 需要知道具体 selector 才能查询，常见如 default._domainkey"},
	}

	if result.Score >= 70 {
		result.Status = "secure"
	} else if result.Score >= 40 {
		result.Status = "partial"
	} else {
		result.Status = "vulnerable"
	}

	c.JSON(200, result)
}

func checkSPF(domain string) *EmailSecurityRecord {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return &EmailSecurityRecord{Found: false, Status: "fail", Details: []string{"无法查询 TXT 记录"}}
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			details := []string{}
			if strings.Contains(txt, "~all") {
				details = append(details, "使用 softfail (~all)")
			} else if strings.Contains(txt, "-all") {
				details = append(details, "使用 hardfail (-all)，安全性较高")
			} else if strings.Contains(txt, "+all") {
				details = append(details, "⚠️ 使用 +all，允许任何服务器发送")
			}

			status := "pass"
			if strings.Contains(txt, "+all") {
				status = "warning"
			}

			return &EmailSecurityRecord{
				Found:   true,
				Record:  txt,
				Status:  status,
				Details: details,
			}
		}
	}

	return &EmailSecurityRecord{Found: false, Status: "fail", Details: []string{"未找到 SPF 记录"}}
}

func checkDMARC(domain string) *EmailSecurityRecord {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return &EmailSecurityRecord{Found: false, Status: "fail", Details: []string{"未找到 DMARC 记录"}}
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			details := []string{}
			if strings.Contains(txt, "p=none") {
				details = append(details, "策略为 none，仅监控")
			} else if strings.Contains(txt, "p=quarantine") {
				details = append(details, "策略为 quarantine，可能隔离未授权邮件")
			} else if strings.Contains(txt, "p=reject") {
				details = append(details, "策略为 reject，拒绝未授权邮件")
			}

			status := "pass"
			if strings.Contains(txt, "p=none") {
				status = "warning"
			}

			return &EmailSecurityRecord{
				Found:   true,
				Record:  txt,
				Status:  status,
				Details: details,
			}
		}
	}

	return &EmailSecurityRecord{Found: false, Status: "fail", Details: []string{"未找到 DMARC 记录"}}
}

// ============ 2. IP黑名单查询 (RBL/DNSBL) ============
type RBLResult struct {
	IP        string      `json:"ip"`
	Blacklist []RBLRecord `json:"blacklist"`
	Status    string      `json:"status"` // "clean", "listed"
}

type RBLRecord struct {
	RBL    string `json:"rbl"`
	Listed bool   `json:"listed"`
	Reason string `json:"reason,omitempty"`
}

var rblProviders = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"dnsbl.sorbs.net",
	"cbl.abuseat.org",
}

// rblCheckHandler 查 5 个 DNSBL。并发查询 —— 原先串行时每个
// 失败域名要等满解析超时，最坏 5×10s；并发放到一次往返内。
func rblCheckHandler(c *gin.Context) {
	ipStr := strings.TrimSpace(c.Param("ip"))
	if ipStr == "" {
		c.JSON(400, gin.H{"error": "IP不能为空"})
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		c.JSON(400, gin.H{"error": "无效的IP地址"})
		return
	}

	reversed := reverseIP(ip.String())
	if reversed == "" {
		c.JSON(400, gin.H{"error": "仅支持IPv4查询"})
		return
	}

	result := RBLResult{
		IP:        ipStr,
		Blacklist: make([]RBLRecord, len(rblProviders)),
		Status:    "clean",
	}

	var wg sync.WaitGroup
	for i, rbl := range rblProviders {
		wg.Add(1)
		go func(i int, rbl string) {
			defer wg.Done()
			query := reversed + "." + rbl
			listed, reason := checkRBL(c.Request.Context(), query)
			result.Blacklist[i] = RBLRecord{
				RBL:    rbl,
				Listed: listed,
				Reason: reason,
			}
		}(i, rbl)
	}
	wg.Wait()
	for _, record := range result.Blacklist {
		if record.Listed {
			result.Status = "listed"
			break
		}
	}

	c.JSON(200, result)
}

func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

func checkRBL(ctx context.Context, query string) (bool, string) {
	var r net.Resolver
	ips, err := r.LookupIPAddr(ctx, query)
	if err != nil || len(ips) == 0 {
		return false, ""
	}
	return true, "Listed in RBL"
}

// ============ 3. CDN识别 ============
type CDNResult struct {
	URL      string   `json:"url"`
	CDN      string   `json:"cdn"`
	Provider string   `json:"provider"`
	IPs      []string `json:"ips"`
	CNAME    []string `json:"cname"`
}

type cdnSignature struct {
	name     string
	cname    []string
	ipPrefix []string
}

// cname 特征均来自实测 DNS 解析结果，勿凭印象增删。
// 参考实测（2026-08-08）：
//
//	www.qq.com        -> ins-r23tsuuf.ias.tencent-cloud.net   EdgeOne
//	www.tencent.com   -> www.tencent.com.eo.dnse5.com          EdgeOne
//	edgeone.ai        -> edgeone.ai.eo.dnse5.com               EdgeOne
//	cloud.tencent.com -> cloud.tencent-cloud.com               腾讯云
//	www.taobao.com    -> www.taobao.com.danuoyi.tbcache.com    阿里云
//	www.alibaba.com   -> www.alibaba.com.gds.alibabadns.com    阿里云
//	www.bilibili.com  -> a.w.bilicdn1.com                      哔哩哔哩
//	www.jd.com        -> www.jd.com.gslb.qianxun.com           京东云
//	www.akamai.com    -> www.akamai.com.edgekey.net            Akamai
//	www.fastly.com    -> prod.www-fastly-com.map.fastly.net    Fastly
var cdnSignatures = []cdnSignature{
	// EdgeOne 放在腾讯云之前：.ias.tencent-cloud.net 属于 EdgeOne 接入，
	// 若先匹配通用的 tencent-cloud 会被误判成普通腾讯云。
	{name: "腾讯云 EdgeOne", cname: []string{
		".eo.dnse", ".eo-cdn.com", ".ias.tencent-cloud.net", ".eo.tencentcs.com",
	}},
	{name: "腾讯云 ESA", cname: []string{".esa-cdn.com", ".esa.tencentcs.com"}},
	{name: "腾讯云 CDN", cname: []string{
		".tencent-cloud.com", ".tencent-cloud.net", ".cdntip.com", ".dnsv1.com", ".tencentcs.com",
	}},
	{name: "阿里云", cname: []string{
		".kunlun", ".alikunlun.com", ".alicdn.com", ".alidns.com",
		".danuoyi.tbcache.com", ".tbcache.com", ".alibabadns.com", ".aliyuncs.com",
	}},
	{name: "Cloudflare", cname: []string{"cloudflare"}, ipPrefix: []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}},
	{name: "Akamai", cname: []string{"akamai", ".edgesuite.net", ".edgekey.net", ".akadns.net"}},
	{name: "Amazon CloudFront", cname: []string{".cloudfront.net"}},
	{name: "Fastly", cname: []string{".fastly.net", ".fastlylb.net"}},
	{name: "华为云", cname: []string{".cdnhwc", ".hwcdn.net"}},
	// shifen.com 是百度自家调度域名，非对外 CDN，故标注为"百度"而不是"百度云 CDN"。
	{name: "百度", cname: []string{".bdydns.com", ".jomodns.com", ".shifen.com"}},
	{name: "京东云", cname: []string{".jcloud", ".galaxy-cdn", ".qianxun.com"}},
	{name: "网宿 ChinaNetCenter", cname: []string{".wscdns.com", ".wsdvs.com", ".wsssec.com"}},
	{name: "哔哩哔哩", cname: []string{".bilicdn", ".hdslb.com"}},
	{name: "字节跳动", cname: []string{".volcgslb", ".bytefcdn", ".byteedge"}},
	{name: "Azure CDN", cname: []string{".azureedge.net", ".azurefd.net", ".trafficmanager.net"}},
	{name: "Google Cloud CDN", cname: []string{".googleusercontent.com", ".ghs.googlehosted.com"}},
	{name: "Imperva Incapsula", cname: []string{".incapdns.net"}},
	{name: "又拍云", cname: []string{".aicdn.com", ".upaiyun.com"}},
	{name: "七牛云", cname: []string{".qbox.me", ".qiniudns.com", ".clouddn.com"}},
	{name: "CDN77", cname: []string{".cdn77.net", ".cdn77.org"}},
	{name: "KeyCDN", cname: []string{".kxcdn.com"}},
	{name: "BunnyCDN", cname: []string{".b-cdn.net"}},
	{name: "Sucuri", cname: []string{".sucuri.net"}},
	{name: "StackPath", cname: []string{".stackpathdns.com", ".netdna-cdn.com"}},
}

func matchCDNByCNAME(cnameStr string) string {
	lower := strings.ToLower(cnameStr)
	for _, sig := range cdnSignatures {
		for _, pattern := range sig.cname {
			if strings.Contains(lower, pattern) {
				return sig.name
			}
		}
	}
	return ""
}

func isCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, sig := range cdnSignatures {
		if sig.name == "Cloudflare" {
			for _, cidr := range sig.ipPrefix {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err == nil && ipnet.Contains(parsed) {
					return true
				}
			}
		}
	}
	return false
}

func cdnDetectHandler(c *gin.Context) {
	urlStr := strings.TrimPrefix(c.Param("url"), "/")
	if urlStr == "" {
		c.JSON(400, gin.H{"error": "URL不能为空"})
		return
	}

	host := extractHost(urlStr)
	if host == "" {
		c.JSON(400, gin.H{"error": "无效的URL"})
		return
	}

	if ssrf.HasLocalOrPrivateIP(host) {
		c.JSON(200, CDNResult{URL: urlStr, CDN: "blocked", Provider: "SSRF protection"})
		return
	}

	result := CDNResult{
		URL:   urlStr,
		CDN:   "None",
		IPs:   []string{},
		CNAME: []string{},
	}

	var resolver net.Resolver
	ctx := c.Request.Context()
	cname, _ := resolver.LookupCNAME(ctx, host)
	if cname != "" && cname != host+"." {
		result.CNAME = append(result.CNAME, strings.TrimSuffix(cname, "."))
	}

	addrs, _ := resolver.LookupIPAddr(ctx, host)
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			result.IPs = append(result.IPs, addr.IP.String())
		}
	}

	cnameStr := strings.ToLower(cname)
	cdnName := matchCDNByCNAME(cnameStr)
	if cdnName == "" && len(result.IPs) > 0 && isCloudflareIP(result.IPs[0]) {
		cdnName = "Cloudflare (by IP)"
	}
	if cdnName != "" {
		result.CDN = cdnName
	}

	c.JSON(200, result)
}

func extractHost(urlStr string) string {
	normalized := normalizeURL(strings.TrimSpace(urlStr))
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return parsed.Hostname()
}

// ============ 4. 批量IP查询 ============
type BatchLocationRequest struct {
	IPs []string `json:"ips"`
}

type BatchLocationResult struct {
	Results []map[string]interface{} `json:"results"`
	Total   int                      `json:"total"`
	Success int                      `json:"success"`
}

func batchLocationHandler(c *gin.Context) {
	var req BatchLocationRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "无效的请求格式"})
		return
	}

	if len(req.IPs) == 0 {
		c.JSON(400, gin.H{"error": "IP列表不能为空"})
		return
	}

	if len(req.IPs) > 50 {
		c.JSON(400, gin.H{"error": "单次最多查询50个IP"})
		return
	}

	result := BatchLocationResult{
		Results: []map[string]interface{}{},
		Total:   len(req.IPs),
		Success: 0,
	}

	for _, ipStr := range req.IPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			result.Results = append(result.Results, map[string]interface{}{
				"ip":    ipStr,
				"error": "无效的IP地址",
			})
			continue
		}

		ipInfo := ipdb.SearchIP(c.Request.Context(), ipStr)
		ipInfo["ip"] = ipStr
		result.Results = append(result.Results, ipInfo)
		result.Success++
	}

	c.JSON(200, result)
}

// ============ 5. HTTP安全头检测 ============
type SecurityHeadersResult struct {
	URL     string                `json:"url"`
	Headers map[string]HeaderInfo `json:"headers"`
	Score   int                   `json:"score"`
	Grade   string                `json:"grade"`
}

type HeaderInfo struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Status  string `json:"status"`
	Info    string `json:"info,omitempty"`
}

func securityHeadersHandler(c *gin.Context) {
	urlStr := strings.TrimPrefix(c.Param("url"), "/")
	if urlStr == "" {
		c.JSON(400, gin.H{"error": "URL不能为空"})
		return
	}

	// Some proxies collapse the second slash of a legacy wildcard URL
	// ("https:/example.com"); normalizeURL restores the scheme before parsing.
	urlStr = normalizeURL(urlStr)

	parsed, err := url.Parse(urlStr)
	if err != nil || parsed.Hostname() == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的URL"})
		return
	}

	// Default-deny: resolve and validate the target before connecting. If DNS
	// resolution fails or any address is private/internal, refuse outright.
	ctx, err := ssrf.ValidateOutboundTarget(c.Request.Context(), urlStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "目标地址不允许访问（SSRF 防护）"})
		return
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := selectTargetIP(dialCtx, host, "tcp4")
			if err != nil {
				ip, err = selectTargetIP(dialCtx, host, "tcp6")
			}
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的URL"})
		return
	}
	resp, err := client.Do(request)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("请求失败: %v", err)})
		return
	}
	defer resp.Body.Close()

	result := SecurityHeadersResult{
		URL:     urlStr,
		Headers: make(map[string]HeaderInfo),
		Score:   0,
	}

	securityHeaders := map[string]struct {
		weight int
		info   string
	}{
		"Strict-Transport-Security": {20, "HSTS 强制 HTTPS"},
		"X-Content-Type-Options":    {15, "防止 MIME 类型嗅探"},
		"X-Frame-Options":           {15, "防止点击劫持"},
		"Content-Security-Policy":   {25, "内容安全策略"},
		"X-XSS-Protection":          {10, "XSS 过滤器"},
		"Referrer-Policy":           {10, "引用策略"},
		"Permissions-Policy":        {5, "权限策略"},
	}

	for header, props := range securityHeaders {
		value := resp.Header.Get(header)
		if value != "" {
			result.Headers[header] = HeaderInfo{
				Present: true,
				Value:   value,
				Status:  "pass",
				Info:    props.info,
			}
			result.Score += props.weight
		} else {
			result.Headers[header] = HeaderInfo{
				Present: false,
				Status:  "fail",
				Info:    props.info,
			}
		}
	}

	if result.Score >= 80 {
		result.Grade = "A"
	} else if result.Score >= 60 {
		result.Grade = "B"
	} else if result.Score >= 40 {
		result.Grade = "C"
	} else if result.Score >= 20 {
		result.Grade = "D"
	} else {
		result.Grade = "F"
	}

	c.JSON(200, result)
}

type CTLogResult struct {
	Domain       string      `json:"domain"`
	Certificates []CTLogCert `json:"certificates"`
	Total        int         `json:"total"`
}

type CTLogCert struct {
	Issuer       string `json:"issuer"`
	CommonName   string `json:"common_name"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

func ctLogHandler(c *gin.Context) {
	domain := strings.TrimSpace(c.Param("domain"))
	if domain == "" {
		c.JSON(400, gin.H{"error": "域名不能为空"})
		return
	}

	if ssrf.HasLocalOrPrivateIP(domain) {
		c.JSON(200, CTLogResult{Domain: domain, Certificates: []CTLogCert{}, Total: 0})
		return
	}

	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("查询失败: %v", err)})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		c.JSON(502, gin.H{"error": fmt.Sprintf("crt.sh 返回 %d", resp.StatusCode)})
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		c.JSON(500, gin.H{"error": "读取响应失败"})
		return
	}

	// crt.sh may return empty body on no results
	if len(body) == 0 || string(body) == "null" || string(body) == "[]" {
		c.JSON(200, CTLogResult{Domain: domain, Certificates: []CTLogCert{}, Total: 0})
		return
	}

	var certs []map[string]interface{}
	if err := json.Unmarshal(body, &certs); err != nil {
		// Try to surface partial info for debug
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		c.JSON(500, gin.H{"error": "解析响应失败", "detail": snippet})
		return
	}

	result := CTLogResult{
		Domain:       domain,
		Certificates: []CTLogCert{},
		Total:        len(certs),
	}

	limit := 20
	if len(certs) > limit {
		certs = certs[:limit]
	}

	for _, cert := range certs {
		ctCert := CTLogCert{}

		if issuer, ok := cert["issuer_name"].(string); ok {
			ctCert.Issuer = issuer
		}
		if cn, ok := cert["common_name"].(string); ok {
			ctCert.CommonName = cn
		}
		if nb, ok := cert["not_before"].(string); ok {
			ctCert.NotBefore = nb
		}
		if na, ok := cert["not_after"].(string); ok {
			ctCert.NotAfter = na
		}
		if sn, ok := cert["serial_number"].(string); ok {
			ctCert.SerialNumber = sn
		}

		result.Certificates = append(result.Certificates, ctCert)
	}

	c.JSON(200, result)
}
