package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lemon-ipw/webtest"
)

// ==================== 上游兼容的公开 GET 接口 ====================
// 为兼容上游 ipw-cn 的 GET 路由（middleware-go 可无缝转发），
// 以下接口的返回 JSON 结构与上游保持一致：
//   - GET /v1/whois/:domain  -> upstream webtest.WhoisResult
//   - GET /v1/dnssec/:domain -> upstream webtest.DNSSECResult
//   - GET /v1/asn/:ip        -> upstream asnLookupHandler
// 全部零第三方依赖：WHOIS 复用现有 queryWhois + 手写解析。
// 三个接口默认强制鉴权：Bearer TOKEN（IPW_PUBLIC_API_KEY）或节点密钥二选一。

// requirePublicCompatKey 校验上游兼容 GET 接口（whois/dnssec/asn）的访问凭证。
// 任一方式通过即可：
//  1. Authorization: Bearer <TOKEN>，TOKEN 与环境变量 IPW_PUBLIC_API_KEY 一致；
//  2. 回退：节点 API 密钥（sk-ipw-*，经 node_keys.json 校验）。
func requirePublicCompatKey(c *gin.Context) bool {
	expected := strings.TrimSpace(os.Getenv("IPW_PUBLIC_API_KEY"))
	if expected != "" {
		if token := bearerTokenFromAuthorization(c); token != "" && secureStringEqual(token, expected) {
			return true
		}
	}
	return requireNodeKey(c)
}

// publicWhoisResult 与上游 webtest.WhoisResult 的 JSON 结构一致
type publicWhoisResult struct {
	Domain       string               `json:"domain"`
	Status       []string             `json:"status"`
	Registrar    publicWhoisRegistrar `json:"registrar"`
	Registrant   publicWhoisContact   `json:"registrant"`
	Technical    publicWhoisContact   `json:"technical"`
	AbuseContact publicWhoisContact   `json:"abuseContact"`
	Dates        publicWhoisDates     `json:"dates"`
	NameServers  []string             `json:"nameservers"`
	WhoisServer  string               `json:"whoisServer"`
	Raw          string               `json:"raw"`
	Error        string               `json:"error"`
}

type publicWhoisRegistrar struct {
	Name   string `json:"name"`
	IanaId string `json:"ianaId"`
}

type publicWhoisContact struct {
	Name       string `json:"name"`
	Org        string `json:"org"`
	Phone      string `json:"phone"`
	Email      string `json:"email"`
	Province   string `json:"province"`
	ContactUri string `json:"contactUri"`
}

type publicWhoisDates struct {
	Registration string `json:"registration"`
	Expiration   string `json:"expiration"`
	LastChanged  string `json:"lastChanged"`
}

// publicASNWhoisResult 与上游 webtest.ASNWhoisResult 的 JSON 结构一致
type publicASNWhoisResult struct {
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

// publicASNLookupHandler GET /v1/asn/:ip
// 返回格式与上游 asnLookupHandler 一致（geolite2_asn + whois 详情）。
// geolite2_asn 复用下游节点 ASN 接口相同的 lookupASN(whois.cymru.com 反查)；
// whois 为 ARIN WHOIS 的 ASN 详情（零依赖直连解析）；
// 查不到时只返回 {"ip": ...}，不做 error 占位。
func publicASNLookupHandler(c *gin.Context) {
	if !requirePublicCompatKey(c) {
		return
	}
	ip := strings.TrimSpace(c.Param("ip"))
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP parameter is required"})
		return
	}
	asnResult := map[string]interface{}{"ip": ip}

	// 与下游 POST /v1/asn 一致：lookupASN 查 whois.cymru.com，查不到就不输出
	if asn, org, err := lookupASN(ip); err == nil {
		asnResult["geolite2_asn"] = map[string]string{
			"asn": asn,
			"org": org,
		}
		// 与上游一致：附加 ARIN WHOIS 的 ASN 详情（查不到不影响主结果）
		if whoisData, whoisErr := queryASNWhoisCompat(asn); whoisErr == nil {
			asnResult["whois"] = whoisData
		}
	}
	// dbip_asn：下游无 dbip-asn 数据库，按需求省略

	c.JSON(http.StatusOK, asnResult)
}

// asnWhoisConnectTimeout ASN WHOIS 连接与读写超时
const asnWhoisConnectTimeout = 8 * time.Second

// queryASNWhoisCompat 零依赖查询 ARIN WHOIS 获取 ASN 详情，
// 返回格式与上游 webtest.ASNWhoisResult 一致。
func queryASNWhoisCompat(asn string) (*publicASNWhoisResult, error) {
	asn = strings.TrimSpace(asn)
	if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
		asn = "AS" + asn
	}
	result := &publicASNWhoisResult{ASNumber: strings.TrimPrefix(asn, "AS")}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("whois.arin.net", "43"), asnWhoisConnectTimeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(asnWhoisConnectTimeout))

	if _, err := fmt.Fprintf(conn, "%s\r\n", asn); err != nil {
		result.Error = err.Error()
		return result, err
	}

	raw := make([]byte, 0, 4096)
	buffer := make([]byte, 4096)
	for {
		n, readErr := conn.Read(buffer)
		if n > 0 {
			raw = append(raw, buffer[:n]...)
			if len(raw) > 128*1024 {
				raw = raw[:128*1024]
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	result.Raw = string(raw)
	if len(raw) == 0 {
		result.Error = "empty response from ARIN whois"
		return result, fmt.Errorf("empty response from ARIN whois")
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		separator := strings.Index(line, ":")
		if separator <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:separator]))
		value := strings.TrimSpace(line[separator+1:])
		switch key {
		case "asnumber":
			if result.ASNumber == "" {
				result.ASNumber = value
			}
		case "asname":
			result.ASName = value
		case "ashandle":
			if result.ASNumber == "" {
				result.ASNumber = strings.TrimPrefix(value, "AS")
			}
		case "orgname":
			result.OrgName = value
		case "orgid":
			result.OrgID = value
		case "country":
			if len(value) == 2 {
				result.Country = value
			}
		case "regdate":
			result.RegDate = value
		case "updated":
			result.Updated = value
		case "orgabusename":
			result.AbuseName = value
		case "orgabuseemail":
			result.AbuseEmail = value
		case "orgabusephone":
			result.AbusePhone = value
		}
	}
	return result, nil
}

// publicWhoisHandler GET /v1/whois/:domain
// 返回格式与上游 webtest.WhoisResult 一致；查询失败时错误写入 error 字段而非直接报错。
func publicWhoisHandler(c *gin.Context) {
	if !requirePublicCompatKey(c) {
		return
	}
	domain := strings.TrimSuffix(strings.TrimSpace(c.Param("domain")), ".")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain parameter is required"})
		return
	}
	domain = strings.ToLower(domain)
	if !validDomain.MatchString(domain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain"})
		return
	}

	result := &publicWhoisResult{Domain: strings.ToUpper(domain)}

	labels := strings.Split(domain, ".")
	server, ok := whoisServers[labels[len(labels)-1]]
	if !ok {
		result.Error = "no whois server found for ." + labels[len(labels)-1]
		c.JSON(http.StatusOK, result)
		return
	}
	result.WhoisServer = server

	raw, err := queryWhois(server, domain)
	result.Raw = raw
	if err != nil {
		result.Error = err.Error()
		c.JSON(http.StatusOK, result)
		return
	}
	fillPublicWhois(result, raw)

	c.JSON(http.StatusOK, result)
}

// fillPublicWhois 手写解析 WHOIS 原始文本（兼容英文与 CNNIC 中文格式），
// 填充 publicWhoisResult 各字段。
func fillPublicWhois(result *publicWhoisResult, raw string) {
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
		out := make([]string, 0)
		seen := make(map[string]struct{})
		for _, key := range keys {
			for _, v := range fields[strings.ToLower(key)] {
				normalized := strings.ToLower(strings.TrimSpace(v))
				if _, ok := seen[normalized]; ok {
					continue
				}
				seen[normalized] = struct{}{}
				out = append(out, strings.TrimSpace(v))
			}
		}
		return out
	}
	first := func(keys ...string) string {
		matched := values(keys...)
		if len(matched) == 0 {
			return ""
		}
		return matched[0]
	}

	result.Status = values("domain status", "status")
	result.NameServers = values("name server", "nserver", "名称服务器")
	result.Registrar.Name = first("registrar", "sponsoring registrar", "注册商")
	result.Registrar.IanaId = first("registrar iana id", "iana id")
	result.Dates.Registration = first("creation date", "created on", "registered on", "registration time", "registration date", "created date", "注册时间")
	result.Dates.Expiration = first("registry expiry date", "expiration date", "registrar registration expiration date", "expiry date", "expiration time", "expiry time", "paid-till", "到期时间")
	result.Dates.LastChanged = first("updated date", "last updated on", "updated on", "last updated date", "modification date", "last modified", "更新时间")

	result.Registrant = publicWhoisContactFrom(fields, "registrant", "注册人")
	result.Technical = publicWhoisContactFrom(fields, "tech", "technical", "技术联系人")

	abuse := publicWhoisAbuseFrom(fields)
	if !publicWhoisContactEmpty(abuse) {
		result.AbuseContact = abuse
	}
}

// publicWhoisContactFrom 按前缀组提取联系人信息
func publicWhoisContactFrom(fields map[string][]string, prefixes ...string) publicWhoisContact {
	var contact publicWhoisContact
	for _, prefix := range prefixes {
		base := strings.ToLower(strings.TrimSpace(prefix))
		firstOf := func(keys ...string) string {
			for _, key := range keys {
				if list, ok := fields[strings.ToLower(key)]; ok && len(list) > 0 {
					return strings.TrimSpace(list[0])
				}
			}
			return ""
		}
		if contact.Name == "" {
			contact.Name = firstOf(base+" name", base+" contact name")
		}
		if contact.Org == "" {
			contact.Org = firstOf(base+" org", base+" organization", base+" organisation")
		}
		if contact.Phone == "" {
			contact.Phone = firstOf(base+" phone", base+" telephone")
		}
		if contact.Email == "" {
			contact.Email = firstOf(base+" email", base+" contact email")
		}
		if contact.Province == "" {
			contact.Province = firstOf(base+" province", base+" state", base+" administrative area")
		}
		if contact.ContactUri == "" {
			contact.ContactUri = firstOf(base+" contact uri", base+" referral url")
		}
	}
	return contact
}

// publicWhoisAbuseFrom 从原始字段中提取 Abuse 联系人（仅邮箱与电话）
func publicWhoisAbuseFrom(fields map[string][]string) publicWhoisContact {
	var abuse publicWhoisContact
	for key, list := range fields {
		if len(list) == 0 {
			continue
		}
		lower := strings.ToLower(key)
		if strings.Contains(lower, "abuse") && strings.Contains(lower, "email") {
			abuse.Email = strings.TrimSpace(list[0])
		}
		if strings.Contains(lower, "abuse") && strings.Contains(lower, "phone") {
			abuse.Phone = strings.TrimSpace(list[0])
		}
	}
	return abuse
}

func publicWhoisContactEmpty(c publicWhoisContact) bool {
	return c.Name == "" && c.Org == "" && c.Phone == "" && c.Email == "" && c.Province == "" && c.ContactUri == ""
}

// publicDNSSECHandler GET /v1/dnssec/:domain
// 返回格式与上游 webtest.DNSSECResult 一致。
func publicDNSSECHandler(c *gin.Context) {
	if !requirePublicCompatKey(c) {
		return
	}
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain parameter is required"})
		return
	}
	result, _ := webtest.ResolveDNSSEC(domain)
	c.JSON(http.StatusOK, result)
}
