package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"lemon-ipw/ipdb"
	"lemon-ipw/ssrf"
	"lemon-ipw/webtest"

	"github.com/gin-gonic/gin"
)

const compatibilityCacheTTL = 5 * time.Minute

type compatibilityCacheEntry[T any] struct {
	value     T
	timestamp time.Time
}

var (
	asnWhoisCache sync.Map
	whoisCache    sync.Map
)

func cachedASNWhois(asn string) (*webtest.ASNWhoisResult, bool) {
	key := strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(key, "AS") {
		key = "AS" + key
	}
	value, ok := asnWhoisCache.Load(key)
	if !ok {
		return nil, false
	}
	entry, ok := value.(compatibilityCacheEntry[*webtest.ASNWhoisResult])
	if !ok || time.Since(entry.timestamp) >= compatibilityCacheTTL {
		asnWhoisCache.Delete(key)
		return nil, false
	}
	return entry.value, true
}

func storeASNWhois(asn string, value *webtest.ASNWhoisResult) {
	key := strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(key, "AS") {
		key = "AS" + key
	}
	asnWhoisCache.Store(key, compatibilityCacheEntry[*webtest.ASNWhoisResult]{value: value, timestamp: time.Now()})
}

func cachedWhois(domain string) (*webtest.WhoisResult, bool) {
	value, ok := whoisCache.Load(domain)
	if !ok {
		return nil, false
	}
	entry, ok := value.(compatibilityCacheEntry[*webtest.WhoisResult])
	if !ok || time.Since(entry.timestamp) >= compatibilityCacheTTL {
		whoisCache.Delete(domain)
		return nil, false
	}
	return entry.value, true
}

func storeWhois(domain string, value *webtest.WhoisResult) {
	whoisCache.Store(domain, compatibilityCacheEntry[*webtest.WhoisResult]{value: value, timestamp: time.Now()})
}

func asnLookupHandler(c *gin.Context) {
	rawIP := strings.TrimSpace(c.Param("ip"))
	if rawIP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP parameter is required"})
		return
	}
	parsedIP := net.ParseIP(rawIP)
	if parsedIP == nil || ssrf.IsPrivateIP(parsedIP) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a public IP address is required"})
		return
	}
	ip := parsedIP.String()
	result := ipdb.SearchIP(c.Request.Context(), ip, "maxmind_asn", "dbip_asn")
	response := gin.H{"ip": ip}

	if value, ok := result["maxmind_asn"]; ok {
		switch typed := value.(type) {
		case *ipdb.MMDBASNResult:
			response["geolite2_asn"] = gin.H{
				"asn": strings.TrimPrefix(strings.ToUpper(typed.ASN), "AS"),
				"org": typed.Org,
			}
			if whois, ok := cachedASNWhois(typed.ASN); ok {
				response["whois"] = whois
			} else if whois, err := webtest.QueryASNWhoisContext(c.Request.Context(), typed.ASN); err == nil {
				storeASNWhois(typed.ASN, whois)
				response["whois"] = whois
			}
		case string:
			response["geolite2_asn"] = gin.H{"error": strings.TrimPrefix(typed, "error: ")}
		}
	}
	if value, ok := result["dbip_asn"]; ok {
		switch typed := value.(type) {
		case *ipdb.MMDBASNResult:
			response["dbip_asn"] = gin.H{
				"asn": strings.TrimPrefix(strings.ToUpper(typed.ASN), "AS"),
				"org": typed.Org,
			}
		case string:
			response["dbip_asn"] = gin.H{"error": strings.TrimPrefix(typed, "error: ")}
		}
	}
	c.JSON(http.StatusOK, response)
}

func whoisCompatibilityHandler(c *gin.Context) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Param("domain")), "."))
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain parameter is required"})
		return
	}
	if result, ok := cachedWhois(domain); ok {
		c.JSON(http.StatusOK, result)
		return
	}
	result, err := webtest.QueryWhoisContext(c.Request.Context(), domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	storeWhois(domain, result)
	c.JSON(http.StatusOK, result)
}

func dnssecCompatibilityHandler(c *gin.Context) {
	domain := strings.TrimSpace(c.Param("domain"))
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain parameter is required"})
		return
	}
	result, err := webtest.ResolveDNSSECContext(c.Request.Context(), domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
