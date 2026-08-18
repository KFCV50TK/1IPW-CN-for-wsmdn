package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"lemon-ipw/webtest"

	"github.com/gin-gonic/gin"
)

func TestCompatibilityCacheExpires(t *testing.T) {
	whoisCache = sync.Map{}
	value := &webtest.WhoisResult{Domain: "EXAMPLE.COM"}
	storeWhois("example.com", value)
	if cached, ok := cachedWhois("example.com"); !ok || cached != value {
		t.Fatal("expected WHOIS cache hit")
	}
	whoisCache.Store("expired.example", compatibilityCacheEntry[*webtest.WhoisResult]{value: value, timestamp: time.Now().Add(-compatibilityCacheTTL - time.Second)})
	if _, ok := cachedWhois("expired.example"); ok {
		t.Fatal("expected expired WHOIS cache entry to be removed")
	}
}

func TestCompatibilityHandlersValidateMissingParameters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/whois/:domain", whoisCompatibilityHandler)
	router.GET("/v1/dnssec/:domain", dnssecCompatibilityHandler)
	router.GET("/v1/asn/:ip", asnLookupHandler)

	for _, path := range []string{"/v1/whois/", "/v1/dnssec/", "/v1/asn/"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, expected router-level 404 for missing path", path, recorder.Code)
		}
	}
}

func TestCompatibilityRoutesUseBearerMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := ACCESS_TOKEN
	ACCESS_TOKEN = "compat-test-token"
	t.Cleanup(func() { ACCESS_TOKEN = original })

	router := gin.New()
	protected := router.Group("", requireBearerMiddleware())
	protected.GET("/v1/whois/:domain", whoisCompatibilityHandler)

	request := httptest.NewRequest(http.MethodGet, "/v1/whois/example.com", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer status = %d, want 401", recorder.Code)
	}
}
