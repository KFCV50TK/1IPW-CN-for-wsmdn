package webtest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSSECResult struct {
	Domain     string  `json:"domain"`
	Enabled    bool    `json:"enabled"`
	Valid      bool    `json:"valid"`
	HasRRSIG   bool    `json:"has_rrsig"`
	HasDNSKEY  bool    `json:"has_dnskey"`
	HasDS      bool    `json:"has_ds"`
	Algorithm  uint8   `json:"algorithm"`
	KeyTag     uint16  `json:"key_tag"`
	SignerName string  `json:"signer_name"`
	Validation string  `json:"validation"`
	Duration   float64 `json:"duration"`
}

func ResolveDNSSEC(domain string) (*DNSSECResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ResolveDNSSECContext(ctx, domain)
}

func ResolveDNSSECContext(ctx context.Context, domain string) (*DNSSECResult, error) {
	started := time.Now()
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, " /\\") {
		return nil, fmt.Errorf("invalid domain")
	}
	result := &DNSSECResult{Domain: domain, Validation: "insecure"}
	fqdn := dns.Fqdn(domain)

	dnskeyResponse, err := exchangeDNSSECContext(ctx, fqdn, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	keys := make([]*dns.DNSKEY, 0)
	for _, rr := range append(append([]dns.RR{}, dnskeyResponse.Answer...), dnskeyResponse.Ns...) {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}
	result.HasDNSKEY = len(keys) > 0

	// Query both address families. Some zones sign only one family or return
	// the RRSIG in the authority section, so inspect all sections.
	var signatures []*dns.RRSIG
	var signedRRsets [][]dns.RR
	for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		response, queryErr := exchangeDNSSECContext(ctx, fqdn, recordType)
		if queryErr != nil {
			if recordType == dns.TypeA {
				return nil, queryErr
			}
			continue
		}
		records := append(append([]dns.RR{}, response.Answer...), response.Ns...)
		var rrset []dns.RR
		for _, rr := range records {
			switch typed := rr.(type) {
			case *dns.RRSIG:
				if typed.TypeCovered == recordType {
					signatures = append(signatures, typed)
				}
			case *dns.A:
				if recordType == dns.TypeA {
					rrset = append(rrset, typed)
				}
			case *dns.AAAA:
				if recordType == dns.TypeAAAA {
					rrset = append(rrset, typed)
				}
			}
		}
		if len(rrset) > 0 {
			signedRRsets = append(signedRRsets, rrset)
		}
	}
	result.HasRRSIG = len(signatures) > 0
	if len(signatures) > 0 {
		result.SignerName = strings.TrimSuffix(signatures[0].SignerName, ".")
	}
	if result.HasDNSKEY {
		result.Algorithm = keys[0].Algorithm
		result.KeyTag = keys[0].KeyTag()
	}

	dsResponse, dsErr := exchangeDNSSECContext(ctx, fqdn, dns.TypeDS)
	var dsRecords []*dns.DS
	if dsErr == nil {
		for _, rr := range append(append([]dns.RR{}, dsResponse.Answer...), dsResponse.Ns...) {
			if ds, ok := rr.(*dns.DS); ok {
				result.HasDS = true
				dsRecords = append(dsRecords, ds)
			}
		}
	}

	if result.HasDNSKEY && result.HasRRSIG {
		result.Enabled = true
		verified := false
		trustedKey := false
		if result.HasDS {
			for _, ds := range dsRecords {
				for _, key := range keys {
					if ds.KeyTag != key.KeyTag() || ds.Algorithm != key.Algorithm {
						continue
					}
					if candidate := key.ToDS(ds.DigestType); candidate != nil && strings.EqualFold(candidate.Digest, ds.Digest) {
						trustedKey = true
						break
					}
				}
				if trustedKey {
					break
				}
			}
		}
		if !trustedKey {
			result.Validation = "bogus"
		}

		for _, sig := range signatures {
			for _, key := range keys {
				if sig.KeyTag != key.KeyTag() || !strings.EqualFold(sig.SignerName, key.Hdr.Name) {
					continue
				}
				for _, rrset := range signedRRsets {
					if err := sig.Verify(key, rrset); err == nil {
						verified = true
						break
					}
				}
				if verified {
					break
				}
			}
			if verified {
				break
			}
		}
		if verified && trustedKey {
			result.Valid = true
			result.Validation = "secure"
		} else {
			result.Validation = "bogus"
		}
	} else if result.HasDNSKEY || result.HasRRSIG || result.HasDS {
		result.Enabled = true
		result.Validation = "bogus"
	}
	result.Duration = time.Since(started).Seconds()
	return result, nil
}

func exchangeDNSSECContext(ctx context.Context, domain string, recordType uint16) (*dns.Msg, error) {
	message := new(dns.Msg)
	message.SetQuestion(domain, recordType)
	message.RecursionDesired = true
	message.SetEdns0(1232, true)
	var lastErr error
	for _, server := range dnsServers() {
		client := &dns.Client{Timeout: 5 * time.Second}
		response, _, err := client.ExchangeContext(ctx, message, server)
		if err == nil {
			if response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError {
				return response, nil
			}
			lastErr = fmt.Errorf("DNS query failed with Rcode %d", response.Rcode)
			continue
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("DNS query failed")
	}
	return nil, lastErr
}
