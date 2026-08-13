package webtest

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DNSSECResult 包含 DNSSEC 验证的结果
// 与上游 ipw-cn webtest/dnssec.go 的返回格式保持一致
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

// ResolveDNSSEC 执行 DNSSEC 验证
// 流程：
//  1. 查询 DNSKEY 记录，获取密钥 RRset
//  2. 查询 A 记录（带 DO 位），获取 A RRset + RRSIG
//  3. 用 DNSKEY 中的密钥逐一对 RRSIG.Verify(dnskey, aRRset) 验证
//  4. 查询 DS 记录，检查链式信任
func ResolveDNSSEC(domain string) (*DNSSECResult, error) {
	start := time.Now()
	result := &DNSSECResult{
		Domain: domain,
	}

	client := new(dns.Client)

	// 1. 查询 DNSKEY 记录
	msgDNSKEY := new(dns.Msg)
	msgDNSKEY.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	msgDNSKEY.SetEdns0(4096, true)

	responseDNSKEY, _, err := client.Exchange(msgDNSKEY, dnsServer)
	result.Duration = time.Since(start).Seconds() * 1000

	if err != nil {
		result.Validation = fmt.Sprintf("DNSKEY query failed: %v", err)
		return result, nil
	}

	if responseDNSKEY.Rcode != dns.RcodeSuccess {
		result.Validation = fmt.Sprintf("DNSKEY query failed with Rcode %d", responseDNSKEY.Rcode)
		return result, nil
	}

	var dnskeyRRset []dns.RR
	var dnskeyList []*dns.DNSKEY
	for _, ans := range responseDNSKEY.Answer {
		if dnskey, ok := ans.(*dns.DNSKEY); ok {
			dnskeyRRset = append(dnskeyRRset, dnskey)
			dnskeyList = append(dnskeyList, dnskey)
			result.HasDNSKEY = true
		}
	}

	if len(dnskeyRRset) > 0 {
		result.KeyTag = dnskeyList[0].KeyTag()
		result.Algorithm = dnskeyList[0].Algorithm
	}

	// 2. 查询 A 记录（带 DO 位）
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msgA.SetEdns0(4096, true)

	responseA, _, err := client.Exchange(msgA, dnsServer)
	if err == nil && responseA.Rcode == dns.RcodeSuccess {
		var aRRset []dns.RR
		for _, ans := range responseA.Answer {
			if aRecord, ok := ans.(*dns.A); ok {
				aRRset = append(aRRset, aRecord)
			}
		}

		var rrsigList []*dns.RRSIG
		for _, ans := range responseA.Answer {
			if rrsig, ok := ans.(*dns.RRSIG); ok {
				rrsigList = append(rrsigList, rrsig)
				result.HasRRSIG = true
			}
		}

		// 3. 用 DNSKEY 逐条验证 RRSIG
		for _, rrsig := range rrsigList {
			for _, dnskey := range dnskeyList {
				if keyErr := rrsig.Verify(dnskey, aRRset); keyErr == nil {
					result.Enabled = true
					result.Valid = true
					result.Algorithm = dnskey.Algorithm
					result.KeyTag = dnskey.KeyTag()
					result.SignerName = rrsig.SignerName
					result.Validation = fmt.Sprintf("DNSSEC 验证通过 (算法: %d, KeyTag: %d)", dnskey.Algorithm, dnskey.KeyTag())
					return result, nil
				}
			}
		}

		if len(rrsigList) > 0 && len(dnskeyRRset) > 0 {
			result.Enabled = true
			result.Valid = false
			result.Validation = fmt.Sprintf("RRSIG 验证失败: %d 条 RRSIG, %d 个 DNSKEY，无匹配签名", len(rrsigList), len(dnskeyRRset))
			return result, nil
		}
	}

	// 4. 查询 DS 记录
	msgDS := new(dns.Msg)
	msgDS.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	responseDS, _, _ := client.Exchange(msgDS, dnsServer)
	if responseDS != nil && responseDS.Rcode == dns.RcodeSuccess {
		for _, ans := range responseDS.Answer {
			if _, ok := ans.(*dns.DS); ok {
				result.HasDS = true
				break
			}
		}
	}

	if result.HasRRSIG && result.HasDNSKEY {
		result.Enabled = true
		result.Valid = false
		result.Validation = "存在 RRSIG 和 DNSKEY，但签名验证未通过"
	} else if result.HasRRSIG {
		result.Enabled = true
		result.Valid = false
		result.Validation = "存在 RRSIG，但缺少 DNSKEY"
	} else if result.HasDNSKEY {
		result.Enabled = false
		result.Valid = false
		result.Validation = "存在 DNSKEY，但缺少 RRSIG"
	} else {
		result.Enabled = false
		result.Valid = false
		result.Validation = "未检测到 DNSSEC 记录"
	}

	return result, nil
}
