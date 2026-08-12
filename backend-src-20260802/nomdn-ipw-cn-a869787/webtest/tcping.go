// Package webtest 提供网络连通性检测功能，支持 IPv4/IPv6 的 ICMP ping 和 TCP ping
package webtest

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"lemon-ipw/ssrf"
)

// TCPingResult 包含 TCP 连接测试的结果
type TCPingResult struct {
	IP        string    `json:"ip"`        // 目标 IP 地址
	Port      string    `json:"port"`      // 目标端口
	Success   bool      `json:"success"`   // 是否连接成功
	RTT       float64   `json:"rtt"`       // 往返时间（毫秒），失败时为 -1
	Error     string    `json:"error"`     // 错误信息，成功时为空
	Timestamp time.Time `json:"timestamp"` // 测试时间
}

// TCPingStats 包含多次 TCP 连接测试的统计信息
type TCPingStats struct {
	IP       string         `json:"ip"`        // 目标 IP 地址
	Port     string         `json:"port"`      // 目标端口
	Sent     int            `json:"sent"`      // 尝试连接次数
	Success  int            `json:"success"`   // 成功连接次数
	LossRate float64        `json:"loss_rate"` // 丢包率（百分比）
	MaxRTT   float64        `json:"max_rtt"`   // 最大往返时间（毫秒）
	MinRTT   float64        `json:"min_rtt"`   // 最小往返时间（毫秒）
	AvgRTT   float64        `json:"avg_rtt"`   // 平均往返时间（毫秒）
	Results  []TCPingResult `json:"results"`   // 每次测试的详细结果
}

// resolveHost 将主机名解析为指定协议版本的 IP 地址
// version 参数支持 "v4"（IPv4）和 "v6"（IPv6）
// isPublicAddress reports whether ip is a global unicast address. Private,
// loopback, link-local, multicast, CGNAT and reserved ranges are rejected so
// TCPing cannot be used as an internal port scanner.
func isPublicAddress(ip net.IP) bool {
	return !ssrf.IsPrivateIP(ip)
}

func resolveHost(host string, version string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicAddress(ip) {
			return "", fmt.Errorf("private or internal address is not allowed")
		}
		if version == "v4" && ip.To4() != nil {
			return ip.String(), nil
		}
		if version == "v6" && ip.To4() == nil && ip.To16() != nil {
			return ip.String(), nil
		}
		return "", fmt.Errorf("no %s address found for %s", version, host)
	}

	var result DNSResult
	var err error
	if version == "v4" {
		result, err = ResolveARecord(host)
	} else {
		result, err = ResolveAAAARecord(host)
	}
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %w", err)
	}
	for _, value := range result.Record {
		if ip := net.ParseIP(value); ip != nil {
			if !isPublicAddress(ip) {
				return "", fmt.Errorf("private or internal address is not allowed")
			}
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("no %s address found for %s", version, host)
}

func TCPing(ctx context.Context, host string, port string, version string, timeout time.Duration) (*TCPingResult, error) {
	ip, err := resolveHost(host, version)
	if err != nil {
		return nil, err
	}
	addr := ""
	switch version {
	case "v4":
		addr = fmt.Sprintf("%s:%s", ip, port)
	case "v6":
		addr = fmt.Sprintf("[%s]:%s", ip, port)

	}

	start := time.Now()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	rtt := time.Since(start)

	result := &TCPingResult{
		IP:        ip,
		Port:      port,
		Timestamp: start,
	}

	if err != nil {
		result.Success = false
		result.RTT = -1
		result.Error = err.Error()
	} else {
		conn.Close()
		result.Success = true
		result.RTT = float64(rtt.Microseconds()) / 1000.0
	}

	return result, nil
}

// TCPingRun 执行多次 TCP 连接测试并返回统计结果
// 参数：
//   - host: 目标主机名或 IP 地址
//   - port: 目标端口号
//   - count: 测试次数
//   - version: 协议版本，"v4" 或 "v6"
//   - timeout: 每次连接的超时时间
//   - interval: 两次测试之间的间隔时间
//
// 返回 TCPingStats 包含统计信息
func TCPingRun(ctx context.Context, host string, port string, count int, version string, timeout time.Duration, interval time.Duration) (*TCPingStats, error) {
	ip, err := resolveHost(host, version)
	if err != nil {
		return &TCPingStats{
			IP:       "Error: " + err.Error(),
			Port:     port,
			Sent:     count,
			Success:  0,
			Results:  nil,
			MinRTT:   -1,
			MaxRTT:   -1,
			AvgRTT:   -1,
			LossRate: 100,
		}, nil
	}

	stats := &TCPingStats{
		IP:      ip,
		Port:    port,
		Sent:    count,
		MinRTT:  math.MaxFloat64,
		Results: make([]TCPingResult, 0, count),
	}

	var totalRTT float64
	successCount := 0

	for i := 0; i < count; i++ {
		result, err := TCPing(ctx, host, port, version, timeout)
		if err != nil {
			return nil, err
		}

		stats.Results = append(stats.Results, *result)

		if result.Success {
			successCount++
			totalRTT += result.RTT
			if result.RTT > stats.MaxRTT {
				stats.MaxRTT = result.RTT
			}
			if result.RTT < stats.MinRTT {
				stats.MinRTT = result.RTT
			}
		}

		if i < count-1 && interval > 0 {
			time.Sleep(interval)
		}
	}

	stats.Success = successCount
	stats.LossRate = math.Round(float64(count-successCount)*10000/float64(count)) / 100

	if successCount > 0 {
		stats.AvgRTT = math.Round(totalRTT*100/float64(successCount)) / 100
	} else {
		stats.MinRTT = -1
		stats.MaxRTT = -1
		stats.AvgRTT = -1
	}

	return stats, nil
}
