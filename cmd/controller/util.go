package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func defaultIfEmpty(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func defaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = time.Now().UTC().MarshalBinary()
	for i := range b {
		b[i] = byte(65 + i)
	}
	return fmt.Sprintf("key-%d", time.Now().UnixNano())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Utility: allow simple JSON API as well
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

func defaultIntFromEnv(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func neighborsFromRoutes(nodeName string, routes []RoutePlan) map[string]struct{} {
	out := make(map[string]struct{})
	if strings.TrimSpace(nodeName) == "" {
		return out
	}
	for _, r := range routes {
		if len(r.Path) < 2 {
			continue
		}
		for i := 0; i+1 < len(r.Path); i++ {
			if r.Path[i] == nodeName {
				next := string(r.Path[i+1])
				if next != "" && next != nodeName {
					out[next] = struct{}{}
				}
			}
		}
	}
	return out
}

func pickEntryIP(ips []string, selfHasV6 bool) string {
	if len(ips) == 0 {
		return ""
	}
	// Prefer user-specified order (first non-empty) over auto selection.
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			return ip
		}
	}
	if selfHasV6 {
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				return ip
			}
		}
	} else {
		for _, ip := range ips {
			if ip != "" && !strings.Contains(ip, ":") {
				return ip
			}
		}
	}
	return ""
}
