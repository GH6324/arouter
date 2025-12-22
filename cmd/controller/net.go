package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if v == "" {
		return v
	}
	return "v" + v
}

func listPublicIfAddrs() []IfAddr {
	ifaces, _ := net.Interfaces()
	var res []IfAddr
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || isPrivateOrLinkLocal(ip) {
				continue
			}
			res = append(res, IfAddr{Iface: iface.Name, Addr: ip.String()})
		}
	}
	return res
}

func isPrivateOrLinkLocal(ip net.IP) bool {
	if ip == nil {
		return true
	}
	ip = ip.To16()
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// private IPv4
	if ip.To4() != nil {
		if ip[0] == 10 || ip[0] == 127 {
			return true
		}
		if ip[0] == 172 && ip[1]&0xf0 == 16 {
			return true
		}
		if ip[0] == 192 && ip[1] == 168 {
			return true
		}
		return false
	}
	// unique local IPv6 (fc00::/7)
	return ip[0]&0xfe == 0xfc
}

func detectPublicIPs() (string, string) {
	client := &http.Client{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v4 := fetchIP(ctx, client, "https://4.ipw.cn/")
	v6 := fetchIP(ctx, client, "https://6.ipw.cn/")
	return strings.TrimSpace(v4), strings.TrimSpace(v6)
}

func fetchIP(ctx context.Context, client *http.Client, url string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return string(b)
}
