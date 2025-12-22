package main

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func applyMetricsPayload(db *gorm.DB, node *Node, payload struct {
	From        string                     `json:"from"`
	Metrics     map[string]LinkMetricsJSON `json:"metrics"`
	ReturnStats []ReturnStatJSON           `json:"return_stats"`
	Status      struct {
		CPUUsage    float64  `json:"cpu_usage"`
		MemUsed     uint64   `json:"mem_used_bytes"`
		MemTotal    uint64   `json:"mem_total_bytes"`
		UptimeSec   uint64   `json:"uptime_sec"`
		NetInBytes  uint64   `json:"net_in_bytes"`
		NetOutBytes uint64   `json:"net_out_bytes"`
		Version     string   `json:"version"`
		Transport   string   `json:"transport"`
		Compression string   `json:"compression"`
		OS          string   `json:"os"`
		Arch        string   `json:"arch"`
		PublicIPs   []string `json:"public_ips"`
	} `json:"status"`
}) {
	for to, m := range payload.Metrics {
		db.Model(&LinkMetric{}).Where("from_node = ? AND to_node = ?", payload.From, to).
			Assign(map[string]any{"rtt_ms": m.RTTms, "loss": m.Loss, "updated_at": time.Now()}).
			FirstOrCreate(&LinkMetric{
				From: payload.From, To: to, RTTMs: m.RTTms, Loss: m.Loss, UpdatedAt: time.Now(),
			})
	}
	for _, rs := range payload.ReturnStats {
		if rs.Route == "" {
			rs.Route = "auto"
		}
		if rs.Entry == "" {
			rs.Entry = payload.From
		}
		if rs.Exit == "" || rs.Entry == "" {
			continue
		}
		status := ReturnRouteStatus{
			Node:       payload.From,
			Route:      rs.Route,
			Entry:      rs.Entry,
			Exit:       rs.Exit,
			Auto:       rs.Auto,
			Pending:    rs.Pending,
			ReadyTotal: rs.ReadyTotal,
			ReadyAt:    rs.ReadyAt,
			FailTotal:  rs.FailTotal,
			FailAt:     rs.FailAt,
			FailReason: rs.FailReason,
		}
		db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "node"}, {Name: "route"}, {Name: "entry"}, {Name: "exit"}, {Name: "auto"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"pending":     status.Pending,
				"ready_total": status.ReadyTotal,
				"ready_at":    status.ReadyAt,
				"fail_total":  status.FailTotal,
				"fail_at":     status.FailAt,
				"fail_reason": status.FailReason,
				"updated_at":  time.Now(),
			}),
		}).Create(&status)
	}
	updates := map[string]any{
		"last_cpu":      payload.Status.CPUUsage,
		"mem_used":      payload.Status.MemUsed,
		"mem_total":     payload.Status.MemTotal,
		"uptime_sec":    payload.Status.UptimeSec,
		"net_in_bytes":  payload.Status.NetInBytes,
		"net_out_bytes": payload.Status.NetOutBytes,
		"node_version":  payload.Status.Version,
		"last_seen_at":  time.Now(),
		"transport":     firstNonEmpty(payload.Status.Transport, node.Transport),
		"compression":   firstNonEmpty(payload.Status.Compression, node.Compression),
		"os_name":       payload.Status.OS,
		"arch":          payload.Status.Arch,
	}
	// 合并已有公网IP + 新上报，不覆盖手动填写
	var existing Node
	_ = db.First(&existing, node.ID).Error
	merged := make([]string, 0)
	seen := map[string]struct{}{}
	for _, ip := range existing.PublicIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		merged = append(merged, ip)
	}
	for _, ip := range payload.Status.PublicIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		merged = append(merged, ip)
	}
	if len(merged) > 0 {
		updates["public_ips"] = StringList(merged)
	}
	db.Model(&Node{}).Where("id = ?", node.ID).Updates(updates)
}

func findNodeByToken(db *gorm.DB, token string) (*Node, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	var n Node
	if err := db.Where("token = ?", token).First(&n).Error; err != nil {
		return nil, err
	}
	return &n, nil
}
