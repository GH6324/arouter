package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	wscompat "arouter/internal/wscompat"
)

func registerWSRoutes(api *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	// WebSocket 通道：节点推送 metrics，后续可扩展控制器下发实时指令。
	api.GET("/ws", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ws, err := wscompat.Accept(c.Writer, c.Request, &wscompat.AcceptOptions{})
		if err != nil {
			return
		}
		hub.register(node.Name, ws)
		ctx := c.Request.Context()
		// 控制器也定期发 ping，避免中间设备超时关闭
		done := make(chan struct{})
		go func() {
			t := time.NewTicker(20 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case <-t.C:
					_ = ws.Ping(context.Background())
				}
			}
		}()
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				ws.Close()
				hub.unregister(node.Name, ws)
				close(done)
				return
			}
			var msg struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			switch msg.Type {
			case "metrics":
				var payload struct {
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
				}
				if err := json.Unmarshal(msg.Data, &payload); err != nil {
					continue
				}
				if payload.From == "" {
					payload.From = node.Name
				}
				applyMetricsPayload(db, node, payload)
			case "route_test_result":
				var res struct {
					Route   string   `json:"route"`
					Path    []string `json:"path"`
					Target  string   `json:"target"`
					RTTMs   int64    `json:"rtt_ms"`
					Success bool     `json:"success"`
					Error   string   `json:"error"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if strings.TrimSpace(res.Route) == "" || len(res.Path) == 0 {
					continue
				}
				probe := RouteProbe{
					Node:    node.Name,
					Route:   res.Route,
					Path:    StringList(res.Path),
					RTTMs:   res.RTTMs,
					Success: res.Success,
					Error:   res.Error,
				}
				db.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "node"}, {Name: "route"}},
					DoUpdates: clause.Assignments(map[string]interface{}{"path": probe.Path, "rtt_ms": probe.RTTMs, "success": probe.Success, "error": probe.Error, "updated_at": time.Now()}),
				}).Create(&probe)
			case "update_status":
				var res struct {
					Status  string `json:"status"`
					Version string `json:"version"`
					Reason  string `json:"reason"`
					Forced  bool   `json:"forced"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				status := NodeUpdateStatus{
					Node:    node.Name,
					Status:  res.Status,
					Version: res.Version,
					Reason:  res.Reason,
					Forced:  res.Forced,
				}
				db.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "node"}},
					DoUpdates: clause.Assignments(map[string]interface{}{"status": status.Status, "version": status.Version, "reason": status.Reason, "forced": status.Forced, "updated_at": time.Now()}),
				}).Create(&status)
			case "diag_report":
				var res struct {
					RunID  string   `json:"run_id"`
					Node   string   `json:"node"`
					At     int64    `json:"at"`
					Lines  []string `json:"lines"`
					Limit  int      `json:"limit"`
					Filter string   `json:"filter"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				at := time.Now()
				if res.At > 0 {
					at = time.UnixMilli(res.At)
				}
				storeDiagReport(res.RunID, DiagReport{
					RunID:  res.RunID,
					Node:   res.Node,
					At:     at,
					Lines:  res.Lines,
					Limit:  res.Limit,
					Filter: res.Filter,
				})
			case "diag_event":
				var res DiagTraceEvent
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				if res.At == 0 {
					res.At = time.Now().UnixMilli()
				}
				storeDiagTraceEvent(res)
			case "endpoint_check_result":
				var res struct {
					RunID   string                `json:"run_id"`
					Node    string                `json:"node"`
					Results []EndpointCheckResult `json:"results"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				for i := range res.Results {
					if res.Results[i].Node == "" {
						res.Results[i].Node = res.Node
					}
				}
				storeEndpointCheckResults(res.RunID, res.Results)
			case "time_sync_result":
				var res TimeSyncResult
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				if res.Node == "" {
					res.Node = node.Name
				}
				storeTimeSyncResult(res.RunID, res)
			case "uninstall_result":
				var res struct {
					Status string `json:"status"`
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(msg.Data, &res); err != nil {
					continue
				}
				status := NodeUninstallStatus{
					Node:   node.Name,
					Status: res.Status,
					Reason: res.Reason,
				}
				db.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "node"}},
					DoUpdates: clause.Assignments(map[string]interface{}{"status": status.Status, "reason": status.Reason, "updated_at": time.Now()}),
				}).Create(&status)
				if strings.EqualFold(res.Status, "success") {
					if req := getDeleteRequest(node.Name); req != nil {
						if req.DeleteRoutes && len(req.RouteIDs) > 0 {
							db.Delete(&RoutePlan{}, req.RouteIDs)
						}
						deleteNodeData(db, node.ID, node.Name)
						clearDeleteRequest(node.Name)
					}
					db.Delete(&NodeUninstallStatus{}, "node = ?", node.Name)
				} else if res.Status != "" {
					clearDeleteRequest(node.Name)
				}
			default:
			}
		}
	})

	api.GET("/topology", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var rows []LinkMetric
		db.Find(&rows)
		edges := make(map[string]map[string]LinkMetricsJSON)
		for _, r := range rows {
			if edges[r.From] == nil {
				edges[r.From] = make(map[string]LinkMetricsJSON)
			}
			edges[r.From][r.To] = LinkMetricsJSON{RTTms: r.RTTMs, Loss: r.Loss, UpdatedAt: r.UpdatedAt}
		}
		c.JSON(http.StatusOK, gin.H{"edges": edges})
	})
}
