package main

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerDiagTraceRoutes(authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	// 线路测试触发：指定节点、目标（对端名称或 host），推送到节点 WS。
	authGroup.POST("/probe/request", func(c *gin.Context) {
		var req struct {
			Node   string `json:"node"`   // 节点名称
			Target string `json:"target"` // 目标节点/host
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Node) == "" || strings.TrimSpace(req.Target) == "" {
			c.String(http.StatusBadRequest, "node and target required")
			return
		}
		if err := hub.sendCommand(req.Node, map[string]any{
			"type": "probe",
			"data": map[string]any{"target": req.Target},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.Status(http.StatusAccepted)
	})

	// 线路端到端延迟测试：指定节点 + 路径，控制器经 WS 下发，节点执行 HTTP 探测并回报。
	authGroup.POST("/route-test", func(c *gin.Context) {
		var req struct {
			Node   string   `json:"node"`
			Route  string   `json:"route"`
			Path   []string `json:"path"`
			Target string   `json:"target"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Node) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "node, path required")
			return
		}
		if err := hub.sendCommand(req.Node, map[string]any{
			"type": "route_test",
			"data": map[string]any{
				"route":  req.Route,
				"path":   req.Path,
				"target": req.Target,
			},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.Status(http.StatusAccepted)
	})

	authGroup.POST("/route-diag/run", func(c *gin.Context) {
		var req struct {
			Node       string   `json:"node"`
			Route      string   `json:"route"`
			Path       []string `json:"path"`
			ReturnPath []string `json:"return_path"`
			Target     string   `json:"target"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Node) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "node, path required")
			return
		}
		run := newDiagTraceRun()
		// collect logs for forward + return nodes
		nodeSet := make(map[string]struct{})
		for _, p := range req.Path {
			if strings.TrimSpace(p) != "" {
				nodeSet[p] = struct{}{}
			}
		}
		for _, p := range req.ReturnPath {
			if strings.TrimSpace(p) != "" {
				nodeSet[p] = struct{}{}
			}
		}
		nodes := make([]string, 0, len(nodeSet))
		for n := range nodeSet {
			nodes = append(nodes, n)
		}
		sort.Strings(nodes)
		ensureDiagRun(run.RunID, nodes)
		offline := make([]string, 0)
		for _, name := range nodes {
			if err := hub.sendCommand(name, map[string]any{
				"type": "diag_collect",
				"data": map[string]any{
					"run_id":       run.RunID,
					"limit":        400,
					"contains":     "",
					"clear_before": true,
					"delay_ms":     12000,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		if err := hub.sendCommand(req.Node, map[string]any{
			"type": "route_diag",
			"data": map[string]any{
				"run_id":      run.RunID,
				"route":       req.Route,
				"path":        req.Path,
				"return_path": req.ReturnPath,
				"target":      req.Target,
			},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
		})
	})

	authGroup.GET("/route-diag", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getDiagTraceRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "events": []DiagTraceEvent{}})
			return
		}
		sort.Slice(run.Events, func(i, j int) bool {
			return run.Events[i].At < run.Events[j].At
		})
		c.JSON(http.StatusOK, gin.H{
			"run_id":     run.RunID,
			"created_at": run.CreatedAt,
			"events":     run.Events,
		})
	})
}
