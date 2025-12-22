package main

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerDiagCollectRoutes(authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	authGroup.POST("/diag/run", func(c *gin.Context) {
		var req struct {
			Nodes    []string `json:"nodes"`
			Limit    int      `json:"limit"`
			Contains string   `json:"contains"`
		}
		_ = c.ShouldBindJSON(&req)
		var nodes []Node
		db.Find(&nodes)
		targets := make([]string, 0)
		if len(req.Nodes) == 0 {
			for _, n := range nodes {
				targets = append(targets, n.Name)
			}
		} else {
			targets = append(targets, req.Nodes...)
		}
		run := newDiagRun(targets)
		sent := make([]string, 0, len(targets))
		offline := make([]string, 0)
		for _, name := range targets {
			if err := hub.sendCommand(name, map[string]any{
				"type": "diag_collect",
				"data": map[string]any{
					"run_id":   run.RunID,
					"limit":    req.Limit,
					"contains": req.Contains,
				},
			}); err != nil {
				offline = append(offline, name)
				continue
			}
			sent = append(sent, name)
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":   run.RunID,
			"sent":     sent,
			"offline":  offline,
			"nodes":    targets,
			"limit":    req.Limit,
			"contains": req.Contains,
		})
	})

	authGroup.GET("/diag", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getDiagRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "nodes": []string{}, "reports": []DiagReport{}, "missing": []string{}})
			return
		}
		reports := make([]DiagReport, 0, len(run.Reports))
		missing := make([]string, 0)
		seen := make(map[string]struct{}, len(run.Reports))
		for node, rep := range run.Reports {
			reports = append(reports, rep)
			seen[node] = struct{}{}
		}
		for _, node := range run.Nodes {
			if _, ok := seen[node]; !ok {
				missing = append(missing, node)
			}
		}
		sort.Slice(reports, func(i, j int) bool {
			if reports[i].Node != reports[j].Node {
				return reports[i].Node < reports[j].Node
			}
			return reports[i].At.Before(reports[j].At)
		})
		c.JSON(http.StatusOK, gin.H{
			"run_id":     run.RunID,
			"created_at": run.CreatedAt,
			"nodes":      run.Nodes,
			"reports":    reports,
			"missing":    missing,
		})
	})

	authGroup.POST("/diag/refresh", func(c *gin.Context) {
		var req struct {
			RunID    string   `json:"run_id"`
			Nodes    []string `json:"nodes"`
			Limit    int      `json:"limit"`
			Contains string   `json:"contains"`
		}
		_ = c.ShouldBindJSON(&req)
		runID := strings.TrimSpace(req.RunID)
		run := getDiagRun(runID)
		if run == nil {
			c.String(http.StatusBadRequest, "invalid run_id")
			return
		}
		targets := req.Nodes
		if len(targets) == 0 {
			targets = run.Nodes
		}
		offline := make([]string, 0)
		for _, name := range targets {
			if err := hub.sendCommand(name, map[string]any{
				"type": "diag_collect",
				"data": map[string]any{
					"run_id":       run.RunID,
					"limit":        req.Limit,
					"contains":     req.Contains,
					"clear_before": false,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
			"nodes":   targets,
		})
	})
}
