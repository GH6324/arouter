package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerDiagCheckRoutes(authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	authGroup.POST("/endpoint-check/run", func(c *gin.Context) {
		var req struct {
			Nodes []string `json:"nodes"`
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
		run := newEndpointCheckRun(targets)
		offline := make([]string, 0)
		for _, name := range targets {
			if err := hub.sendCommand(name, map[string]any{
				"type": "endpoint_check",
				"data": map[string]any{
					"run_id": run.RunID,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
		})
	})

	authGroup.POST("/time-sync/run", func(c *gin.Context) {
		var req struct {
			Nodes    []string `json:"nodes"`
			Timezone string   `json:"timezone"`
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
		run := newTimeSyncRun(targets)
		offline := make([]string, 0)
		for _, name := range targets {
			if err := hub.sendCommand(name, map[string]any{
				"type": "time_sync",
				"data": map[string]any{
					"run_id":   run.RunID,
					"timezone": req.Timezone,
				},
			}); err != nil {
				offline = append(offline, name)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":  run.RunID,
			"offline": offline,
		})
	})

	authGroup.GET("/time-sync", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getTimeSyncRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "results": []TimeSyncResult{}})
			return
		}
		missing := make([]string, 0)
		got := make(map[string]struct{}, len(run.Results))
		for _, r := range run.Results {
			got[r.Node] = struct{}{}
		}
		for _, n := range run.Nodes {
			if _, ok := got[n]; !ok {
				missing = append(missing, n)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"run_id":     run.RunID,
			"created_at": run.CreatedAt,
			"results":    run.Results,
			"missing":    missing,
		})
	})
	authGroup.GET("/endpoint-check", func(c *gin.Context) {
		runID := strings.TrimSpace(c.Query("run_id"))
		run := getEndpointCheckRun(runID)
		if run == nil {
			c.JSON(http.StatusOK, gin.H{"run_id": runID, "results": []EndpointCheckResult{}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"run_id": run.RunID, "results": run.Results, "nodes": run.Nodes})
	})
}
