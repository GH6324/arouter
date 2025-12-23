package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func registerMetricsRoutes(api *gin.RouterGroup, authGroup *gin.RouterGroup, db *gorm.DB) {
	api.POST("/metrics", func(c *gin.Context) {
		// 节点 token 校验
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
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
				Geo         struct {
					IP        string  `json:"ip"`
					Lat       float64 `json:"lat"`
					Lng       float64 `json:"lng"`
					City      string  `json:"city"`
					Region    string  `json:"region"`
					Country   string  `json:"country"`
					Org       string  `json:"org"`
					UpdatedAt int64   `json:"updated_at"`
				} `json:"geo"`
			} `json:"status"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		applyMetricsPayload(db, node, payload)
		c.Status(http.StatusNoContent)
	})

	api.POST("/probe/e2e", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		node, err := findNodeByToken(db, nodeToken)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var req struct {
			Route   string   `json:"route"`
			Path    []string `json:"path"`
			RTTMs   int64    `json:"rtt_ms"`
			Success bool     `json:"success"`
			Error   string   `json:"error"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Route) == "" || len(req.Path) == 0 {
			c.String(http.StatusBadRequest, "route and path required")
			return
		}
		probe := RouteProbe{
			Node:    node.Name,
			Route:   req.Route,
			Path:    StringList(req.Path),
			RTTMs:   req.RTTMs,
			Success: req.Success,
			Error:   req.Error,
		}
		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node"}, {Name: "route"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"path": probe.Path, "rtt_ms": probe.RTTMs, "success": probe.Success, "error": probe.Error, "updated_at": time.Now()}),
		}).Create(&probe).Error; err != nil {
			c.String(http.StatusInternalServerError, "save failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})

	authGroup.GET("/probes", func(c *gin.Context) {
		var probes []RouteProbe
		db.Order("updated_at desc").Find(&probes)
		c.JSON(http.StatusOK, probes)
	})
}
