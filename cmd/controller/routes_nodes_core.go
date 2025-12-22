package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerNodeCoreRoutes(authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	authGroup.GET("/nodes", func(c *gin.Context) {
		var settings Setting
		db.First(&settings)
		var nodes []Node
		db.Preload("Entries").Preload("Peers").Preload("Routes").Find(&nodes)
		for i := range nodes {
			nodeChanged := normalizeNodePorts(&nodes[i])
			entryChanged := normalizeEntriesPorts(nodes[i].Entries)
			if nodeChanged {
				db.Model(&nodes[i]).Updates(map[string]interface{}{
					"ws_listen":      nodes[i].WSListen,
					"wss_listen":     nodes[i].WSSListen,
					"metrics_listen": nodes[i].MetricsListen,
					"quic_listen":    nodes[i].QUICListen,
				})
			}
			if entryChanged {
				for _, e := range nodes[i].Entries {
					db.Model(&Entry{}).Where("id = ?", e.ID).Update("listen", e.Listen)
				}
			}
			ensureNodeToken(db, &nodes[i])
			if nodes[i].Transport == "" {
				nodes[i].Transport = settings.Transport
			}
			if nodes[i].Compression == "" {
				nodes[i].Compression = settings.Compression
			}
			if nodes[i].CompressionMin == 0 && settings.CompressionMin > 0 {
				nodes[i].CompressionMin = settings.CompressionMin
			}
		}
		c.JSON(http.StatusOK, nodes)
	})
	authGroup.POST("/nodes", func(c *gin.Context) {
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			c.String(http.StatusBadRequest, "name required")
			return
		}
		req.WSListen = stripPortPrefix(defaultIfEmpty(req.WSListen, "18080"))
		req.WSSListen = stripPortPrefix(req.WSSListen)
		req.MetricsListen = stripPortPrefix(defaultIfEmpty(req.MetricsListen, "19090"))
		req.QUICListen = stripPortPrefix(req.QUICListen)
		if strings.TrimSpace(req.MemLimit) == "" {
			req.MemLimit = "256MiB"
		}
		req.AuthKey = defaultIfEmpty(req.AuthKey, randomKey())
		req.InsecureSkipTLS = true
		req.RerouteAttempts = defaultInt(req.RerouteAttempts, 3)
		req.UDPSessionTTL = defaultIfEmpty(req.UDPSessionTTL, "60s")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		ensureNodeToken(db, &req)
		c.JSON(http.StatusCreated, req)
	})
	authGroup.GET("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if normalizeNodePorts(&node) {
			db.Model(&node).Updates(map[string]interface{}{
				"ws_listen":      node.WSListen,
				"wss_listen":     node.WSSListen,
				"metrics_listen": node.MetricsListen,
				"quic_listen":    node.QUICListen,
			})
		}
		if normalizeEntriesPorts(node.Entries) {
			for _, e := range node.Entries {
				db.Model(&Entry{}).Where("id = ?", e.ID).Update("listen", e.Listen)
			}
		}
		var settings Setting
		db.First(&settings)
		if node.Transport == "" {
			node.Transport = settings.Transport
		}
		if node.Compression == "" {
			node.Compression = settings.Compression
		}
		if node.CompressionMin == 0 && settings.CompressionMin > 0 {
			node.CompressionMin = settings.CompressionMin
		}
		if strings.TrimSpace(node.MemLimit) == "" {
			node.MemLimit = "256MiB"
		}
		c.JSON(http.StatusOK, node)
	})
	authGroup.GET("/nodes/:id/update-status", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var status NodeUpdateStatus
		if err := db.Where("node = ?", node.Name).First(&status).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusOK, nil)
				return
			}
			c.String(http.StatusInternalServerError, "query failed")
			return
		}
		c.JSON(http.StatusOK, status)
	})
	authGroup.PUT("/nodes/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Node
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		wsListen := stripPortPrefix(defaultIfEmpty(req.WSListen, node.WSListen))
		wssListen := stripPortPrefix(defaultIfEmpty(req.WSSListen, node.WSSListen))
		metricsListen := stripPortPrefix(defaultIfEmpty(req.MetricsListen, node.MetricsListen))
		quicListen := stripPortPrefix(defaultIfEmpty(req.QUICListen, node.QUICListen))
		memLimit := defaultIfEmpty(req.MemLimit, node.MemLimit)
		updates := map[string]interface{}{
			"ws_listen":        wsListen,
			"wss_listen":       wssListen,
			"metrics_listen":   metricsListen,
			"poll_period":      defaultIfEmpty(req.PollPeriod, node.PollPeriod),
			"compression":      defaultIfEmpty(req.Compression, node.Compression),
			"compression_min":  req.CompressionMin,
			"transport":        defaultIfEmpty(req.Transport, node.Transport),
			"quic_listen":      quicListen,
			"quic_server_name": defaultIfEmpty(req.QUICServerName, node.QUICServerName),
			"max_mux_streams":  req.MaxMuxStreams,
			"mux_max_age":      defaultIfEmpty(req.MuxMaxAge, node.MuxMaxAge),
			"mux_max_idle":     defaultIfEmpty(req.MuxMaxIdle, node.MuxMaxIdle),
			"mem_limit":        memLimit,
		}
		if err := db.Model(&node).Updates(updates).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id)
		c.JSON(http.StatusOK, node)
	})
	authGroup.POST("/nodes/:id/force-update", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := hub.sendCommand(node.Name, map[string]any{
			"type": "force_update",
			"data": map[string]any{},
		}); err != nil {
			c.String(http.StatusServiceUnavailable, "node offline or send failed: %v", err)
			return
		}
		c.Status(http.StatusAccepted)
	})
}
