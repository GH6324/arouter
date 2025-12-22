package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type NodeRouteDep struct {
	ID         uint     `json:"id"`
	Name       string   `json:"name"`
	Exit       string   `json:"exit"`
	Remote     string   `json:"remote"`
	Priority   int      `json:"priority"`
	Path       []string `json:"path"`
	ReturnPath []string `json:"return_path"`
}

func registerNodeDeleteRoutes(authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	authGroup.GET("/nodes/:id/delete-plan", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		routes := nodeRouteDeps(db, node.Name)
		c.JSON(http.StatusOK, gin.H{
			"node":   node.Name,
			"routes": routes,
		})
	})

	authGroup.POST("/nodes/:id/delete", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req struct {
			DeleteRoutes bool `json:"delete_routes"`
		}
		_ = c.ShouldBindJSON(&req)
		routes := nodeRouteDeps(db, node.Name)
		if len(routes) > 0 && !req.DeleteRoutes {
			c.JSON(http.StatusConflict, gin.H{
				"error":  "routes depend on node",
				"routes": routes,
			})
			return
		}
		if err := hub.sendCommand(node.Name, map[string]any{
			"type": "uninstall",
			"data": map[string]any{},
		}); err != nil {
			c.String(http.StatusConflict, "node offline or send failed: %v", err)
			return
		}
		pending := NodeUninstallStatus{
			Node:   node.Name,
			Status: "pending",
			Reason: "",
		}
		db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "node"}},
			DoUpdates: clause.Assignments(map[string]interface{}{"status": pending.Status, "reason": pending.Reason, "updated_at": time.Now()}),
		}).Create(&pending)
		routeIDs := make([]uint, 0, len(routes))
		routeNames := make([]string, 0, len(routes))
		for _, r := range routes {
			routeIDs = append(routeIDs, r.ID)
			routeNames = append(routeNames, r.Name)
		}
		storeDeleteRequest(&deleteRequest{
			Node:         node.Name,
			DeleteRoutes: req.DeleteRoutes,
			RouteIDs:     routeIDs,
			RouteNames:   routeNames,
			RequestedAt:  time.Now(),
		})
		c.JSON(http.StatusAccepted, gin.H{
			"node":   node.Name,
			"routes": routes,
		})
	})
}

func nodeRouteDeps(db *gorm.DB, nodeName string) []NodeRouteDep {
	var routes []RoutePlan
	db.Find(&routes)
	deps := make([]NodeRouteDep, 0)
	for _, r := range routes {
		if routeUsesNode(&r, nodeName) {
			deps = append(deps, NodeRouteDep{
				ID:         r.ID,
				Name:       r.Name,
				Exit:       r.Exit,
				Remote:     r.Remote,
				Priority:   r.Priority,
				Path:       []string(r.Path),
				ReturnPath: []string(r.ReturnPath),
			})
		}
	}
	return deps
}

func routeUsesNode(r *RoutePlan, node string) bool {
	if strings.TrimSpace(node) == "" || r == nil {
		return false
	}
	if r.Exit == node {
		return true
	}
	for _, p := range r.Path {
		if p == node {
			return true
		}
	}
	for _, p := range r.ReturnPath {
		if p == node {
			return true
		}
	}
	return false
}

func deleteNodeData(db *gorm.DB, nodeID uint, nodeName string) {
	db.Delete(&Peer{}, "node_id = ?", nodeID)
	db.Delete(&Entry{}, "node_id = ?", nodeID)
	db.Delete(&RoutePlan{}, "node_id = ?", nodeID)
	db.Delete(&Node{}, "id = ?", nodeID)
}
