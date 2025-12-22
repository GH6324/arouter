package main

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerNodeRouteRoutes(api *gin.RouterGroup, authGroup *gin.RouterGroup, db *gorm.DB) {
	authGroup.GET("/nodes/:id/routes", func(c *gin.Context) {
		id := c.Param("id")
		var routes []RoutePlan
		db.Where("node_id = ?", id).Order("priority asc, id asc").Find(&routes)
		c.JSON(http.StatusOK, routes)
	})
	api.GET("/node-routes/:name", func(c *gin.Context) {
		// 节点 token 校验
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		name := c.Param("name")
		var node Node
		if err := db.Preload("Routes").Where("name = ?", name).First(&node).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		routes := make([]RouteConfig, 0, len(node.Routes))
		for _, r := range node.Routes {
			routes = append(routes, RouteConfig{
				Name:       r.Name,
				Exit:       r.Exit,
				Remote:     r.Remote,
				Priority:   r.Priority,
				Path:       []string(r.Path),
				ReturnPath: []string(r.ReturnPath),
			})
		}
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Priority == routes[j].Priority {
				return routes[i].Name < routes[j].Name
			}
			return routes[i].Priority < routes[j].Priority
		})
		c.JSON(http.StatusOK, gin.H{"routes": routes})
	})
	authGroup.POST("/nodes/:id/routes", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req RoutePlan
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		if req.Priority == 0 {
			req.Priority = 1
		}
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.PUT("/nodes/:id/routes/:routeId", func(c *gin.Context) {
		id := c.Param("id")
		rid := c.Param("routeId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req RoutePlan
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if err := db.Model(&RoutePlan{}).Where("id = ? AND node_id = ?", rid, id).Updates(map[string]any{
			"name":        req.Name,
			"exit":        req.Exit,
			"remote":      req.Remote,
			"priority":    req.Priority,
			"path":        req.Path,
			"return_path": req.ReturnPath,
			"updated_at":  time.Now(),
		}).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		var route RoutePlan
		db.First(&route, rid)
		c.JSON(http.StatusOK, route)
	})
	authGroup.DELETE("/nodes/:id/routes/:routeId", func(c *gin.Context) {
		id := c.Param("id")
		rid := c.Param("routeId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&RoutePlan{}, "id = ? AND node_id = ?", rid, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})
}
