package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerNodeMiscRoutes(authGroup *gin.RouterGroup, db *gorm.DB) {
	authGroup.GET("/return-status", func(c *gin.Context) {
		var rows []ReturnRouteStatus
		db.Order("updated_at desc").Find(&rows)
		c.JSON(http.StatusOK, rows)
	})

	authGroup.GET("/uninstall-status", func(c *gin.Context) {
		var rows []NodeUninstallStatus
		db.Order("updated_at desc").Find(&rows)
		c.JSON(http.StatusOK, rows)
	})

	authGroup.GET("/nodes/:id/uninstall-status", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var status NodeUninstallStatus
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

	// 手工设置节点公网IP
	authGroup.PUT("/nodes/:id/public-ips", func(c *gin.Context) {
		id := c.Param("id")
		var req struct {
			PublicIPs []string `json:"public_ips"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		ips := make([]string, 0)
		for _, ip := range req.PublicIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
		if err := db.Model(&Node{}).Where("id = ?", id).Update("public_ips", StringList(ips)).Error; err != nil {
			c.String(http.StatusInternalServerError, "update failed: %v", err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"public_ips": ips})
	})
}
