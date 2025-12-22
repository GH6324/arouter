package main

import (
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
