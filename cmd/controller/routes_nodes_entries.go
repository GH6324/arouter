package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerNodeEntryRoutes(authGroup *gin.RouterGroup, db *gorm.DB) {
	authGroup.POST("/nodes/:id/entries", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Entry
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.Listen = stripPortPrefix(req.Listen)
		req.NodeID = node.ID
		req.Proto = defaultIfEmpty(req.Proto, "tcp")
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.DELETE("/nodes/:id/entries/:entryId", func(c *gin.Context) {
		id := c.Param("id")
		entryId := c.Param("entryId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&Entry{}, "id = ? AND node_id = ?", entryId, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})
}
