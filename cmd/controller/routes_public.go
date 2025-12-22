package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func registerPublicRoutes(r *gin.Engine) {
	// 版本信息
	r.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": buildVersion})
	})
}
