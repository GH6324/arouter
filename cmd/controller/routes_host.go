package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerHostRoutes(api *gin.RouterGroup, db *gorm.DB) {
	api.GET("/host/ips", authUserMiddleware(db), func(c *gin.Context) {
		resp := map[string]any{
			"interfaces": listPublicIfAddrs(),
		}
		if v4, v6 := detectPublicIPs(); v4 != "" || v6 != "" {
			resp["public_v4"] = v4
			resp["public_v6"] = v6
		}
		c.JSON(http.StatusOK, resp)
	})
	api.GET("/certs", func(c *gin.Context) {
		nodeToken := getBearerToken(c)
		if _, err := findNodeByToken(db, nodeToken); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		certPath := envOrDefault("AROUTER_CERT_PATH", "certs/arouter.crt")
		keyPath := envOrDefault("AROUTER_KEY_PATH", "certs/arouter.key")
		certData, err1 := os.ReadFile(certPath)
		keyData, err2 := os.ReadFile(keyPath)
		if err1 != nil || err2 != nil {
			// fallback to embedded defaults
			certData = defaultCert
			keyData = defaultKey
			if len(certData) == 0 || len(keyData) == 0 {
				c.String(http.StatusInternalServerError, fmt.Sprintf("cert read err=%v key err=%v", err1, err2))
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"cert": string(certData), "key": string(keyData)})
	})
}
