package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerConfigPublicRoutes(r *gin.Engine, db *gorm.DB) {
	// 提供嵌入的节点二进制下载，按 os/arch 返回对应文件。
	r.GET("/downloads/arouter", func(c *gin.Context) {
		osName := strings.ToLower(c.Query("os"))
		if osName == "" {
			osName = "linux"
		}
		arch := strings.ToLower(c.Query("arch"))
		if arch == "" {
			arch = "amd64"
		}
		filename := fmt.Sprintf("dist/arouter-%s-%s", osName, arch)
		data, err := embeddedNodeBins.ReadFile(filename)
		if err != nil {
			c.String(http.StatusNotFound, "binary not found for %s/%s", osName, arch)
			return
		}
		sum := sha256.Sum256(data)
		c.Header("X-Checksum-SHA256", hex.EncodeToString(sum[:]))
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="arouter-%s-%s"`, osName, arch))
		c.Data(http.StatusOK, "application/octet-stream", data)
	})

	// 返回填充好的 config_pull.sh
	r.GET("/nodes/:id/config_pull.sh", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		// token 校验，与 config 相同策略
		tokenHeader := getBearerToken(c)
		if tokenHeader == "" {
			if t := c.Query("token"); t != "" {
				tokenHeader = "Bearer " + t
			}
		}
		if token := strings.TrimPrefix(tokenHeader, "Bearer "); token == "" || token != node.Token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		installDir := c.Query("install_dir")
		if strings.TrimSpace(installDir) == "" {
			installDir = "/opt/arouter"
		}
		configURL := c.Query("config_url")
		if configURL == "" {
			if b64 := c.Query("config_url_b64"); b64 != "" {
				if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
					configURL = string(data)
				}
			}
		}
		if configURL == "" {
			scheme := "http"
			if c.Request.TLS != nil {
				scheme = "https"
			}
			hostBase := scheme + "://" + c.Request.Host
			configURL = fmt.Sprintf("%s/nodes/%d/config?token=%s", hostBase, node.ID, url.QueryEscape(node.Token))
		}
		proxy := c.Query("proxy_prefix")
		tokenVal := c.Query("token_override")
		if tokenVal == "" {
			tokenVal = node.Token
		}
		script := renderConfigPullScript(installDir, configURL, tokenVal, proxy)
		c.Header("Content-Type", "text/x-shellscript")
		c.String(http.StatusOK, script)
	})

	// 生成节点 config.json
	r.GET("/nodes/:id/config", func(c *gin.Context) {
		nodeToken := c.GetHeader("Authorization")
		if nodeToken == "" {
			if t := c.Query("token"); t != "" {
				nodeToken = "Bearer " + t
			}
		}
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").Preload("Routes").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if node.Token == "" {
			ensureNodeToken(db, &node)
		}
		if token := strings.TrimPrefix(nodeToken, "Bearer "); token == "" || token != node.Token {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var all []Node
		db.Find(&all)
		settings := loadSettings(db)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		base := scheme + "://" + c.Request.Host
		cfg := buildConfig(node, all, globalKey, base, settings)
		osHint := strings.ToLower(c.Query("os"))
		cfg = applyOSOverrides(cfg, osHint)
		if dir := c.Query("install_dir"); dir != "" {
			if strings.HasSuffix(dir, "/.arouter") {
				dir = strings.TrimSuffix(dir, "/.arouter")
			}
			cfg = applyInstallDirOverrides(cfg, dir)
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-config.json"`, node.Name))
		c.JSON(http.StatusOK, cfg)
	})

	// 生成节点安装脚本（内嵌 config，并包含后续自动拉取配置的 URL）
	r.GET("/nodes/:id/install.sh", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Entries").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if node.Token == "" {
			ensureNodeToken(db, &node)
		}
		authHeader := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if authHeader == "" {
			authHeader = c.Query("token")
		}
		authorized := authHeader != "" && authHeader == node.Token
		if !authorized {
			if tok := getBearerToken(c); tok != "" {
				if claims, err := parseJWT(tok); err == nil {
					var u User
					if err := db.First(&u, claims.UserID).Error; err == nil {
						authorized = true
					}
				}
			}
		}
		if !authorized {
			// 最后兜底：如果没有用户存在且首次访问，直接允许下载
			var cnt int64
			db.Model(&User{}).Count(&cnt)
			if cnt == 0 {
				authorized = true
			}
		}
		if !authorized {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var all []Node
		db.Find(&all)
		settings := loadSettings(db)
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		base := scheme + "://" + c.Request.Host
		cfg := buildConfig(node, all, globalKey, base, settings)
		osHint := strings.ToLower(c.Query("os"))
		cfg = applyOSOverrides(cfg, osHint)
		data, _ := json.MarshalIndent(cfg, "", "  ")
		configURL := fmt.Sprintf("%s/nodes/%s/config?token=%s", base, id, url.QueryEscape(node.Token))
		configPullBase := fmt.Sprintf("%s/nodes/%s/config_pull.sh?token=%s", base, id, url.QueryEscape(node.Token))
		c.Header("Content-Type", "text/x-shellscript")
		c.Header("Content-Disposition", "attachment; filename=\"install.sh\"")
		syncInt := syncIntervalFromConfig(data)
		c.String(http.StatusOK, installScript(string(data), configURL, configPullBase, base, syncInt))
	})
}
