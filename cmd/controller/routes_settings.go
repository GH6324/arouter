package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerSettingsRoutes(r *gin.Engine, db *gorm.DB) {
	// 全局系统设置（传输/压缩）读写接口
	r.GET("/api/settings", authUserMiddleware(db), func(c *gin.Context) {
		c.JSON(http.StatusOK, loadSettings(db))
	})
	r.POST("/api/settings", authUserMiddleware(db), func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var req Setting
		if err := c.BindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		maybeCheckpoint(db)
		var saved Setting
		err := db.Transaction(func(tx *gorm.DB) error {
			var s Setting
			if err := tx.First(&s).Error; err != nil {
				return err
			}
			if strings.TrimSpace(req.Transport) != "" {
				s.Transport = strings.TrimSpace(req.Transport)
			}
			if strings.TrimSpace(req.Compression) != "" {
				s.Compression = strings.TrimSpace(req.Compression)
			}
			if req.CompressionMin >= 0 {
				s.CompressionMin = req.CompressionMin
			}
			if req.MaxMuxStreams > 0 {
				s.MaxMuxStreams = req.MaxMuxStreams
			}
			s.DebugLog = req.DebugLog
			if req.EncryptionPolicies != nil {
				s.EncryptionPolicies = req.EncryptionPolicies.normalize()
			}
			if strings.TrimSpace(req.HTTPProbeURL) != "" {
				s.HTTPProbeURL = strings.TrimSpace(req.HTTPProbeURL)
			}
			if strings.TrimSpace(req.ReturnAckTimeout) != "" {
				s.ReturnAckTimeout = strings.TrimSpace(req.ReturnAckTimeout)
			}
			if err := tx.Save(&s).Error; err != nil {
				return err
			}
			saved = s
			return nil
		})
		if err != nil {
			if isSQLiteFull(err) {
				c.String(http.StatusInsufficientStorage, "写入失败：磁盘空间不足或 SQLite 无写权限，请清理空间或改用 MySQL。原始错误: %v", err)
				return
			}
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, saved)
	})
}
