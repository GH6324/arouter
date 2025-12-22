package main

import (
	"log"
	"strings"

	"gorm.io/gorm"
)

// ensureGlobalSettings 确保全局设置存在（单行），默认从环境获取或使用内置值。
func ensureGlobalSettings(db *gorm.DB) {
	var cnt int64
	if err := db.Model(&Setting{}).Count(&cnt).Error; err != nil {
		log.Printf("count settings failed: %v", err)
		return
	}
	if cnt == 0 {
		def := Setting{
			Transport:        envOrDefault("GLOBAL_TRANSPORT", "quic"),
			Compression:      envOrDefault("GLOBAL_COMPRESSION", "none"),
			CompressionMin:   0,
			MaxMuxStreams:    defaultIntFromEnv("GLOBAL_MAX_MUX_STREAMS", 4),
			DebugLog:         false,
			HTTPProbeURL:     envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204"),
			ReturnAckTimeout: envOrDefault("GLOBAL_RETURN_ACK_TIMEOUT", "10s"),
			EncryptionPolicies: EncPolicyList{
				{ID: 1, Name: "aes128", Method: "aes-128-gcm", Key: "YWFhYWFhYWFhYWFhYWFhYQ=="},
				{ID: 2, Name: "chacha", Method: "chacha20-poly1305", Key: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="},
			},
		}
		def.EncryptionPolicies = def.EncryptionPolicies.normalize()
		if err := db.Create(&def).Error; err != nil {
			log.Printf("create default settings failed: %v", err)
		} else {
			log.Printf("created default global settings: %+v", def)
		}
	}
}

func loadSettings(db *gorm.DB) Setting {
	var s Setting
	if err := db.First(&s).Error; err != nil {
		log.Printf("load settings failed, using defaults: %v", err)
		return Setting{
			Transport:        envOrDefault("GLOBAL_TRANSPORT", "quic"),
			Compression:      envOrDefault("GLOBAL_COMPRESSION", "none"),
			CompressionMin:   0,
			MaxMuxStreams:    defaultIntFromEnv("GLOBAL_MAX_MUX_STREAMS", 4),
			DebugLog:         false,
			HTTPProbeURL:     envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204"),
			ReturnAckTimeout: envOrDefault("GLOBAL_RETURN_ACK_TIMEOUT", "10s"),
			EncryptionPolicies: EncPolicyList{
				{ID: 1, Name: "aes128", Method: "aes-128-gcm", Key: "YWFhYWFhYWFhYWFhYWFhYQ=="},
			}.normalize(),
		}
	}
	if strings.TrimSpace(s.HTTPProbeURL) == "" {
		s.HTTPProbeURL = envOrDefault("GLOBAL_HTTP_PROBE_URL", "https://www.google.com/generate_204")
	}
	if strings.TrimSpace(s.ReturnAckTimeout) == "" {
		s.ReturnAckTimeout = envOrDefault("GLOBAL_RETURN_ACK_TIMEOUT", "10s")
	}
	if s.MaxMuxStreams <= 0 {
		s.MaxMuxStreams = defaultIntFromEnv("GLOBAL_MAX_MUX_STREAMS", 4)
	}
	if len(s.EncryptionPolicies) == 0 {
		s.EncryptionPolicies = EncPolicyList{
			{ID: 1, Name: "aes128", Method: "aes-128-gcm", Key: "YWFhYWFhYWFhYWFhYWFhYQ=="},
		}.normalize()
	}
	s.EncryptionPolicies = s.EncryptionPolicies.normalize()
	return s
}
