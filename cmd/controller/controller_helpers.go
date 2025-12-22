package main

import (
	"log"
	"strings"

	"gorm.io/gorm"
)

func stripPortPrefix(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, ":") {
		s = strings.TrimPrefix(s, ":")
	}
	return s
}

func normalizeNodePorts(n *Node) (changed bool) {
	norm := func(v string) (string, bool) {
		nv := stripPortPrefix(v)
		return nv, nv != v
	}
	if nv, diff := norm(n.WSListen); diff {
		n.WSListen = nv
		changed = true
	}
	if nv, diff := norm(n.WSSListen); diff {
		n.WSSListen = nv
		changed = true
	}
	if nv, diff := norm(n.MetricsListen); diff {
		n.MetricsListen = nv
		changed = true
	}
	if nv, diff := norm(n.QUICListen); diff {
		n.QUICListen = nv
		changed = true
	}
	return
}

func normalizeEntriesPorts(entries []Entry) (changed bool) {
	for i := range entries {
		nv := stripPortPrefix(entries[i].Listen)
		if nv != entries[i].Listen {
			entries[i].Listen = nv
			changed = true
		}
	}
	return
}

// applyOSOverrides 根据 os hint（例如 darwin）调整默认路径，便于节点在不同平台使用合适的目录。
func applyOSOverrides(cfg ConfigResponse, osHint string) ConfigResponse {
	if osHint == "darwin" {
		if strings.HasPrefix(cfg.MTLSCert, "/opt/arouter/") {
			cfg.MTLSCert = strings.Replace(cfg.MTLSCert, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if strings.HasPrefix(cfg.MTLSKey, "/opt/arouter/") {
			cfg.MTLSKey = strings.Replace(cfg.MTLSKey, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if strings.HasPrefix(cfg.MTLSCA, "/opt/arouter/") {
			cfg.MTLSCA = strings.Replace(cfg.MTLSCA, "/opt/arouter", "${HOME}/.arouter", 1)
		}
		if cfg.TokenPath == "" || strings.HasPrefix(cfg.TokenPath, "/opt/arouter/") {
			cfg.TokenPath = strings.Replace("/opt/arouter/.token", "/opt/arouter", "${HOME}/.arouter", 1)
		}
	}
	return cfg
}

func applyInstallDirOverrides(cfg ConfigResponse, installDir string) ConfigResponse {
	if installDir == "" {
		return cfg
	}
	replacePath := func(v string) string {
		if v == "" {
			return v
		}
		if strings.Contains(v, "${HOME}") {
			return strings.ReplaceAll(v, "${HOME}", installDir)
		}
		if strings.HasPrefix(v, "/opt/arouter") {
			return strings.Replace(v, "/opt/arouter", installDir, 1)
		}
		return v
	}
	cfg.MTLSCert = replacePath(cfg.MTLSCert)
	cfg.MTLSKey = replacePath(cfg.MTLSKey)
	cfg.MTLSCA = replacePath(cfg.MTLSCA)
	cfg.TokenPath = replacePath(cfg.TokenPath)
	return cfg
}

func normalizeStoredPorts(db *gorm.DB) {
	var nodes []Node
	if err := db.Preload("Entries").Find(&nodes).Error; err != nil {
		log.Printf("normalize ports skipped: %v", err)
		return
	}
	for i := range nodes {
		nodeChanged := normalizeNodePorts(&nodes[i])
		entryChanged := normalizeEntriesPorts(nodes[i].Entries)
		if nodeChanged {
			db.Model(&nodes[i]).Updates(map[string]interface{}{
				"ws_listen":      nodes[i].WSListen,
				"wss_listen":     nodes[i].WSSListen,
				"metrics_listen": nodes[i].MetricsListen,
				"quic_listen":    nodes[i].QUICListen,
			})
		}
		if entryChanged {
			for _, e := range nodes[i].Entries {
				db.Model(&Entry{}).Where("id = ?", e.ID).Update("listen", e.Listen)
			}
		}
	}
}
