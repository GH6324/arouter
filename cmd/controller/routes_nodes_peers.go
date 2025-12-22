package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerNodePeerRoutes(authGroup *gin.RouterGroup, db *gorm.DB) {
	authGroup.POST("/nodes/:id/peers", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Peer
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		req.NodeID = node.ID
		if err := db.Create(&req).Error; err != nil {
			c.String(http.StatusBadRequest, "create failed: %v", err)
			return
		}
		c.JSON(http.StatusCreated, req)
	})
	authGroup.POST("/nodes/:id/peers/auto", func(c *gin.Context) {
		id := c.Param("id")
		var node Node
		if err := db.Preload("Routes").Preload("Peers").First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var allNodes []Node
		db.Find(&allNodes)
		var allRoutes []RoutePlan
		db.Find(&allRoutes)
		pubMap := make(map[string][]string, len(allNodes))
		selfHasV6 := false
		for _, ip := range node.PublicIPs {
			if strings.Contains(ip, ":") {
				selfHasV6 = true
				break
			}
		}
		for _, n := range allNodes {
			if len(n.PublicIPs) > 0 {
				pubMap[n.Name] = n.PublicIPs
			}
		}
		neighbors := neighborsFromRoutes(node.Name, allRoutes)
		existing := make(map[string]*Peer, len(node.Peers))
		for i := range node.Peers {
			p := &node.Peers[i]
			existing[p.PeerName] = p
		}
		created := 0
		updated := 0
		for peerName := range neighbors {
			if peerName == "" || peerName == node.Name {
				continue
			}
			if cur, ok := existing[peerName]; ok {
				update := map[string]interface{}{}
				if cur.EntryIP == "" {
					entryIP := pickEntryIP(pubMap[peerName], selfHasV6)
					if entryIP != "" {
						update["entry_ip"] = entryIP
					}
				}
				if len(update) > 0 {
					if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", cur.ID, node.ID).Updates(update).Error; err == nil {
						updated++
					}
				}
				continue
			}
			entryIP := pickEntryIP(pubMap[peerName], selfHasV6)
			newPeer := Peer{
				NodeID:   node.ID,
				PeerName: peerName,
				EntryIP:  entryIP,
			}
			if err := db.Create(&newPeer).Error; err == nil {
				created++
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"created": created,
			"updated": updated,
		})
	})
	authGroup.POST("/peers/auto", func(c *gin.Context) {
		var nodes []Node
		db.Preload("Routes").Preload("Peers").Find(&nodes)
		var allNodes []Node
		db.Find(&allNodes)
		var allRoutes []RoutePlan
		db.Find(&allRoutes)
		pubMap := make(map[string][]string, len(allNodes))
		for _, n := range allNodes {
			if len(n.PublicIPs) > 0 {
				pubMap[n.Name] = n.PublicIPs
			}
		}
		created := 0
		updated := 0
		for i := range nodes {
			node := &nodes[i]
			selfHasV6 := false
			for _, ip := range node.PublicIPs {
				if strings.Contains(ip, ":") {
					selfHasV6 = true
					break
				}
			}
			neighbors := neighborsFromRoutes(node.Name, allRoutes)
			existing := make(map[string]*Peer, len(node.Peers))
			for i := range node.Peers {
				p := &node.Peers[i]
				existing[p.PeerName] = p
			}
			for peerName := range neighbors {
				if peerName == "" || peerName == node.Name {
					continue
				}
				if cur, ok := existing[peerName]; ok {
					if cur.EntryIP == "" {
						entryIP := pickEntryIP(pubMap[peerName], selfHasV6)
						if entryIP != "" {
							if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", cur.ID, node.ID).Updates(map[string]interface{}{
								"entry_ip": entryIP,
							}).Error; err == nil {
								updated++
							}
						}
					}
					continue
				}
				entryIP := pickEntryIP(pubMap[peerName], selfHasV6)
				newPeer := Peer{
					NodeID:   node.ID,
					PeerName: peerName,
					EntryIP:  entryIP,
				}
				if err := db.Create(&newPeer).Error; err == nil {
					created++
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"created": created,
			"updated": updated,
		})
	})
	authGroup.PUT("/nodes/:id/peers/:peerId", func(c *gin.Context) {
		id := c.Param("id")
		pid := c.Param("peerId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		var req Peer
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, "bad request: %v", err)
			return
		}
		if err := db.Model(&Peer{}).Where("id = ? AND node_id = ?", pid, id).Updates(map[string]interface{}{
			"peer_name": req.PeerName,
			"entry_ip":  req.EntryIP,
			"exit_ip":   req.ExitIP,
			"endpoint":  req.Endpoint,
		}).Error; err != nil {
			c.String(http.StatusBadRequest, "update failed: %v", err)
			return
		}
		var peer Peer
		db.First(&peer, pid)
		c.JSON(http.StatusOK, peer)
	})
	authGroup.DELETE("/nodes/:id/peers/:peerId", func(c *gin.Context) {
		id := c.Param("id")
		pid := c.Param("peerId")
		var node Node
		if err := db.First(&node, id).Error; err != nil {
			c.String(http.StatusNotFound, "not found")
			return
		}
		if err := db.Delete(&Peer{}, "id = ? AND node_id = ?", pid, id).Error; err != nil {
			c.String(http.StatusBadRequest, "delete failed: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})
}
