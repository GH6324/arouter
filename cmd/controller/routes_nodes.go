package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerNodeRoutes(api *gin.RouterGroup, authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	registerNodeCoreRoutes(authGroup, db, hub)
	registerNodeEntryRoutes(authGroup, db)
	registerNodePeerRoutes(authGroup, db)
	registerNodeRouteRoutes(api, authGroup, db)
	registerNodeMiscRoutes(authGroup, db)
	registerNodeDeleteRoutes(authGroup, db, hub)
}
