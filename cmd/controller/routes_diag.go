package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func registerDiagRoutes(authGroup *gin.RouterGroup, db *gorm.DB, hub *wsHub) {
	registerDiagTraceRoutes(authGroup, db, hub)
	registerDiagCollectRoutes(authGroup, db, hub)
	registerDiagCheckRoutes(authGroup, db, hub)
}
