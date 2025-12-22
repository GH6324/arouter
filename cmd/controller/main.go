package main

import (
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	db := mustOpenDB()
	maybeCheckpoint(db)
	auth := NewGlobalAuth(envOrDefault("AUTH_KEY_FILE", "/app/data/auth.key"))
	globalKey = auth.LoadOrCreate()
	buildVersion = canonicalVersion(buildVersion)
	if err := db.AutoMigrate(&Node{}, &Entry{}, &Peer{}, &LinkMetric{}, &RoutePlan{}, &Setting{}, &User{}, &RouteProbe{}, &ReturnRouteStatus{}, &NodeUpdateStatus{}, &NodeUninstallStatus{}); err != nil {
		log.Fatalf("migrate failed: %v", err)
	}
	ensureColumns(db)
	normalizeStoredPorts(db)
	ensureGlobalSettings(db)
	jwtSecret = []byte(envOrDefault("JWT_SECRET", randomKey()))
	log.Printf("arouter controller version %s", buildVersion)

	r := gin.Default()
	enableCors := strings.ToLower(envOrDefault("ENABLE_CORS", "true"))
	if enableCors == "true" || enableCors == "1" || enableCors == "yes" {
		r.Use(func(c *gin.Context) {
			w := c.Writer
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			h.Set("Access-Control-Max-Age", "86400")
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		})
	}
	hub := newWSHub()

	distDir := envOrDefault("WEB_DIST", "cmd/controller/web/dist")
	if info, err := os.Stat(distDir); err == nil && info.IsDir() {
		indexFile := filepath.Join(distDir, "index.html")
		if _, err := os.Stat(indexFile); err == nil {
			log.Printf("serving static front-end from %s", distDir)
			assetsDir := filepath.Join(distDir, "assets")
			if _, err := os.Stat(assetsDir); err == nil {
				r.Static("/assets", assetsDir)
			}
			r.StaticFile("/favicon.ico", filepath.Join(distDir, "favicon.ico"))
			r.GET("/", func(c *gin.Context) {
				c.File(indexFile)
			})
			r.NoRoute(func(c *gin.Context) {
				if strings.HasPrefix(c.Request.URL.Path, "/api/") {
					c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
					return
				}
				// try to serve existing file
				path := filepath.Clean(c.Request.URL.Path)
				fpath := filepath.Join(distDir, path)
				if info, err := os.Stat(fpath); err == nil && !info.IsDir() {
					c.File(fpath)
					return
				}
				// fallback to SPA entry
				c.File(indexFile)
			})
		} else {
			log.Printf("WEB_DIST=%s exists but missing index.html, fallback to embedded assets", distDir)
			if sub, err := fs.Sub(embeddedWeb, "web/dist"); err == nil {
				efs := http.FS(sub)
				r.GET("/", func(c *gin.Context) {
					c.FileFromFS("index.html", efs)
				})
				r.NoRoute(func(c *gin.Context) {
					if strings.HasPrefix(c.Request.URL.Path, "/api/") {
						c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
						return
					}
					path := strings.TrimPrefix(filepath.Clean(c.Request.URL.Path), "/")
					if path == "" {
						path = "index.html"
					}
					if _, err := sub.Open(path); err == nil {
						c.FileFromFS(path, efs)
						return
					}
					c.FileFromFS("index.html", efs)
				})
			}
		}
	} else if sub, err := fs.Sub(embeddedWeb, "web/dist"); err == nil {
		log.Printf("serving embedded static front-end")
		efs := http.FS(sub)
		r.GET("/", func(c *gin.Context) {
			c.FileFromFS("index.html", efs)
		})
		r.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			path := strings.TrimPrefix(filepath.Clean(c.Request.URL.Path), "/")
			if path == "" {
				path = "index.html"
			}
			// try direct file (assets/...)
			if _, err := sub.Open(path); err == nil {
				c.FileFromFS(path, efs)
				return
			}
			// fallback SPA
			c.FileFromFS("index.html", efs)
		})
	} else {
		log.Printf("static front-end not found (%s), please build React front-end into this path", distDir)
		r.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Front-end not found. Build React app and set WEB_DIST to its dist directory.")
		})
	}

	registerPublicRoutes(r)

	api := r.Group("/api")
	authGroup := api.Group("")
	authGroup.Use(authUserMiddleware(db))
	registerAuthRoutes(api, authGroup, db)

	registerNodeRoutes(api, authGroup, db, hub)
	registerHostRoutes(api, db)
	registerMetricsRoutes(api, authGroup, db)
	registerDiagRoutes(authGroup, db, hub)
	registerWSRoutes(api, db, hub)
	registerConfigPublicRoutes(r, db)
	registerSettingsRoutes(r, db)

	addr := envOrDefault("CONTROLLER_ADDR", ":8080")
	log.Printf("controller listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("controller run failed: %v", err)
	}
}
