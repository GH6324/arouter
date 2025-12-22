package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func registerAuthRoutes(api *gin.RouterGroup, authGroup *gin.RouterGroup, db *gorm.DB) {
	authGroup.GET("/me", func(c *gin.Context) {
		u, _ := c.Get("user")
		c.JSON(http.StatusOK, u)
	})
	authGroup.GET("/users", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	})
	authGroup.POST("/users", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"is_admin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		if req.Username == "" || req.Password == "" {
			c.String(http.StatusBadRequest, "username/password required")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		user := User{Username: req.Username, PasswordHash: string(hash), IsAdmin: req.IsAdmin}
		if err := db.Create(&user).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusCreated, user)
	})
	authGroup.PUT("/users/:id", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		id := c.Param("id")
		var req struct {
			Password string `json:"password"`
			IsAdmin  *bool  `json:"is_admin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		updates := map[string]interface{}{}
		if req.Password != "" {
			hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			updates["password_hash"] = string(hash)
		}
		if req.IsAdmin != nil {
			updates["is_admin"] = *req.IsAdmin
		}
		if len(updates) == 0 {
			c.String(http.StatusBadRequest, "nothing to update")
			return
		}
		if err := db.Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})
	authGroup.DELETE("/users/:id", func(c *gin.Context) {
		requireAdmin(c)
		if c.IsAborted() {
			return
		}
		id := c.Param("id")
		if err := db.Delete(&User{}, "id = ?", id).Error; err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		c.Status(http.StatusNoContent)
	})
	// login
	api.POST("/login", func(c *gin.Context) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(http.StatusBadRequest, err.Error())
			return
		}
		var cnt int64
		db.Model(&User{}).Count(&cnt)
		if cnt == 0 {
			// 首个用户自动创建为管理员
			hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			user := User{Username: req.Username, PasswordHash: string(hash), IsAdmin: true}
			if err := db.Create(&user).Error; err != nil {
				c.String(http.StatusInternalServerError, err.Error())
				return
			}
			token, _ := issueJWT(user)
			c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
			return
		}
		var user User
		if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			c.String(http.StatusUnauthorized, "invalid credentials")
			return
		}
		token, _ := issueJWT(user)
		c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
	})
}
