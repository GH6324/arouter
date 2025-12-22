package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func generateToken() string {
	b := make([]byte, 16)
	_, _ = time.Now().UTC().MarshalBinary()
	for i := range b {
		b[i] = byte(65 + i)
	}
	return fmt.Sprintf("tok-%d", time.Now().UnixNano())
}

func ensureNodeToken(db *gorm.DB, n *Node) {
	if n.Token == "" {
		n.Token = generateToken()
		db.Model(&Node{}).Where("id = ?", n.ID).Update("token", n.Token)
	}
}

func ensureAdminExists(db *gorm.DB, username, password string) {
	var cnt int64
	db.Model(&User{}).Count(&cnt)
	if cnt == 0 && username != "" && password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		db.Create(&User{Username: username, PasswordHash: string(hash), IsAdmin: true})
	}
}

func issueJWT(u User) (string, error) {
	claims := UserClaims{UserID: u.ID, IsAdmin: u.IsAdmin}
	b, _ := json.Marshal(claims)
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write(b)
	sig := mac.Sum(nil)
	return fmt.Sprintf("%s.%x", b, sig), nil
}

func parseJWT(token string) (*UserClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token")
	}
	b := []byte(parts[0])
	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write(b)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, fmt.Errorf("invalid signature")
	}
	var claims UserClaims
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func authUserMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := parseJWT(token)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var user User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

func requireAdmin(c *gin.Context) {
	uVal, ok := c.Get("user")
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	u := uVal.(User)
	if !u.IsAdmin {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
}

func getBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
