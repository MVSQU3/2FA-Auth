package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func ValidationJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"Error": "Token manqant"})
			c.Abort()
			return
		}
		fmt.Printf("log de token %s", token)
		tokenString := strings.TrimPrefix(token, "Bearer ")
		if tokenString == token {
			c.JSON(http.StatusBadRequest, gin.H{"Error": "Format invalide"})
			c.Abort()
			return
		}

		authHeader, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Méthode de signature invalide")
			}
			return []byte(os.Getenv("SECRET_JWT")), nil
		})

		if err != nil || !authHeader.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		if claims, ok := authHeader.Claims.(jwt.MapClaims); ok && authHeader.Valid {
			c.Set("email", claims["email"])
			c.Set("userId", claims["id"])
			c.Set("exp", claims["exp"])
		}

	}
}
