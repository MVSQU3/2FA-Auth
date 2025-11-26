package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateTokenJWT(email string, id int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"userId": id,
		"exp":   time.Now().Add(time.Hour * 10).Unix(),
	})
	return token.SignedString([]byte(os.Getenv("SECRET_JWT")))
}
