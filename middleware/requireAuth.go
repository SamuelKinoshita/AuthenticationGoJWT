package middleware

import (
	"auth_jwt/controllers"
	"auth_jwt/initializers"
	"auth_jwt/models"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var user models.User

func RequireAuth(c *gin.Context) {
	//get the cookie off req
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode/validae it
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de assinatura inesperado: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		log.Fatal(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Verificar se o token está próximo da expiração
		expTime := time.Unix(int64(claims["exp"].(float64)), 0)
		if time.Until(expTime) > 30*time.Second {
			// Gerar um novo token
			// Nota: Aqui você precisa ter uma função GenerateToken implementada em controllers.
			initializers.DB.First(&user, claims["sub"])
			newTokenString, err := controllers.GenerateToken(user)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			// Enviar o novo token para o cliente no cabeçalho da resposta
			c.Header("Authorization", newTokenString)
			// c.SetSameSite(http.SameSiteLaxMode)
			// c.SetCookie("Authorization", tokenString, 3600, "", "", false, true)
		}

		// Anexar as reivindicações ao contexto e continuar
		c.Set("user", user)
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// if claims, ok := token.Claims.(jwt.MapClaims); ok {

	// 	//Check the exp
	// 	if float64(time.Now().Unix()) > claims["exp"].(float64) {
	// 		c.AbortWithStatus(http.StatusUnauthorized)
	// 	}

	// 	// Find the user with token sub
	// 	var user models.User
	// 	initializers.DB.First(&user, claims["sub"])

	// 	if user.ID == 0 {
	// 		c.AbortWithStatus(http.StatusUnauthorized)
	// 	}
	// 	// Attach to req
	// 	c.Set("user", user)
	// 	// Cotinue
	// 	c.Next()
	// } else {
	// 	c.AbortWithStatus(http.StatusUnauthorized)
	// }

}
