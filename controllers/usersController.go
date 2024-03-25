package controllers

import (
	"auth_jwt/initializers"
	"auth_jwt/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	//Get email and pass off req body
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	//hash the pass
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	//Create the user
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	//Respond
	c.JSON(http.StatusOK, gin.H{})

}

func Login(c *gin.Context) {

	//Get email and pass off req body
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	//look up requested user
	var user models.User
	initializers.DB.First(&user, "email = ? ", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email ",
		})
		return
	}

	//compare sent in pass
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid password",
		})
		return
	}

	tokenString, err := GenerateToken(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})

}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func GenerateToken(user models.User) (string, error) {
	// Criar o token com as reivindicações necessárias
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour).Unix(), // Token expira em 1 hora
	})

	// Assinar o token usando a chave secreta e retornar o token assinado
	return token.SignedString([]byte(os.Getenv("SECRET")))
}

//generate a jwt token

// token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 	"sub": user.ID,
// 	"exp": time.Now().Add(time.Hour).Unix(), //time.Now().Add(time.Hour * 24 * 30).Unix(),
// })

// // Sign and get the complete encoded token as a string using the secret
// tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

// if err != nil {
// 	c.JSON(http.StatusBadRequest, gin.H{
// 		"error": "Faild to create token",
// 	})
// 	return
// }

// c.JSON(http.StatusOK, gin.H{
// 	"token": tokenString,
// })

// fmt.Println(tokenString, err)
