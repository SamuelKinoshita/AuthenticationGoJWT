package main

import (
	"auth_jwt/controllers"
	"auth_jwt/initializers"
	"auth_jwt/middleware"
	"os"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariabls()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Define um valor padrão caso a variável PORT não esteja definida
	}

	r.Run(":" + port)

}
