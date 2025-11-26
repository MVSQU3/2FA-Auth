package main

import (
	"auth-sys/controller"
	"auth-sys/db"
	"auth-sys/middleware"
	"auth-sys/repo"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Aucun fichier .env trouvé, utilisation des variables d'environnement système")
	}

	database := db.InitDb()
	defer database.Close()

	// Instancier le repo Auth
	authRepo := repo.NewAuthRepository(database)
	// Instancier le Controller Auth
	AuthCtrl := controller.NewAuthController(authRepo)

	r := gin.Default()

	// Activer CORS avec la configuration par défaut (autorise les méthodes courantes)
	r.Use(cors.Default())

	// Routes protégées (nécessitent JWT) Test routes
	auth := r.Group("/", middleware.ValidationJWT())
	auth.GET("/protect", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"message": "You are access in protected Road",
		})
	})

	// 2FA Routes
	auth.POST("/api/totp/setup", AuthCtrl.RequestTOTPSetup)
	auth.POST("/api/totp/confirm", AuthCtrl.ConfirmTOTP)
	auth.POST("/api/totp/disable", AuthCtrl.DisableTOTP)
	auth.POST("/api/totp/regenerate", AuthCtrl.RegenerateBackupCodes)

	// Connexion Routes
	r.POST("/api/register", AuthCtrl.Register)
	r.POST("/api/login", AuthCtrl.Login)

	r.Run()
}
