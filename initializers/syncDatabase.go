package initializers

import "auth_jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
