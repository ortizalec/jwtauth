package db

import (
	"database/sql"

	"github.com/charmbracelet/log"
	"github.com/ortizalec/jwtauth/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(f string) (*sql.DB, error) {
	log.Info("Init DB")
	var err error
	DB, err = gorm.Open(sqlite.Open(f), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	DB.AutoMigrate(&models.User{})

	return DB.DB()

}
