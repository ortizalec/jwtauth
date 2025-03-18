package db

import (
	"database/sql"

	"github.com/charmbracelet/log"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB(f string) {
	var err error
	DB, err = sql.Open("sqlite3", f)
	if err != nil {
		log.Error("Failed to connect to database:", err)
	}

	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);`

	_, err = DB.Exec(createTableSQL)
	if err != nil {
		log.Error("Failed to create users table:", err)
	}

	log.Info("Database initialized successfully")
}
