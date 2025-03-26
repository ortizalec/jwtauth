package main

import (
	"flag"
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/ortizalec/jwtauth/internal/db"
	"github.com/ortizalec/jwtauth/internal/handlers"
	"github.com/ortizalec/jwtauth/internal/routes"
	"github.com/rs/cors"
)

type config struct {
	addr        string
	sqlitefile  string
	version     string
	servicename string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.addr, "addr", ":3001", "HTTP network address")
	flag.StringVar(&cfg.sqlitefile, "sqlfile", "users.db", "Sqlite3 Database File")
	cfg.servicename = "jwtauth"
	cfg.version = "1.0.0"
	flag.Parse()

	log.Info("launching service",
		"name", cfg.servicename,
		"addr", cfg.addr,
		"db", cfg.sqlitefile,
		"version", cfg.version)

	sqldb, err := db.InitDB(cfg.sqlitefile)
	if err != nil {
		panic("failed to get db")
	}
	defer sqldb.Close()

	mux := http.NewServeMux()

	mux.HandleFunc(routes.Heartbeat, handlers.Heartbeat)
	mux.HandleFunc(routes.SignIn, handlers.SignIn)
	mux.HandleFunc(routes.SignUp, handlers.SignUp)
	mux.HandleFunc(routes.SignOut, handlers.SignOut)

	// Apply CORS Middleware
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"}, // Allow frontend
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}).Handler(mux)

	log.Error(http.ListenAndServe(*&cfg.addr, handler))
}
