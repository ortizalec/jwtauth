package main

import (
	"flag"
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/ortizalec/papersplease/internal/db"
	"github.com/ortizalec/papersplease/internal/handlers"
	"github.com/ortizalec/papersplease/internal/routes"
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
	cfg.servicename = "papersplease"
	cfg.version = "1.0.0"
	flag.Parse()

	log.Info("launching service",
		"name", cfg.servicename,
		"addr", cfg.addr,
		"db", cfg.sqlitefile,
		"version", cfg.version)

	db.InitDB(cfg.sqlitefile)
	defer db.DB.Close()

	mux := http.NewServeMux()

	mux.HandleFunc(routes.Heartbeat, handlers.Heartbeat)
	mux.HandleFunc(routes.SignIn, handlers.SignIn)
	mux.HandleFunc(routes.SignUp, handlers.SignUp)
	mux.HandleFunc(routes.SignOut, handlers.SignOut)
	mux.HandleFunc(routes.Validate, handlers.Validate)
	mux.HandleFunc(routes.Parse, handlers.Parse)

	// Apply CORS Middleware
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"}, // Allow frontend
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}).Handler(mux)

	log.Error(http.ListenAndServe(*&cfg.addr, handler))
}
