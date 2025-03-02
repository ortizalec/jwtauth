package main

import (
	"net/http"

	"github.com/charmbracelet/log"
	"github.com/ortizalec/papersplease/internal/db"
	"github.com/ortizalec/papersplease/internal/handlers"
	"github.com/ortizalec/papersplease/internal/routes"
	"github.com/rs/cors"
)

func main() {
	db.InitDB()
	defer db.DB.Close()

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

	log.Info("Starting papersplease :3001")
	log.Error(http.ListenAndServe(":3001", handler))
}
