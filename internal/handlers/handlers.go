package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ortizalec/papersplease/internal/db"
	"github.com/ortizalec/papersplease/internal/routes"
	"golang.org/x/crypto/bcrypt"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResponse struct {
	Message string `json:"msg"`
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	log.Info("POST", "path", routes.SignIn)
	var requestData SignInRequest

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		log.Error("Invalid JSON", r.Body)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if requestData.Email == "" || requestData.Password == "" {
		log.Error("Email and password are required", requestData)
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Retrieve user from database
	var hashedPassword string
	err = db.DB.QueryRow("SELECT password FROM users WHERE email = ?", requestData.Email).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Error("Invalid email or password")
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		} else {
			log.Error("Database error", err)
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(requestData.Password))
	if err != nil {
		log.Error("Invalid email or password")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Load RSA private key
	key, err := LoadRSAKey("private-key.pem")
	if err != nil {
		log.Error("Failed to load RSA key", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create JWT token
	expiresin := time.Now().Add(time.Hour * 24)
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "papersplease",
		"email": requestData.Email,
		"exp":   expiresin.Unix(), // Token expires in 24 hours
	})

	// Sign token
	signedToken, err := t.SignedString(key)
	if err != nil {
		log.Error("Failed to sign token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send response
	responseData := SignInResponse{Message: "sign in successful"}
	w.Header().Set("Content-Type", "application/json")
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    signedToken,
		HttpOnly: true,  // Prevent frontend JS from accessing it
		Secure:   false, // Only send over HTTPS
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(time.Hour * 24),
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseData)
}

type HeartbeatResponse struct {
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

func Heartbeat(w http.ResponseWriter, r *http.Request) {
	log.Info("GET", "path", routes.Heartbeat)
	data := HeartbeatResponse{Timestamp: time.Now(), Status: "healthy"}
	w.Header().Set("Content-Type", "apllication/json")
	w.WriteHeader((http.StatusOK))
	json.NewEncoder(w).Encode(data)
}

type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignUpResponse struct {
	Message string `json:"message"`
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	log.Info("POST", "path", routes.SignUp)
	var requestData SignUpRequest

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if requestData.Email == "" || requestData.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Exec("INSERT INTO users (email, password) VALUES (?, ?)", requestData.Email, string(hashedPassword))
	if err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	responseData := SignUpResponse{Message: "User registered successfully"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(responseData)
}

type SignOutResponse struct {
	Message string `json:"message"`
}

func SignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Unix(0, 0), // Expire immediately
		HttpOnly: true,
		Path:     "/", // Ensure it covers all routes
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Signed out successfully"})
}

func LoadRSAKey(filename string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Error("Could not read file", "error", err)
		return nil, fmt.Errorf("could not read file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		log.Error("Could not decode PEM block")
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Info("Trying PKCS#8 format")
		pk8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Error("Could not parse RSA private key", "error", err)
			return nil, fmt.Errorf("could not parse RSA private key: %w", err)
		}
		return pk8Key.(*rsa.PrivateKey), nil
	}

	log.Info("Successfully loaded RSA key", "size", privateKey.Size())
	return privateKey, nil
}
