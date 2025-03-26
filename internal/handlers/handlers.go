package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ortizalec/jwtauth/internal/db"
	"github.com/ortizalec/jwtauth/internal/models"
	"github.com/ortizalec/jwtauth/internal/routes"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func generateJWT(u models.User) (string, error) {
	claims := jwt.MapClaims{
		"id":    u.ID,
		"email": u.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // token expires in 24h
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func verifyJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Make sure the signing method is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	log.Info(routes.SignIn)
	var requestData routes.SignInRequest

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if requestData.Email == "" || requestData.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	var user models.User
	result := db.DB.Where(&models.User{Email: requestData.Email}).Limit(1).Find(&user)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestData.Password))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	t, err := generateJWT(user)
	if err != nil {
		panic(err)
	}

	responseData := routes.SignInResponse{Message: "sign in successful"}
	w.Header().Set("Content-Type", "application/json")
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    t,
		HttpOnly: true,  // Prevent frontend JS from accessing it
		Secure:   false, // Only send over HTTPS
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(time.Hour * 24),
		Path:     "/",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseData)
}

func Heartbeat(w http.ResponseWriter, r *http.Request) {
	log.Info(routes.Heartbeat)
	data := routes.HeartbeatResponse{Timestamp: time.Now(), Status: "healthy"}
	w.Header().Set("Content-Type", "apllication/json")
	w.WriteHeader((http.StatusOK))
	json.NewEncoder(w).Encode(data)
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	log.Info(routes.SignUp)
	var requestData routes.SignUpRequest

	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if requestData.Email == "" || requestData.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := models.User{Email: requestData.Email, Password: string(hashedPassword)}
	if db.DB == nil {
		log.Error("db is nil")
	}
	result := db.DB.Create(&user)

	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	responseData := routes.SignUpResponse{ID: user.ID}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(responseData)
}

func SignOut(w http.ResponseWriter, r *http.Request) {
	log.Info(routes.SignOut)
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
