package routes

import (
	"time"
)

const (
	Heartbeat = "GET /api/auth/heartbeat"
	SignIn    = "POST /api/auth/signin"
	SignUp    = "POST /api/auth/signup"
	SignOut   = "POST /api/auth/signout"
	Validate  = "POST /api/auth/validate"
	Parse     = "POST /api/auth/parse"
)

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResponse struct {
	Message string `json:"msg"`
}

type HeartbeatResponse struct {
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignUpResponse struct {
	Message string `json:"message"`
}

type SignOutResponse struct {
	Message string `json:"message"`
}

type ValidateRequest struct {
	Token string `json:"token"`
}

type ValidateResponse struct {
	IsValid bool `json:"is_valid"`
}

type ParseRequest struct {
	Token string `json:"token"`
}

type ParseResponse struct {
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}
