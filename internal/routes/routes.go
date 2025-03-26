package routes

import (
	"time"
)

const (
	Heartbeat = "GET /api/auth/heartbeat"
	SignIn    = "POST /api/auth/signin"
	SignUp    = "POST /api/auth/signup"
	SignOut   = "POST /api/auth/signout"
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
	ID uint `json:"id"`
}

type SignOutResponse struct {
	Message string `json:"message"`
}
