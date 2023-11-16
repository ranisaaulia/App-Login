package models

import "github.com/golang-jwt/jwt"

// Struktur data pengguna
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Struktur data karyawan
type Employee struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
