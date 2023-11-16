package main

import (
	"AppLogin/models"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var secretKey = []byte("secret-key")

func main() {
	r := gin.Default()

	// Route untuk login pengguna
	r.POST("/login/user", userLoginHandler)

	// Route untuk login karyawan
	r.POST("/login/employee", employeeLoginHandler)

	// Route yang memerlukan otentikasi pengguna
	r.GET("/protected/user", authenticateUserToken, protectedUserHandler)

	// Route yang memerlukan otentikasi karyawan
	// r.GET("/protected/employee", authenticateEmployeeToken, protectedEmployeeHandler)

	// Jalankan server
	r.Run(":3000")
}

func userLoginHandler(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if user.Username == "user" && user.Password == "password" {
		token := generateToken(user.Username)
		c.JSON(http.StatusOK, gin.H{"token": token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func employeeLoginHandler(c *gin.Context) {
	var employee models.Employee
	if err := c.ShouldBindJSON(&employee); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if employee.Username == "employee" && employee.Password == "password" {
		token := generateToken(employee.Username)
		c.JSON(http.StatusOK, gin.H{"token": token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func protectedUserHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Protected user resource"})
}

// func protectedEmployeeHandler(c *gin.Context) {
// 	c.JSON(http.StatusOK, gin.H{"message": "Protected employee resource"})
// }

// Fungsi middleware untuk memeriksa token pengguna
func authenticateUserToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	tokenString = extractTokenFromHeader(tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
		c.Abort()
		return
	}

	// Dapatkan klaim-klaim dari token
	claims, ok := token.Claims.(*models.UserClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		c.Abort()
		return
	}

	// Mengakses nilai klaim tertentu (username)
	// usernameClaim, usernameExists := (*claims)["username"]
	// if !usernameExists {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
	// 	c.Abort()
	// 	return
	// }

	// Periksa tipe data dan konversi ke string
	username := claims.Username
	if username == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		c.Abort()
		return
	}

	// Sekarang, Anda dapat menggunakan nilai username
	fmt.Println("username:", username)

	c.Next()
}

func extractTokenFromHeader(authHeader string) string {
	parts := strings.Split(authHeader, "")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

// Fungsi middleware untuk memeriksa token karyawan
// func authenticateEmployeeToken(c *gin.Context) {
// 	tokenString := c.GetHeader("Authorization")
// 	if tokenString == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
// 		c.Abort()
// 		return
// 	}

// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		return secretKey, nil
// 	})

// 	if err != nil || !token.Valid {
// 		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
// 		c.Abort()
// 		return
// 	}

// 	c.Next()
// }

// Fungsi untuk menghasilkan token
func generateToken(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // Token berlaku selama 1 jam
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error generating token:", err)
	}

	return tokenString
}
