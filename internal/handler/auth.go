package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"my-project/internal/database"
	"my-project/internal/helper"
	"my-project/internal/model"
	"my-project/internal/response"
	"my-project/internal/validation"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type SignInRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type AuthHandler struct {
	db database.Service
}

func NewAuthHandler(db database.Service) *AuthHandler {
	return &AuthHandler{db: db}
}

// HelloAuth handles the GET request for auth root endpoint
func (h *AuthHandler) HelloAuth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Hello from auth group"})
}

// SignUp handles user registration
func (h *AuthHandler) SignUp(c *gin.Context) {
	// Get validated schema from context
	validated, exists := c.Get("validated")
	if !exists {
		response.ApiError(c, http.StatusInternalServerError, "Validation data missing")
		return
	}
	req, ok := validated.(*validation.SignUpRequest)
	if !ok {
		response.ApiError(c, http.StatusInternalServerError, "Invalid validation data")
		return
	}

	// Check for existing user
	var existingUser model.User
	if err := h.db.DB().Where("email = ? OR phone_number = ?", req.Email, req.PhoneNumber).First(&existingUser).Error; err == nil {
		response.ApiError(c, http.StatusUnprocessableEntity, "Email or PhoneNumber already exists")
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		response.ApiError(c, http.StatusInternalServerError, "Failed to hash password", err.Error())
		return
	}

	// Create a new user
	user := &model.User{
		Name:        req.Name,
		Email:       req.Email,
		PhoneNumber: req.PhoneNumber,
		Password:    string(hashedPassword),
	}

	if err := h.db.DB().Create(user).Error; err != nil {
		response.ApiError(c, http.StatusInternalServerError, "Failed to registered new user", err.Error())
		return
	}

	// Generate email verification token
	expiresInStr := os.Getenv("JWT_EMAIL_VERIFY_EXPIRES_IN")
	expiresIn, err := strconv.ParseInt(expiresInStr, 10, 64)
	if err != nil {
		response.ApiError(c, http.StatusInternalServerError, "Invalid JWT_EMAIL_VERIFY_EXPIRES_IN value", err.Error())
		return
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(time.Second * time.Duration(expiresIn)).Unix(),
	}).SignedString([]byte(os.Getenv("JWT_VERIFY_EMAIL_SECRET")))
	if err != nil {
		response.ApiError(c, http.StatusInternalServerError, "Failed to generate verification token", err.Error())
		return
	}

	//Send verification email
	clientURL := os.Getenv("ADMIN_CLIENT_URL")
	emailBody := fmt.Sprintf(`
		<div>
			<p>Hi, %s</p>
			<p>Welcome to E-Commerce! Please verify your email address by clicking the link below:</p>
			<p>
				<a href="%s/auth/verify-email?token=%s">
					Verify Email
				</a>
			</p>
			<p>This link will expire soon.</p>
			<p>If you didn't create this account, you can ignore this email.</p>
			<p>Thank you, <br> E-Commerce</p>
		</div>`,
		user.Name, clientURL, token)

	if err := helper.SendEmail(user.Email, emailBody, "Verify Your Email"); err != nil {
		// response.ApiError(c, http.StatusInternalServerError, "Failed to send verification email", err.Error())
		// return
		log.Print("Failed to send verification email", err.Error())
	}

	// Send success response
	response.SendResponse(c, http.StatusCreated, true, "User registered successfully", struct {
		ID uint `json:"id"`
	}{
		ID: user.ID,
	}, nil)
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Param("token")

	if token == "" {
		response.ApiError(c, http.StatusBadRequest, "Verification token is required")
		return
	}

	// Parse and validate the token
	claims := jwt.MapClaims{}
	t, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_VERIFY_EMAIL_SECRET")), nil
	})
	if err != nil || !t.Valid {

		response.ApiError(c, http.StatusBadRequest, "Invalid or expired verification token")
		return
	}

	// Extract user ID from the token
	idFloat, ok := claims["id"].(float64)
	if !ok {
		response.ApiError(c, http.StatusBadRequest, "Invalid token payload")
		return
	}
	userID := uint(idFloat)
	

	// Update user's email_verified_at field
	if err := h.db.DB().Model(&model.User{}).Where("id = ?", uint(userID)).Update("is_verified", true).Error; err != nil {
		response.ApiError(c, http.StatusInternalServerError, "Failed to verify email", err.Error())
		return
	}
	// Send success response
	response.SendResponse(c, http.StatusOK, true, "Email verified successfully", struct {
		ID uint `json:"id"`
	}{
		ID: userID,
	}, nil)
}

// SignIn handles user authentication
func (h *AuthHandler) SignIn(c *gin.Context) {
	var req SignInRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create a new user
	user := &model.User{
		Email:    req.Email,
		Password: req.Password,
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User signed in successfully",
		"email":   user.Email,
	})
}
