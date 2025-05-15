package server

import (
	"my-project/internal/handler"
	"my-project/internal/middleware"
	"my-project/internal/validation"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"}, // Add your frontend URL
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true, // Enable cookies/auth
	}))

	r.GET("/", s.HelloWorldHandler)

	r.GET("/health", s.healthHandler)

	//all routes for v1
	v1 := r.Group("/api/v1")
	{
		// Initialize handlers
		authHandler := handler.NewAuthHandler(s.db)
		userHandler := handler.NewUserHandler(s.db)

		// Auth routes
		auth := v1.Group("/auth")
		{
			auth.GET("/", authHandler.HelloAuth)
			auth.POST("/signup", middleware.ValidateRequest(&validation.SignUpRequest{}, validator.New()), authHandler.SignUp)
			auth.PUT("/verify-email/:token", authHandler.VerifyEmail)
			auth.POST("/signin", authHandler.SignIn)
		}

		// User routes
		user := v1.Group("/user")
		{
			user.GET("/", userHandler.HelloUser)
		}
	}

	//This route will catch the error if user hits a route that does not exist in our api.
	r.NoRoute(noRouteHandler)

	return r
}

func (s *Server) HelloWorldHandler(c *gin.Context) {
	resp := make(map[string]string)
	resp["message"] = "Hello! Welcome to GoLang API"

	c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, s.db.Health())
}
func noRouteHandler(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"message": "Api not found!!! Wrong url, there is no route in this url."})
}
