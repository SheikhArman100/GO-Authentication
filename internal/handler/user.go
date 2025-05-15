package handler

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "my-project/internal/database"
)

type UserHandler struct {
    db database.Service
}

func NewUserHandler(db database.Service) *UserHandler {
    return &UserHandler{db: db}
}

func (h *UserHandler) HelloUser(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Hello from user group"})
}