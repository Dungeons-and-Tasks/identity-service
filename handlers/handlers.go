package handlers

import (
	"identity/config"
	"identity/handlers/middlewares"
	"net/http"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type handler struct {
	cfg *config.Config
	db  *gorm.DB
}

func MountHandlers(r *gin.Engine, cfg *config.Config, db *gorm.DB) {
	r.Use(cors.New(cors.Config{
		AllowOrigins: strings.Split(cfg.ALLOW_ORIGINS, " "),
		AllowHeaders: []string{
			"Content-Type",
		},
		AllowCredentials: true,
	}))

	m := middlewares.NewMiddlware(cfg, db)
	authMiddleware := m.NewAuthMiddleware()

	h := handler{
		cfg: cfg,
		db:  db,
	}

	r.GET("/health-check", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "I'm still alive bruh")
	})

	api := r.Group("/api/v1")

	users := api.Group("/users")
	users.GET("/:id", authMiddleware.MiddlewareFunc, h.GetUser)

	auth := users.Group("/auth")
	auth.POST("/sign-up", h.signUp)
	auth.POST("/sign-in", authMiddleware.LoginHandler)
	auth.GET("/oauth/:oauthServiceName", authMiddleware.OAuthHandler)
	auth.POST("/oauth/:oauthServiceName", authMiddleware.OAuthCodeHandler)
	auth.GET("/refresh", authMiddleware.RefreshHandler)
	auth.GET("/sign-out", authMiddleware.MiddlewareFunc, authMiddleware.LogoutHandler)
	auth.GET("/verify-email", authMiddleware.MiddlewareFunc, h.verifyEmail)
	auth.GET("/verify-email/:verificationCode", authMiddleware.MiddlewareFunc, h.verifyEmailCode)
	auth.POST("/reset-password", h.resetPassword)
	auth.PATCH("/reset-password/:resetToken", h.resetPasswordToken)
}
