package main

import (
	"identity/common/helpers/db"
	"identity/config"
	"identity/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.LoadConfig("./config/.env")

	db := db.Connect(cfg.DSN)

	router := gin.Default()
	handlers.MountHandlers(router, cfg, db)
	router.Run(cfg.ADDRESS)
}
