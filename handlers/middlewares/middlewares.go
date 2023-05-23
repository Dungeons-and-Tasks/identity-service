package middlewares

import (
	"identity/config"

	"gorm.io/gorm"
)

type middleware struct {
	cfg *config.Config
	db  *gorm.DB
}

func NewMiddlware(cfg *config.Config, db *gorm.DB) *middleware {
	return &middleware{
		cfg: cfg,
		db:  db,
	}
}
