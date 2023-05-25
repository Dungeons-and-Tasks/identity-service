package models

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uuid.UUID `gorm:"primaryKey;type:char(36);" json:"userId"`
	User      *User     `json:"user,omitempty"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
}
