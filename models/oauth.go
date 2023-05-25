package models

import (
	"time"

	"github.com/google/uuid"
)

type OAuth struct {
	UserID             uuid.UUID     `gorm:"primaryKey;type:char(36);" json:"userId"`
	User               *User         `json:"user,omitempty"`
	OAuthServiceID     uint          `gorm:"primaryKey" json:"oAuthServiceId"`
	OAuthService       *OAuthService `json:"oAuthService,omitempty"`
	OAuthServiceUserID string        `json:"-"`
	CreatedAt          time.Time     `json:"createdAt"`
}
