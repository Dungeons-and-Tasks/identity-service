package models

import "time"

type OAuthService struct {
	ID        uint      `gorm:"primaryKey;autoIncrement:false" json:"id"`
	Title     string    `gorm:"uniqueIndex;size:50" json:"title"`
	CreatedAt time.Time `json:"createdAt"`
}
