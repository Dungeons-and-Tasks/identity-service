package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                             uuid.UUID `gorm:"primaryKey;type:char(36);autoIncrement:false" json:"id"`
	Name                           string    `gorm:"size:50" json:"name"`
	Email                          string    `gorm:"uniqueIndex;size:320" json:"email"`
	Login                          string    `gorm:"uniqueIndex;size:50" json:"-"`
	Password                       string    `json:"-"`
	PasswordResetToken             string    `json:"-"`
	PasswordResetTokenExpiresAt    time.Time `gorm:"autoCreateTime" json:"-"`
	IsEmailVerified                bool      `json:"isEmailVerified"`
	EmailVerificationCode          string    `json:"-"`
	EmailVerificationCodeExpiresAt time.Time `gorm:"autoCreateTime" json:"-"`
	Picture                        string    `json:"picture"`
	CreatedAt                      time.Time `json:"createdAt"`
	UpdatedAt                      time.Time `json:"updatedAt"`
	OAuths                         []OAuth   `gorm:"constraint:OnDelete:CASCADE;" json:"oauths,omitempty"`
	Sessions                       []Session `gorm:"constraint:OnDelete:CASCADE;" json:"sessions,omitempty"`
}

type SignUpUser struct {
	Email           string `json:"email" binding:"required,email"`
	Login           string `json:"login" binding:"required"`
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}

type OAuthUser struct {
	Code string `json:"code" binding:"required"`
}

type SignInUser struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type ResetPasswordUser struct {
	Email string `json:"email" binding:"required"`
}

type ResetPasswordTokenUser struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}
