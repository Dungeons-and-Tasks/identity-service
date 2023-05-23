package handlers

import (
	"errors"
	"identity/common/helpers"
	"identity/common/helpers/apperrors"
	"identity/models"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/thanhpk/randstr"
	"gorm.io/gorm"
)

func (h *handler) resetPassword(ctx *gin.Context) {
	var resetPasswordUser models.ResetPasswordUser
	if err := ctx.BindJSON(&resetPasswordUser); err != nil {
		err := apperrors.NewBadRequest("not valid request object")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var user models.User
	err := h.db.First(&user, "email = ?", strings.ToLower(resetPasswordUser.Email)).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err := apperrors.NewNotFound("user not found")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	} else if err != nil {
		err := apperrors.NewBadGateway("failed get user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	if !user.IsEmailVerified {
		err := apperrors.NewBadRequest("email not verified")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	resetToken := randstr.String(h.cfg.PASSWORD_RESET_TOKEN_LENGTH)
	resetTokenExpiresAt := time.Now().Add(h.cfg.PASSWORD_RESET_TOKEN_EXPIRES_IN).UTC()
	err = h.db.Model(&user).Select("PasswordResetToken", "PasswordResetTokenExpiresAt").Updates(models.User{PasswordResetToken: resetToken, PasswordResetTokenExpiresAt: resetTokenExpiresAt}).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed update user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	err = helpers.SendEmail(h.cfg, user.Email, resetToken)
	if err != nil {
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	ctx.Status(http.StatusOK)
}

func (h *handler) resetPasswordToken(ctx *gin.Context) {
	resetToken := ctx.Param("resetToken")
	var resetPasswordTokenUser models.ResetPasswordTokenUser
	if err := ctx.BindJSON(&resetPasswordTokenUser); err != nil {
		err := apperrors.NewBadRequest("not valid request object")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	if resetPasswordTokenUser.Password != resetPasswordTokenUser.PasswordConfirm {
		err := apperrors.NewBadRequest("passwords not match")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var user models.User
	err := h.db.Where(&models.User{PasswordResetToken: resetToken}).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err := apperrors.NewNotFound("not valid resetToken")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	} else if err != nil {
		err := apperrors.NewBadGateway("failed get user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	if user.PasswordResetTokenExpiresAt.Before(time.Now().UTC()) {
		err := apperrors.NewBadRequest("token expired")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	hashedPassword, err := helpers.HashPassword(resetPasswordTokenUser.Password)
	if err != nil {
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	err = h.db.Model(&user).Select("Password").Updates(models.User{Password: hashedPassword}).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed update password")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	ctx.Status(http.StatusOK)
}
