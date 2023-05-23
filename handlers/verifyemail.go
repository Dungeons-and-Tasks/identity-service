package handlers

import (
	"identity/common/helpers"
	"identity/common/helpers/apperrors"
	"identity/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/thanhpk/randstr"
)

func (h *handler) verifyEmail(ctx *gin.Context) {
	session := ctx.MustGet("session").(*models.Session)
	verificationCode := randstr.String(h.cfg.VERIFICATION_CODE_LENGTH)
	verificationCodeExpiresAt := time.Now().Add(h.cfg.VERIFICATION_CODE_EXPIRES_IN).UTC()
	err := h.db.Model(&session.User).Select("EmailVerificationCode", "EmailVerificationCodeExpiresAt").Updates(models.User{EmailVerificationCode: verificationCode, EmailVerificationCodeExpiresAt: verificationCodeExpiresAt}).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed update user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	err = helpers.SendEmail(h.cfg, session.User.Email, verificationCode)
	if err != nil {
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	ctx.Status(http.StatusOK)
}

func (h *handler) verifyEmailCode(ctx *gin.Context) {
	session := ctx.MustGet("session").(*models.Session)
	verificationCode := ctx.Param("verificationCode")
	if session.User.EmailVerificationCode != verificationCode {
		err := apperrors.NewBadRequest("not valid verificationCode")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	if session.User.EmailVerificationCodeExpiresAt.Before(time.Now().UTC()) {
		err := apperrors.NewBadRequest("verificationCode expired")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	err := h.db.Model(&session.User).Select("IsEmailVerified").Updates(models.User{IsEmailVerified: true}).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed update user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	ctx.Status(http.StatusOK)
}
