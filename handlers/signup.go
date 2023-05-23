package handlers

import (
	"errors"
	"identity/common/helpers"
	"identity/common/helpers/apperrors"
	"identity/models"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (h *handler) signUp(ctx *gin.Context) {
	var signUpUser models.SignUpUser
	if err := ctx.BindJSON(&signUpUser); err != nil {
		err := apperrors.NewBadRequest("incorrect structure")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	if signUpUser.Password != signUpUser.PasswordConfirm {
		err := apperrors.NewBadRequest("passwords not match")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	hashedPassword, err := helpers.HashPassword(signUpUser.Password)
	if err != nil {
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	uuid, err := uuid.NewRandom()
	if err != nil {
		err := apperrors.NewInternal("failed generate uuid")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	user := models.User{
		ID:       uuid,
		Email:    strings.ToLower(signUpUser.Email),
		Login:    strings.ToLower(signUpUser.Login),
		Password: hashedPassword,
	}
	err = h.db.Create(&user).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		err := apperrors.NewConflict("email or login busy")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	} else if err != nil {
		err := apperrors.NewBadGateway("failed create user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	h.db.First(&user, user.ID)

	ctx.JSON(http.StatusCreated, user)
}
