package handlers

import (
	"errors"
	"identity/common/helpers/apperrors"
	"identity/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (h *handler) GetUser(ctx *gin.Context) {
	userId := ctx.Param("id")
	var user models.User
	err := h.db.First(&user, "id = ?", userId).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err := apperrors.NewNotFound("user not found")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	} else if err != nil {
		err := apperrors.NewBadGateway("failed get user")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	ctx.JSON(http.StatusOK, user)
}
