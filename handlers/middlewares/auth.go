package middlewares

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"identity/common/constants/oauthservices"
	"identity/common/helpers"
	"identity/common/helpers/apperrors"
	"identity/common/helpers/oauth"
	"identity/config"
	"identity/models"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/thanhpk/randstr"
	"gorm.io/gorm"
)

type authMiddleware struct {
	cfg            *config.Config
	db             *gorm.DB
	privKey        *rsa.PrivateKey
	pubKey         *rsa.PublicKey
	expires        time.Duration
	refreshExpires time.Duration
	sendCookie     bool
	cookieName     string // default: access_token
	cookieMaxAge   time.Duration
	cookieDomain   string
	secureCookie   bool
	cookieHTTPOnly bool
	signingMethod  string // default: RS256
	tokenLookup    string // default: header: Authorization, cookie: access_token
	tokenHeadName  string // default: Bearer
}

func (m *middleware) NewAuthMiddleware() *authMiddleware {
	am := &authMiddleware{
		cfg:            m.cfg,
		db:             m.db,
		expires:        m.cfg.ACCESS_TOKEN_EXPIRES_IN,
		refreshExpires: m.cfg.ACCESS_TOKEN_REFRESH_EXPIRES_IN,
		sendCookie:     true,
		cookieName:     "access_token",
		cookieHTTPOnly: true,
		cookieMaxAge:   m.cfg.ACCESS_TOKEN_MAXAGE,
		signingMethod:  "RS256",
		tokenLookup:    "header: Authorization, cookie: access_token",
		tokenHeadName:  "Bearer",
	}
	am.init()
	return am
}

func (am *authMiddleware) init() {
	am.privateKey(am.cfg.ACCESS_TOKEN_PRIVATE_KEY_PATH)
	am.publicKey(am.cfg.ACCESS_TOKEN_PUBLIC_KEY_PATH)
}

func (am *authMiddleware) privateKey(privKeyFile string) {
	keyData, err := os.ReadFile(privKeyFile)
	if err != nil {
		log.Fatalln(err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalln(err)
	}
	am.privKey = privKey
}

func (am *authMiddleware) publicKey(pubKeyFile string) {
	keyData, err := os.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatalln(err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		log.Fatalln(err)
	}
	am.pubKey = pubKey
}

func (am *authMiddleware) MiddlewareFunc(ctx *gin.Context) {
	claims, err := am.validateToken(ctx)
	if err != nil {
		err := apperrors.NewUnauthorized(err.Error())
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var session models.Session
	err = am.db.Preload("User").First(&session, "id = ? AND user_id = ?", uint(claims["sessionId"].(float64)), claims["userId"]).Error
	if err != nil {
		err := apperrors.NewForbidden("session not found")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	ctx.Set("session", &session)
	ctx.Next()
}

func (am *authMiddleware) LoginHandler(ctx *gin.Context) {
	var signInUser models.SignInUser
	if err := ctx.BindJSON(&signInUser); err != nil {
		err := apperrors.NewBadRequest("invalid request object")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var user models.User
	err := am.db.First(&user, "login = ?", strings.ToLower(signInUser.Login)).Error
	if err != nil {
		err := apperrors.NewBadRequest("invalid login or password")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	if err := helpers.VerifyPassword(user.Password, signInUser.Password); err != nil {
		err := apperrors.NewBadRequest("invalid login or password")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	am.createSessionWithDeletePrev(ctx, &user, ctx.GetHeader("User-Agent"))
}

func (am *authMiddleware) OAuthHandler(ctx *gin.Context) {
	oauthServiceName := ctx.Param("oauthServiceName")

	var oauthUri string
	var err error
	switch oauthServiceName {
	case "google":
		oauthUri, err = oauth.GetGoogleAuthURI(am.cfg)
	case "vk":
		oauthUri, err = oauth.GetVKAuthURI(am.cfg)
	default:
		err = apperrors.NewInternal("invalid param oauthServiceName")
	}

	if err != nil {
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"oauthUri": oauthUri,
	})
}

func (am *authMiddleware) OAuthCodeHandler(ctx *gin.Context) {
	oauthServiceName := ctx.Param("oauthServiceName")
	var authorizeOAuthUser models.AuthorizeOAuthUser
	if err := ctx.BindJSON(&authorizeOAuthUser); err != nil {
		err := apperrors.NewBadRequest("incorrect structure")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var userInfo *oauth.OAuthUser
	var err error
	switch oauthServiceName {
	case "google":
		userInfo, err = oauth.GetGoogleUserInfo(am.cfg, authorizeOAuthUser.Code)
	case "vk":
		userInfo, err = oauth.GetVKUserInfo(am.cfg, authorizeOAuthUser.Code)
	default:
		err = apperrors.NewInternal("invalid param oauthServiceName")
	}

	if err != nil {
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var oauth models.OAuth
	err = am.db.Where("o_auth_service_user_id = ? AND o_auth_service_id = ?", userInfo.Id, oauthservices.OAuthServiceMap[oauthServiceName]).Preload("User").First(&oauth).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		uuid, err := uuid.NewRandom()
		if err != nil {
			err := apperrors.NewInternal("failed generate uuid")
			ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
			return
		}
		hashedPassword, err := helpers.HashPassword(randstr.String(am.cfg.PASSWORD_RESET_TOKEN_LENGTH))
		if err != nil {
			ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
			return
		}
		user := models.User{
			ID:       uuid,
			Name:     userInfo.Name,
			Email:    userInfo.Email,
			Login:    userInfo.Email,
			Password: hashedPassword,
			Picture:  userInfo.Picture,
		}
		err = am.db.Create(&user).Error
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			err := apperrors.NewConflict("email or login busy")
			ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
			return
		} else if err != nil {
			err := apperrors.NewBadGateway("failed create user")
			ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
			return
		}

		oauth = models.OAuth{
			UserID:             user.ID,
			User:               &user,
			OAuthServiceID:     oauthservices.OAuthServiceMap[oauthServiceName],
			OAuthServiceUserID: userInfo.Id,
		}
		err = am.db.Create(&oauth).Error
		if err != nil {
			err := apperrors.NewBadGateway("failed create oauth")
			ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
			return
		}
	} else if err != nil {
		err := apperrors.NewBadGateway("failed get oauth")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	am.createSessionWithDeletePrev(ctx, oauth.User, ctx.GetHeader("User-Agent"))
}

func (am *authMiddleware) RefreshHandler(ctx *gin.Context) {
	claims, err := am.refreshToken(ctx)
	if err != nil {
		err := apperrors.NewUnauthorized(err.Error())
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	var session models.Session
	err = am.db.Preload("User").First(&session, "id = ? AND user_id = ?", uint(claims["sessionId"].(float64)), claims["userId"]).Error
	if err != nil {
		err := apperrors.NewForbidden("session not found")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	err = am.db.Delete(&session).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed delete session")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	am.createSession(ctx, session.User, ctx.GetHeader("User-Agent"))
}

func (am *authMiddleware) LogoutHandler(ctx *gin.Context) {
	session := ctx.MustGet("session").(*models.Session)
	err := am.db.Delete(&session).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed delete session")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	if am.sendCookie {
		ctx.SetCookie(am.cookieName, "", -1, "/", am.cookieDomain, am.secureCookie, am.cookieHTTPOnly)
	}

	ctx.Status(http.StatusOK)
}

func (am *authMiddleware) createSessionWithDeletePrev(ctx *gin.Context, user *models.User, useragent string) {
	err := am.db.Where("user_agent LIKE ? AND user_id = ?", useragent, user.ID).Delete(&models.Session{}).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed delete sessoin by User-Agent")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}
	am.createSession(ctx, user, useragent)
}

func (am *authMiddleware) createSession(ctx *gin.Context, user *models.User, useragent string) {
	session := models.Session{
		UserID:    user.ID,
		UserAgent: useragent,
	}
	err := am.db.Create(&session).Error
	if err != nil {
		err := apperrors.NewBadGateway("failed create session")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	payload := map[string]interface{}{
		"sessionId": session.ID,
		"userId":    user.ID,
	}
	token, expired, err := am.generateToken(payload)
	if err != nil {
		err := apperrors.NewInternal("failed generate token")
		ctx.AbortWithStatusJSON(apperrors.HttpStatus(err), err)
		return
	}

	if am.sendCookie {
		ctx.SetCookie(am.cookieName, token, int(am.cookieMaxAge.Seconds()), "/", am.cookieDomain, am.secureCookie, am.cookieHTTPOnly)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"expired":      expired,
	})
}

func (am *authMiddleware) generateToken(data map[string]interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(am.signingMethod))
	claims := token.Claims.(jwt.MapClaims)

	for k, v := range data {
		claims[k] = v
	}

	now := time.Now().UTC()
	expired := now.Add(am.expires)
	claims["exp"] = expired.Unix()
	claims["iat"] = now.Unix()

	signedToken, err := token.SignedString(am.privKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return signedToken, expired, nil
}

func (am *authMiddleware) validateToken(ctx *gin.Context) (jwt.MapClaims, error) {
	var token string
	methods := strings.Split(am.tokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token = am.jwtFromHeader(ctx, v)
		case "cookie":
			token = am.jwtFromCookie(ctx, v)
		}
	}
	if token == "" {
		return nil, fmt.Errorf("token not provided")
	}
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(am.signingMethod) != t.Method {
			return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
		}
		return am.pubKey, nil
	})
	return parsedToken.Claims.(jwt.MapClaims), err
}

func (am *authMiddleware) refreshToken(ctx *gin.Context) (jwt.MapClaims, error) {
	claims, err := am.validateToken(ctx)
	if err != nil {
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	iat := time.Unix(int64(claims["iat"].(float64)), 0)
	if iat.Before(time.Now().UTC().Add(-am.refreshExpires)) {
		return nil, fmt.Errorf("token refresh expired")
	}

	return claims, nil
}

func (am *authMiddleware) jwtFromHeader(c *gin.Context, key string) string {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == am.tokenHeadName) {
		return ""
	}
	return parts[1]
}

func (am *authMiddleware) jwtFromCookie(c *gin.Context, key string) string {
	cookie, _ := c.Cookie(key)
	return cookie
}
