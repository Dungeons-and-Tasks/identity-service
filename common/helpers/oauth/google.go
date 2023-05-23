package oauth

import (
	"identity/common/helpers/apperrors"
	"identity/config"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
)

type googleTokens struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    uint   `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type googleUserInfo struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func GetGoogleAuthURI(cfg *config.Config) (string, error) {
	var u, err = url.Parse(cfg.GOOGLE_AUTH_URI)
	if err != nil {
		return "", apperrors.NewInternal("failed parse google auth uri")
	}
	v := url.Values{}
	v.Set("scope", strings.Join(cfg.GOOGLE_SCOPE, " "))
	v.Set("access_type", "offline")
	v.Set("include_granted_scopes", "true")
	v.Set("response_type", "code")
	v.Set("redirect_uri", cfg.GOOGLE_REDIRECT_URI)
	v.Set("client_id", cfg.GOOGLE_CLIENT_ID)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

func getGoogleTokens(cfg *config.Config, code string) (*googleTokens, error) {
	client := resty.New()
	var res googleTokens
	var req_err error
	_, err := client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"client_id":     cfg.GOOGLE_CLIENT_ID,
			"client_secret": cfg.GOOGLE_CLIENT_SECRET,
			"code":          code,
			"grant_type":    "authorization_code",
			"redirect_uri":  cfg.GOOGLE_REDIRECT_URI,
		}).
		SetError(&req_err).
		SetResult(&res).
		Post(cfg.GOOGLE_TOKEN_URI)
	if err != nil {
		return nil, apperrors.NewInternal(err.Error())
	} else if req_err != nil {
		return nil, apperrors.NewBadGateway(req_err.Error())
	}
	return &res, nil
}

func GetGoogleUserInfo(cfg *config.Config, code string) (*OAuthUser, error) {
	tokens, err := getGoogleTokens(cfg, code)
	if err != nil {
		return nil, err
	}

	client := resty.New()
	var res googleUserInfo
	var req_err error
	_, err = client.R().
		SetHeader("Authorization", "Bearer "+tokens.AccessToken).
		SetError(&req_err).
		SetResult(&res).
		Get(cfg.GOOGLE_USER_INFO_URI)
	if err != nil {
		return nil, apperrors.NewInternal(err.Error())
	} else if req_err != nil {
		return nil, apperrors.NewBadGateway(req_err.Error())
	}

	return &OAuthUser{
		Id:      res.Id,
		Name:    res.Name,
		Email:   res.Email,
		Picture: res.Picture,
	}, nil
}
